import { sha256 } from '@noble/hashes/sha2.js';
import { constantTimeEqual, readUint16, readUint32, toHex, utf8Decode, utf8Encode, writeUint16, writeUint32 } from '../bytes.js';
import { type Role, Roles } from '../grants.js';
import type { Platform, UdpSocket } from '../platform.js';
import { type ByteStream, Deferred, delay, withTimeout } from '../streams.js';
import { formatAddress, ipv6Bytes, isGlobalIpv6, isIpv6, normalizeHost, parseAddress, sameAddress, type UdpAddress } from './addresses.js';
import { DatagramType, KcpPath } from './kcpPath.js';

// One attempt to open a direct path for a session (protocol section 6): discover this endpoint's
// addresses, exchange candidates with the peer through signaling, then punch through the NATs
// with UDP probes. The initiator picks the first path that works.
//
// Probes carry no payload and prove nothing about who sent them - they only find a working path.
// Everything that matters is established afterwards by the end-to-end handshake over that path,
// and both endpoints then confirm in the session bind which candidate lists they used. That is
// also why an address the peer did not announce, learned from where its probes come from, is used
// only when the session's end-to-end layer authenticates the peer (`peerReflexive`).

export const DirectFailureReasons = {
  PolicyRelayOnly: 'policy_relay_only',
  PeerNoDirectSupport: 'peer_no_direct_support',
  StunUnreachable: 'stun_unreachable',
  UdpBlockedLocal: 'udp_blocked_local',
  UdpBlockedRemote: 'udp_blocked_remote',
  SymmetricNatBoth: 'symmetric_nat_both',
  ProbeTimeout: 'probe_timeout',
} as const;

export interface DirectPath {
  stream: ByteStream;
  /** `ip:port` of the peer on the selected path. */
  peerAddress: string;
}

export interface DirectAttemptOptions {
  /**
   * The UDP path may also use an address of the peer that the peer did not announce, learned from
   * where its probes arrive from (as behind a symmetric NAT). Only for sessions whose end-to-end
   * handshake authenticates the peer; see {@link peerReflexiveFor}.
   */
  peerReflexive?: boolean;
  /** Test hook: changes the UDP candidates before they are announced. */
  announceFilter?: (candidates: string[]) => string[];
  /** Diagnostics: one line per step (STUN answers, candidates, probes). The lines contain network addresses. */
  log?: (line: string) => void;
}

/** First datagrams from new addresses that are logged per attempt; more would only repeat the picture. */
const MAX_LOGGED_SOURCES = 12;

/**
 * Whether a session with this end-to-end layer may use learned addresses: only when the layer
 * authenticates the peer (certificates, or a shared key), because nothing but that handshake
 * vouches for a path through an address neither side announced.
 */
export const peerReflexiveFor = (e2eMethod: string): boolean => e2eMethod === 'tls13' || e2eMethod === 'shared-key';

const PROBE_SIZE = 18;
const FLAG_PROBE = 0;
const FLAG_SELECT = 1;
const MAX_CANDIDATES = 16;
const MAX_IPV4_ADDRESSES = 6;
const MAX_IPV6_ADDRESSES = 4;
const MAX_LEARNED = 4;
const PROBE_INTERVAL_MS = 100;
const STUN_TIMEOUT_MS = 1500;
/** How long an announced candidate gets to validate after a learned address did, before the learned one is selected. */
const LEARNED_GRACE_MS = 500;
const STUN_MAGIC = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS = 0x0101;
const STUN_XOR_MAPPED_ADDRESS = 0x0020;

interface CandidateList {
  sid: string;
  role: string;
  udp: string[];
  nat: string;
}

/** Reads the mapped address from a STUN Binding success response for one of our transactions. */
export function readStunSuccess(datagram: Uint8Array, transactionId: Uint8Array): string | null {
  if (datagram.length < 20 || readUint16(datagram, 0) !== STUN_BINDING_SUCCESS || readUint32(datagram, 4) !== STUN_MAGIC
    || !constantTimeEqual(datagram.subarray(8, 20), transactionId)) {
    return null;
  }
  const length = readUint16(datagram, 2);
  if (length > datagram.length - 20) {
    return null;
  }
  let offset = 20;
  const end = 20 + length;
  while (end - offset >= 4) {
    const type = readUint16(datagram, offset);
    const valueLength = readUint16(datagram, offset + 2);
    if (valueLength > end - offset - 4) {
      return null;
    }
    if (type === STUN_XOR_MAPPED_ADDRESS && valueLength >= 8 && datagram[offset + 5] === 0x01) {
      const port = readUint16(datagram, offset + 6) ^ (STUN_MAGIC >>> 16);
      const address = (readUint32(datagram, offset + 8) ^ STUN_MAGIC) >>> 0;
      return `${address >>> 24}.${(address >>> 16) & 255}.${(address >>> 8) & 255}.${address & 255}:${port}`;
    }
    // Attributes are padded to a multiple of four bytes.
    offset += 4 + ((valueLength + 3) & ~3);
  }
  return null;
}

/** A peer candidate this endpoint can send to: IPv4, or IPv6 that is neither link-local, multicast nor unspecified. */
function usableCandidate(address: UdpAddress): boolean {
  if (!isIpv6(address.host)) {
    return true;
  }
  const bytes = ipv6Bytes(address.host)!;
  const linkLocal = bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80;
  return !linkLocal && bytes[0] !== 0xff && !bytes.every((byte) => byte === 0);
}

export class DirectAttempt {
  /** SHA-256 (hex) of the candidate list this endpoint sent; confirmed inside the encrypted session. */
  localCandidatesHash: string | undefined;

  /** SHA-256 (hex) of the candidate list received from the peer through signaling. */
  remoteCandidatesHash: string | undefined;

  private readonly tag: Uint8Array;
  private readonly conversation: number;
  private socket: UdpSocket | null = null;
  private remoteCandidates: UdpAddress[] = [];
  private learned: UdpAddress[] = [];
  private remoteNat = 'unknown';
  private readonly remoteKnown = new Deferred<void>();
  private readonly validated = new Deferred<UdpAddress>();
  private readonly validatedLearned = new Deferred<UdpAddress>();
  private readonly selectAcknowledged = new Deferred<void>();
  private readonly selectedByPeer = new Deferred<KcpPath>();
  private selected: UdpAddress | null = null;
  private path: KcpPath | null = null;
  private stunTransactions: { id: Uint8Array; answer: string | null }[] = [];
  private stunReachable = false;
  private stunSymmetric = false;
  private hasStunServers = false;
  private handedOver = false;
  private closed = false;
  private probesSent = 0;
  private probesReceived = 0;
  private acksReceived = 0;
  private readonly loggedSources = new Set<string>();

  constructor(
    private readonly platform: Platform,
    private readonly role: Role,
    private readonly sessionId: string,
    grantToken: string,
    private readonly stunServers: readonly string[],
    private readonly options: DirectAttemptOptions = {},
  ) {
    // Both endpoints hold the same grant, so both derive the same tag and KCP conversation id.
    const digest = sha256(utf8Encode(grantToken));
    this.tag = digest.subarray(0, 8);
    this.conversation = (readUint32(digest, 8) | 1) >>> 0;
  }

  /** What this side of the attempt sent and saw, for the log when no path was found. */
  summary(): string {
    return `sent ${this.probesSent} probes to ${this.probeTargets().map(formatAddress).join(', ') || '(nothing)'}; `
      + `received ${this.probesReceived} probes and ${this.acksReceived} answers`;
  }

  private log(text: string): void {
    try {
      this.options.log?.(`direct: ${text}`);
    } catch {
      // Diagnostics must never break the attempt.
    }
  }

  /** Discovers this endpoint's addresses and returns the candidate list to send to the peer. */
  async gather(): Promise<Uint8Array> {
    const udp = this.platform.udp!;
    this.socket = await udp.bind();
    this.socket.onMessage = (data, host, port) => this.onDatagram(data, host, port);
    this.log(`UDP socket on port ${this.socket.port}, IPv6 ${this.socket.ipv6 ? 'yes' : 'no'}`);

    const mapped = await this.discover();
    let candidates: string[] = [];
    let ipv4 = 0;
    let ipv6 = 0;
    const local = await udp.localAddresses().catch((error: unknown) => {
      this.log(`local addresses could not be read: ${error instanceof Error ? error.message : String(error)}`);
      return [] as string[];
    });
    this.log(`local addresses: ${local.length === 0 ? '(none)' : local.join(', ')}`);
    for (const text of local) {
      const host = normalizeHost(text);
      if (!host) {
        continue;
      }
      // IPv4 on every interface; IPv6 only global addresses, and only when the socket has IPv6.
      const usable = isIpv6(host) ? this.socket.ipv6 && isGlobalIpv6(host) && ipv6 < MAX_IPV6_ADDRESSES : ipv4 < MAX_IPV4_ADDRESSES;
      const candidate = formatAddress({ host, port: this.socket.port });
      if (usable && !candidates.includes(candidate)) {
        candidates.push(candidate);
        isIpv6(host) ? ipv6++ : ipv4++;
      }
    }
    if (mapped && !candidates.includes(mapped)) {
      candidates.push(mapped);
    }
    if (this.options.announceFilter) {
      candidates = this.options.announceFilter(candidates);
    }

    const list: CandidateList = {
      sid: this.sessionId,
      role: this.role,
      udp: candidates,
      nat: !this.stunReachable ? 'unknown' : this.stunSymmetric ? 'symmetric' : 'cone',
    };
    const blob = utf8Encode(JSON.stringify(list));
    this.localCandidatesHash = toHex(sha256(blob));
    this.log(`announcing ${candidates.length === 0 ? '(no candidates)' : candidates.join(', ')}; NAT ${list.nat}`);
    return blob;
  }

  /** Takes the peer's candidate list as received through signaling. False when it is not usable. */
  setRemoteCandidates(blob: Uint8Array): boolean {
    let list: CandidateList;
    try {
      list = JSON.parse(utf8Decode(blob)) as CandidateList;
    } catch {
      this.log('the peer\'s candidate list is not readable');
      return false;
    }
    if (!list || list.sid !== this.sessionId || list.role === this.role || !Array.isArray(list.udp) || list.udp.length > MAX_CANDIDATES) {
      this.log('the peer\'s candidate list is not for this session or not usable');
      return false;
    }
    this.log(`peer announces ${list.udp.length === 0 ? '(no candidates)' : list.udp.join(', ')}; NAT ${String(list.nat)}`);
    this.remoteCandidatesHash = toHex(sha256(blob));
    this.remoteNat = typeof list.nat === 'string' ? list.nat : 'unknown';
    const parsed: UdpAddress[] = [];
    for (const text of list.udp) {
      const address = typeof text === 'string' ? parseAddress(text) : null;
      if (address && usableCandidate(address) && !parsed.some((known) => sameAddress(known, address))) {
        parsed.push(address);
      }
    }
    this.remoteCandidates = parsed;
    this.remoteKnown.resolve();
    return true;
  }

  private isRemoteCandidate(address: UdpAddress): boolean {
    return this.remoteCandidates.some((candidate) => sameAddress(candidate, address));
  }

  private isLearned(address: UdpAddress): boolean {
    return this.learned.some((known) => sameAddress(known, address));
  }

  /**
   * Remembers an address of the peer that the peer did not announce, because a datagram with this
   * session's tag came from it. Only once the peer's list is known (so that it is clear the address
   * is not on it), only for sessions that allow it, and only a few.
   */
  private learn(address: UdpAddress): void {
    if (!this.options.peerReflexive || !this.remoteKnown.settled || this.isRemoteCandidate(address)
      || this.isLearned(address) || this.learned.length >= MAX_LEARNED) {
      return;
    }
    this.learned = [...this.learned, address];
  }

  /** Where probes go: the peer's candidates, then what was learned. */
  private probeTargets(): UdpAddress[] {
    return this.learned.length === 0 ? this.remoteCandidates : [...this.remoteCandidates, ...this.learned];
  }

  /** A learned address that answered, once an announced candidate has had a moment to answer too. */
  private async learnedFallback(): Promise<UdpAddress> {
    const learned = await this.validatedLearned.promise;
    await delay(LEARNED_GRACE_MS);
    return learned;
  }

  /**
   * Initiator: tries the peer's candidates until a path works, then tells the peer which one to
   * use. Returns that path, or null when none worked in time.
   */
  async open(budgetMs: number): Promise<DirectPath | null> {
    const started = Date.now();
    const deadline = started + budgetMs;
    const remaining = () => Math.max(deadline - Date.now(), 1);
    let stop = false;
    let step = 'waiting for the peer\'s candidates';
    const expired = () => new Error('no direct path in time');
    try {
      await withTimeout(this.remoteKnown.promise, remaining(), expired);
      this.log(`peer's candidates after ${Date.now() - started} ms; probing`);
      step = 'probing, no answer from the peer yet';
      void this.probeLoop(FLAG_PROBE, () => this.probeTargets(), () => stop || this.selected !== null);

      // A learned address is the fallback: it is selected only if no announced candidate answers in time.
      const learned = this.options.peerReflexive ? this.learnedFallback() : new Promise<UdpAddress>(() => undefined);
      learned.catch(() => undefined);
      const remote = await withTimeout(Promise.race([this.validated.promise, learned]), remaining(), expired);
      this.selected = remote;
      this.log(`${formatAddress(remote)} answered after ${Date.now() - started} ms (${this.isRemoteCandidate(remote) ? 'announced' : 'learned'}); selecting it`);
      step = `selecting ${formatAddress(remote)}, no acknowledgement yet`;
      void this.probeLoop(FLAG_SELECT, () => [remote], () => stop);
      await withTimeout(this.selectAcknowledged.promise, remaining(), expired);

      stop = true;
      this.handedOver = true;
      this.path = new KcpPath(this.socket!, remote.host, remote.port, this.conversation);
      this.log(`path to ${formatAddress(remote)} after ${Date.now() - started} ms`);
      return { stream: this.path.stream, peerAddress: this.path.peerAddress };
    } catch {
      stop = true;
      this.log(`no path within ${budgetMs} ms (${step}); sent ${this.probesSent} probes to `
        + `${this.probeTargets().map(formatAddress).join(', ') || '(nothing)'}, received ${this.probesReceived} probes and ${this.acksReceived} answers`
        + `${this.learned.length > 0 ? `; learned ${this.learned.map(formatAddress).join(', ')}` : ''}; reason ${this.failureReason()}`);
      return null;
    }
  }

  /**
   * Device: keeps probing the initiator's candidates (which opens this side's NAT) and waits for
   * the initiator to select a path. Rejects when the attempt is closed first.
   */
  async waitForSelection(): Promise<DirectPath> {
    void this.remoteKnown.promise.then(() => this.probeLoop(FLAG_PROBE, () => this.probeTargets(), () => this.closed || this.path !== null));
    const path = await this.selectedByPeer.promise;
    return { stream: path.stream, peerAddress: path.peerAddress };
  }

  /** Why no direct path was found. */
  failureReason(): string {
    if (this.stunSymmetric && this.remoteNat === 'symmetric') {
      return DirectFailureReasons.SymmetricNatBoth;
    }
    if (!this.stunReachable) {
      return this.hasStunServers ? DirectFailureReasons.UdpBlockedLocal : DirectFailureReasons.StunUnreachable;
    }
    if (this.remoteNat === 'unknown') {
      return DirectFailureReasons.UdpBlockedRemote;
    }
    return DirectFailureReasons.ProbeTimeout;
  }

  /** Gives up the attempt. A path that was handed to a session is not affected. */
  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.selectedByPeer.reject(new Error('The direct attempt was closed.'));
    this.validated.reject(new Error('The direct attempt was closed.'));
    this.validatedLearned.reject(new Error('The direct attempt was closed.'));
    if (!this.handedOver) {
      try {
        this.socket?.close();
      } catch {
        // Already closed.
      }
    }
  }

  /**
   * Asks the STUN servers how this endpoint's UDP port appears from outside. Different answers
   * from different servers mean the NAT maps each destination separately ("symmetric"), in which
   * case the reported address is of no use to a peer.
   */
  private async discover(): Promise<string | null> {
    const servers: { host: string; port: number }[] = [];
    for (const server of this.stunServers) {
      const colon = server.lastIndexOf(':');
      const port = Number.parseInt(server.substring(colon + 1), 10);
      if (colon <= 0 || Number.isNaN(port) || port < 1 || port > 65535) {
        continue;
      }
      try {
        const host = server.substring(0, colon);
        servers.push({ host: parseAddress(`${host}:${port}`)?.host ?? (await this.platform.udp!.resolve(host)), port });
      } catch {
        // A server that cannot be resolved is skipped.
      }
    }
    this.hasStunServers = servers.length > 0;
    if (servers.length === 0) {
      this.log(`no STUN server to ask (given: ${this.stunServers.length === 0 ? 'none' : this.stunServers.join(', ')})`);
      return null;
    }

    this.stunTransactions = servers.map(() => ({ id: this.platform.randomBytes(12), answer: null }));
    const started = Date.now();
    // UDP is lossy: repeat the requests a few times until every server has answered.
    for (const wait of [0, 200, 400, 800]) {
      const until = started + wait;
      while (Date.now() < until && !this.stunTransactions.every((t) => t.answer !== null)) {
        await delay(20);
      }
      if (this.stunTransactions.every((t) => t.answer !== null)) {
        break;
      }
      servers.forEach((server, index) => {
        if (this.stunTransactions[index].answer === null) {
          const request = new Uint8Array(20);
          writeUint16(request, 0, STUN_BINDING_REQUEST);
          writeUint16(request, 2, 0);
          writeUint32(request, 4, STUN_MAGIC);
          request.set(this.stunTransactions[index].id, 8);
          this.socket!.send(request, server.host, server.port);
        }
      });
    }
    while (Date.now() < started + STUN_TIMEOUT_MS && !this.stunTransactions.every((t) => t.answer !== null)) {
      await delay(20);
    }

    const answers = this.stunTransactions.map((t) => t.answer).filter((answer): answer is string => answer !== null);
    this.stunReachable = answers.length > 0;
    this.stunSymmetric = new Set(answers).size > 1;
    this.log(`STUN after ${Date.now() - started} ms: ${servers.map((server, index) => `${formatAddress(server)} -> ${this.stunTransactions[index].answer ?? 'no answer'}`).join(', ')}`
      + ` (${!this.stunReachable ? 'unreachable' : this.stunSymmetric ? 'different public ports: symmetric NAT' : 'one public address: cone'})`);
    return answers[0] ?? null;
  }

  private onDatagram(data: Uint8Array, host: string, port: number): void {
    if (data.length === 0) {
      return;
    }
    if (data[0] <= 0x03) {
      for (const transaction of this.stunTransactions) {
        transaction.answer ??= readStunSuccess(data, transaction.id);
      }
      return;
    }
    if (data[0] === DatagramType.Probe || data[0] === DatagramType.ProbeAck) {
      this.onProbe(data, host, port);
    }
  }

  private onProbe(data: Uint8Array, rawHost: string, port: number): void {
    if (data.length !== PROBE_SIZE || !constantTimeEqual(data.subarray(1, 9), this.tag) || !this.socket) {
      return; // not for this session
    }
    const host = normalizeHost(rawHost) ?? rawHost;
    const from = { host, port };
    this.learn(from);
    const announced = this.isRemoteCandidate(from);
    const flags = data[9];
    if (data[0] === DatagramType.Probe) {
      this.probesReceived++;
    } else {
      this.acksReceived++;
    }
    const source = `${data[0] === DatagramType.Probe ? 'probe' : 'answer'} ${formatAddress(from)}`;
    if (!this.loggedSources.has(source) && this.loggedSources.size < MAX_LOGGED_SOURCES) {
      this.loggedSources.add(source);
      this.log(`first ${source.replace(' ', ' from ')} (${announced ? 'announced' : this.isLearned(from) ? 'learned' : 'not announced'})`);
    }
    if (data[0] === DatagramType.Probe) {
      if (flags === FLAG_SELECT) {
        // Only the initiator selects, and only an address from its own announced list (or, where
        // the session allows it, one learned from its probes) is accepted.
        if (this.role !== Roles.Device || !(announced || this.isLearned(from))) {
          return;
        }
        if (this.path === null) {
          this.selected = { host, port };
          this.handedOver = true;
          // The path listens before the selection is acknowledged, so the initiator's first packets are not lost.
          this.path = new KcpPath(this.socket, host, port, this.conversation);
          this.path.onProbe = (probe, probeHost, probePort) => this.onProbe(probe, probeHost, probePort);
          this.selectedByPeer.resolve(this.path);
        } else if (this.selected?.host !== host || this.selected?.port !== port) {
          return;
        }
      }
      const ack = data.slice();
      ack[0] = DatagramType.ProbeAck;
      this.socket.send(ack, host, port);
      return;
    }

    if (this.role === Roles.Initiator && (announced || this.isLearned(from))) {
      if (flags === FLAG_PROBE) {
        const validated = announced ? this.validated : this.validatedLearned;
        if (!validated.settled) {
          validated.resolve(from);
        }
      } else if (this.selected !== null && sameAddress(this.selected, from) && !this.selectAcknowledged.settled) {
        this.selectAcknowledged.resolve();
      }
    }
  }

  private async probeLoop(flags: number, targets: () => UdpAddress[], done: () => boolean): Promise<void> {
    const probe = new Uint8Array(PROBE_SIZE);
    probe[0] = DatagramType.Probe;
    probe.set(this.tag, 1);
    probe[9] = flags;
    while (!done() && !this.closed) {
      probe.set(this.platform.randomBytes(8), 10);
      for (const target of targets()) {
        try {
          this.socket?.send(probe.slice(), target.host, target.port);
          this.probesSent++;
        } catch {
          // An address this machine cannot send to is just one that does not work.
        }
      }
      await delay(PROBE_INTERVAL_MS);
    }
  }
}
