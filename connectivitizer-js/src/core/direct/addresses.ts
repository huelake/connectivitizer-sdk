// UDP addresses as the candidate lists write them (protocol section 6.3): IPv4 as `a.b.c.d:port`,
// IPv6 as `[address]:port`. Hosts are kept in one canonical text form (RFC 5952 for IPv6), so that
// two spellings of the same address compare equal.

export interface UdpAddress {
  host: string;
  port: number;
}

/** The 16 bytes of an IPv6 address in text form, or null. Zone ids (`%eth0`) are not accepted. */
export function ipv6Bytes(text: string): Uint8Array | null {
  if (!/^[0-9a-fA-F:.]+$/.test(text) || text.length > 45) {
    return null;
  }
  // An embedded IPv4 address at the end (`::ffff:192.0.2.1`) stands for the last two groups.
  let body = text;
  if (text.includes('.')) {
    const lastColon = text.lastIndexOf(':');
    const ipv4 = lastColon < 0 ? null : ipv4Bytes(text.substring(lastColon + 1));
    if (!ipv4) {
      return null;
    }
    body = `${text.substring(0, lastColon + 1)}${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }

  const halves = body.split('::');
  if (halves.length > 2) {
    return null;
  }
  const parse = (part: string): number[] | null => {
    if (part === '') {
      return [];
    }
    const groups: number[] = [];
    for (const group of part.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
        return null;
      }
      groups.push(Number.parseInt(group, 16));
    }
    return groups;
  };
  const before = parse(halves[0]);
  const after = halves.length === 2 ? parse(halves[1]) : [];
  if (!before || !after) {
    return null;
  }
  const known = before.length + after.length;
  if (halves.length === 2 ? known > 7 : known !== 8) {
    return null;
  }
  const groups = [...before, ...new Array<number>(8 - known).fill(0), ...after];
  const bytes = new Uint8Array(16);
  groups.forEach((group, index) => {
    bytes[index * 2] = group >> 8;
    bytes[index * 2 + 1] = group & 255;
  });
  return bytes;
}

/** The four bytes of an IPv4 address in dotted form, or null. */
export function ipv4Bytes(text: string): Uint8Array | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(text);
  if (!match) {
    return null;
  }
  const parts = match.slice(1, 5).map((part) => Number.parseInt(part, 10));
  return parts.some((part) => part > 255) ? null : new Uint8Array(parts);
}

/** The canonical text of an IPv6 address (RFC 5952: lower case, longest run of zero groups as `::`). */
export function formatIpv6(bytes: Uint8Array): string {
  const groups = Array.from({ length: 8 }, (_, index) => (bytes[index * 2] << 8) | bytes[index * 2 + 1]);
  let bestStart = -1;
  let bestLength = 1; // a single zero group is not shortened
  for (let start = 0; start < 8;) {
    if (groups[start] !== 0) {
      start++;
      continue;
    }
    let end = start;
    while (end < 8 && groups[end] === 0) {
      end++;
    }
    if (end - start > bestLength) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  const text = (from: number, to: number) => groups.slice(from, to).map((group) => group.toString(16)).join(':');
  return bestStart < 0 ? text(0, 8) : `${text(0, bestStart)}::${text(bestStart + bestLength, 8)}`;
}

/**
 * A host as the SDK keeps it: IPv4 dotted, IPv6 canonical, and an IPv4-mapped IPv6 address (what a
 * dual-stack socket reports for an IPv4 peer) as the IPv4 address it stands for. Null when the text
 * is not an IP address.
 */
export function normalizeHost(text: string): string | null {
  const ipv4 = ipv4Bytes(text);
  if (ipv4) {
    return Array.from(ipv4).join('.');
  }
  const ipv6 = ipv6Bytes(text);
  if (!ipv6) {
    return null;
  }
  const mapped = ipv6.subarray(0, 10).every((byte) => byte === 0) && ipv6[10] === 0xff && ipv6[11] === 0xff;
  return mapped ? Array.from(ipv6.subarray(12)).join('.') : formatIpv6(ipv6);
}

export const isIpv6 = (host: string): boolean => host.includes(':');

/** A global unicast IPv6 address (2000::/3): reachable from elsewhere on the internet without NAT in between. */
export function isGlobalIpv6(host: string): boolean {
  const bytes = isIpv6(host) ? ipv6Bytes(host) : null;
  return bytes !== null && (bytes[0] & 0xe0) === 0x20;
}

/** `a.b.c.d:port` or `[address]:port`, as written in candidate lists. */
export function formatAddress(address: UdpAddress): string {
  return isIpv6(address.host) ? `[${address.host}]:${address.port}` : `${address.host}:${address.port}`;
}

/** Reads a candidate (`a.b.c.d:port` or `[address]:port`); null when it is neither. */
export function parseAddress(text: string): UdpAddress | null {
  const match = /^\[([^\]]+)\]:(\d{1,5})$/.exec(text) ?? /^([\d.]+):(\d{1,5})$/.exec(text);
  if (!match) {
    return null;
  }
  const port = Number.parseInt(match[2], 10);
  const host = normalizeHost(match[1]);
  if (!host || port < 1 || port > 65535) {
    return null;
  }
  return { host, port };
}

export const sameAddress = (a: UdpAddress, b: UdpAddress): boolean => a.host === b.host && a.port === b.port;
