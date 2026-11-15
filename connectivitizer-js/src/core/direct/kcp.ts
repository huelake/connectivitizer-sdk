// KCP: a reliable, ordered stream over datagrams.
//
// A port to TypeScript of the reference implementation ikcp.c by Lin Wei (skywind3000/kcp,
// MIT licence, revision b1a7a21), wire-compatible with it. The structure and the names follow the
// original so that the two can be compared line by line; the pluggable congestion control of the
// original is left out, because the protocol runs KCP with congestion control switched off.
//
// MIT License - Copyright (c) 2017 Lin Wei (skywind3000 at gmail.com)
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software
// and associated documentation files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions: The above copyright notice
// and this permission notice shall be included in all copies or substantial portions of the
// Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

const IKCP_RTO_NDL = 30;
const IKCP_RTO_MIN = 100;
const IKCP_RTO_DEF = 200;
const IKCP_RTO_MAX = 60000;
const IKCP_CMD_PUSH = 81;
const IKCP_CMD_ACK = 82;
const IKCP_CMD_WASK = 83;
const IKCP_CMD_WINS = 84;
const IKCP_ASK_SEND = 1;
const IKCP_ASK_TELL = 2;
const IKCP_WND_SND = 32;
const IKCP_WND_RCV = 128;
const IKCP_MTU_DEF = 1400;
const IKCP_INTERVAL = 100;
export const IKCP_OVERHEAD = 24;
const IKCP_DEADLINK = 20;
const IKCP_THRESH_INIT = 2;
const IKCP_THRESH_MIN = 2;
const IKCP_PROBE_INIT = 5000;
const IKCP_PROBE_LIMIT = 120000;
const IKCP_FASTACK_LIMIT = 5;

interface Segment {
  conv: number;
  cmd: number;
  frg: number;
  wnd: number;
  ts: number;
  sn: number;
  una: number;
  resendts: number;
  rto: number;
  fastack: number;
  xmit: number;
  data: Uint8Array;
}

/** Difference of two 32-bit timestamps or sequence numbers, correct across wrap-around. */
const timediff = (later: number, earlier: number): number => (later - earlier) | 0;
const u32 = (value: number): number => value >>> 0;

function newSegment(data: Uint8Array): Segment {
  return { conv: 0, cmd: 0, frg: 0, wnd: 0, ts: 0, sn: 0, una: 0, resendts: 0, rto: 0, fastack: 0, xmit: 0, data };
}

export class Kcp {
  /** Stream mode: segment boundaries carry no meaning and small writes are merged. */
  stream = false;
  /** Set to -1 when a segment was retransmitted so often that the link must be considered dead. */
  state = 0;

  private snd_una = 0;
  private snd_nxt = 0;
  private rcv_nxt = 0;
  private ssthresh = IKCP_THRESH_INIT;
  private rx_rttval = 0;
  private rx_srtt = 0;
  private rx_rto = IKCP_RTO_DEF;
  private rx_minrto = IKCP_RTO_MIN;
  private snd_wnd = IKCP_WND_SND;
  private rcv_wnd = IKCP_WND_RCV;
  private rmt_wnd = IKCP_WND_RCV;
  private cwnd = 0;
  private probe = 0;
  private current = 0;
  private interval = IKCP_INTERVAL;
  private ts_flush = IKCP_INTERVAL;
  private xmit = 0;
  private nodelay = 0;
  private updated = false;
  private ts_probe = 0;
  private probe_wait = 0;
  private incr = 0;
  private mtu = IKCP_MTU_DEF;
  private mss = IKCP_MTU_DEF - IKCP_OVERHEAD;
  private fastresend = 0;
  private fastlimit = IKCP_FASTACK_LIMIT;
  private nocwnd = 0;
  private readonly dead_link = IKCP_DEADLINK;
  private snd_queue: Segment[] = [];
  private rcv_queue: Segment[] = [];
  private snd_buf: Segment[] = [];
  private rcv_buf: Segment[] = [];
  private acklist: number[] = [];
  private buffer: Uint8Array;

  constructor(
    private readonly conv: number,
    private readonly output: (packet: Uint8Array) => void,
  ) {
    this.conv = u32(conv);
    this.buffer = new Uint8Array((this.mtu + IKCP_OVERHEAD) * 3);
  }

  /** Segments waiting to be sent or acknowledged. */
  get waitSnd(): number {
    return this.snd_buf.length + this.snd_queue.length;
  }

  /** Bytes that can be read now; -1 when there are none. */
  peekSize(): number {
    if (this.rcv_queue.length === 0) {
      return -1;
    }
    const first = this.rcv_queue[0];
    if (first.frg === 0) {
      return first.data.length;
    }
    if (this.rcv_queue.length < first.frg + 1) {
      return -1;
    }
    let length = 0;
    for (const seg of this.rcv_queue) {
      length += seg.data.length;
      if (seg.frg === 0) {
        break;
      }
    }
    return length;
  }

  /** The next message (in stream mode: the next piece of the stream), or null when nothing is ready. */
  recv(): Uint8Array | null {
    const peeksize = this.peekSize();
    if (peeksize < 0) {
      return null;
    }
    const recover = this.rcv_queue.length >= this.rcv_wnd;

    // merge fragment
    const result = new Uint8Array(peeksize);
    let length = 0;
    while (this.rcv_queue.length > 0) {
      const seg = this.rcv_queue.shift()!;
      result.set(seg.data, length);
      length += seg.data.length;
      if (seg.frg === 0) {
        break;
      }
    }

    // move available data from rcv_buf -> rcv_queue
    this.moveReceived();

    // fast recover
    if (this.rcv_queue.length < this.rcv_wnd && recover) {
      // ready to send back IKCP_CMD_WINS in flush: tell remote my window size
      this.probe |= IKCP_ASK_TELL;
    }
    return result;
  }

  /** Queues data for sending. Returns the number of bytes taken, or a negative value on error. */
  send(buffer: Uint8Array): number {
    let offset = 0;
    let len = buffer.length;
    let sent = 0;

    // append to previous segment in streaming mode (if possible)
    if (this.stream) {
      if (this.snd_queue.length > 0) {
        const old = this.snd_queue[this.snd_queue.length - 1];
        if (old.data.length < this.mss) {
          const capacity = this.mss - old.data.length;
          const extend = len < capacity ? len : capacity;
          const merged = new Uint8Array(old.data.length + extend);
          merged.set(old.data, 0);
          merged.set(buffer.subarray(0, extend), old.data.length);
          const seg = newSegment(merged);
          seg.frg = 0;
          this.snd_queue[this.snd_queue.length - 1] = seg;
          offset += extend;
          len -= extend;
          sent = extend;
        }
      }
      if (len <= 0) {
        return sent;
      }
    }

    let count = len <= this.mss ? 1 : Math.floor((len + this.mss - 1) / this.mss);
    if (count >= IKCP_WND_RCV) {
      if (this.stream && sent > 0) {
        return sent;
      }
      return -2;
    }
    if (count === 0) {
      count = 1;
    }

    // fragment
    for (let i = 0; i < count; i++) {
      const size = len > this.mss ? this.mss : len;
      const seg = newSegment(buffer.slice(offset, offset + size));
      seg.frg = this.stream ? 0 : count - i - 1;
      this.snd_queue.push(seg);
      offset += size;
      len -= size;
      sent += size;
    }
    return sent;
  }

  private updateAck(rtt: number): void {
    if (this.rx_srtt === 0) {
      this.rx_srtt = rtt;
      this.rx_rttval = Math.floor(rtt / 2);
    } else {
      let delta = rtt - this.rx_srtt;
      if (delta < 0) {
        delta = -delta;
      }
      this.rx_rttval = Math.floor((3 * this.rx_rttval + delta) / 4);
      this.rx_srtt = Math.floor((7 * this.rx_srtt + rtt) / 8);
      if (this.rx_srtt < 1) {
        this.rx_srtt = 1;
      }
    }
    const rto = this.rx_srtt + Math.max(this.interval, 4 * this.rx_rttval);
    this.rx_rto = Math.min(Math.max(this.rx_minrto, rto), IKCP_RTO_MAX);
  }

  private shrinkBuf(): void {
    this.snd_una = this.snd_buf.length > 0 ? this.snd_buf[0].sn : this.snd_nxt;
  }

  private parseAck(sn: number): void {
    if (timediff(sn, this.snd_una) < 0 || timediff(sn, this.snd_nxt) >= 0) {
      return;
    }
    for (let i = 0; i < this.snd_buf.length; i++) {
      const seg = this.snd_buf[i];
      if (sn === seg.sn) {
        this.snd_buf.splice(i, 1);
        break;
      }
      if (timediff(sn, seg.sn) < 0) {
        break;
      }
    }
  }

  private parseUna(una: number): void {
    let count = 0;
    for (const seg of this.snd_buf) {
      if (timediff(una, seg.sn) > 0) {
        count++;
      } else {
        break;
      }
    }
    if (count > 0) {
      this.snd_buf.splice(0, count);
    }
  }

  private parseFastack(sn: number, ts: number): void {
    if (timediff(sn, this.snd_una) < 0 || timediff(sn, this.snd_nxt) >= 0) {
      return;
    }
    for (const seg of this.snd_buf) {
      if (timediff(sn, seg.sn) < 0) {
        break;
      } else if (sn !== seg.sn) {
        // IKCP_FASTACK_CONSERVE, as the reference is built
        if (timediff(ts, seg.ts) >= 0) {
          seg.fastack++;
        }
      }
    }
  }

  private parseData(newseg: Segment): void {
    const sn = newseg.sn;
    if (timediff(sn, u32(this.rcv_nxt + this.rcv_wnd)) >= 0 || timediff(sn, this.rcv_nxt) < 0) {
      return;
    }

    let repeat = false;
    let index = this.rcv_buf.length - 1;
    for (; index >= 0; index--) {
      const seg = this.rcv_buf[index];
      if (seg.sn === sn) {
        repeat = true;
        break;
      }
      if (timediff(sn, seg.sn) > 0) {
        break;
      }
    }
    if (!repeat) {
      this.rcv_buf.splice(index + 1, 0, newseg);
    }

    // move available data from rcv_buf -> rcv_queue
    this.moveReceived();
  }

  private moveReceived(): void {
    while (this.rcv_buf.length > 0) {
      const seg = this.rcv_buf[0];
      if (seg.sn === this.rcv_nxt && this.rcv_queue.length < this.rcv_wnd) {
        this.rcv_buf.shift();
        this.rcv_queue.push(seg);
        this.rcv_nxt = u32(this.rcv_nxt + 1);
      } else {
        break;
      }
    }
  }

  /** Feeds one received packet. Returns 0, or a negative value when the packet is not valid. */
  input(data: Uint8Array): number {
    const prev_una = this.snd_una;
    let maxack = 0;
    let latest_ts = 0;
    let flag = false;
    let offset = 0;
    let size = data.length;

    if (size < IKCP_OVERHEAD) {
      return -1;
    }
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

    while (true) {
      if (size < IKCP_OVERHEAD) {
        break;
      }
      const conv = view.getUint32(offset, true);
      if (conv !== this.conv) {
        return -1;
      }
      const cmd = view.getUint8(offset + 4);
      const frg = view.getUint8(offset + 5);
      const wnd = view.getUint16(offset + 6, true);
      const ts = view.getUint32(offset + 8, true);
      const sn = view.getUint32(offset + 12, true);
      const una = view.getUint32(offset + 16, true);
      const len = view.getUint32(offset + 20, true);
      offset += IKCP_OVERHEAD;
      size -= IKCP_OVERHEAD;

      if (size < len || len > 0x7fffffff) {
        return -2;
      }
      if (cmd !== IKCP_CMD_PUSH && cmd !== IKCP_CMD_ACK && cmd !== IKCP_CMD_WASK && cmd !== IKCP_CMD_WINS) {
        return -3;
      }

      this.rmt_wnd = wnd;
      this.parseUna(una);
      this.shrinkBuf();

      if (cmd === IKCP_CMD_ACK) {
        if (timediff(this.current, ts) >= 0) {
          this.updateAck(timediff(this.current, ts));
        }
        this.parseAck(sn);
        this.shrinkBuf();
        if (!flag) {
          flag = true;
          maxack = sn;
          latest_ts = ts;
        } else if (timediff(sn, maxack) > 0) {
          // IKCP_FASTACK_CONSERVE
          if (timediff(ts, latest_ts) > 0) {
            maxack = sn;
            latest_ts = ts;
          }
        }
      } else if (cmd === IKCP_CMD_PUSH) {
        if (timediff(sn, u32(this.rcv_nxt + this.rcv_wnd)) < 0) {
          this.acklist.push(sn, ts);
          if (timediff(sn, this.rcv_nxt) >= 0) {
            const seg = newSegment(data.slice(offset, offset + len));
            seg.conv = conv;
            seg.cmd = cmd;
            seg.frg = frg;
            seg.wnd = wnd;
            seg.ts = ts;
            seg.sn = sn;
            seg.una = una;
            this.parseData(seg);
          }
        }
      } else if (cmd === IKCP_CMD_WASK) {
        // ready to send back IKCP_CMD_WINS in flush: tell remote my window size
        this.probe |= IKCP_ASK_TELL;
      }
      // IKCP_CMD_WINS: nothing to do, rmt_wnd is already updated

      offset += len;
      size -= len;
    }

    if (flag) {
      this.parseFastack(maxack, latest_ts);
    }

    if (timediff(this.snd_una, prev_una) > 0) {
      if (this.cwnd < this.rmt_wnd) {
        const mss = this.mss;
        if (this.cwnd < this.ssthresh) {
          this.cwnd++;
          this.incr += mss;
        } else {
          if (this.incr < mss) {
            this.incr = mss;
          }
          this.incr += Math.floor((mss * mss) / this.incr) + Math.floor(mss / 16);
          if ((this.cwnd + 1) * mss <= this.incr) {
            this.cwnd = Math.floor((this.incr + mss - 1) / (mss > 0 ? mss : 1));
          }
        }
        if (this.cwnd > this.rmt_wnd) {
          this.cwnd = this.rmt_wnd;
          this.incr = this.rmt_wnd * mss;
        }
      }
    }
    return 0;
  }

  private encodeSegment(view: DataView, offset: number, seg: Segment, length: number): number {
    view.setUint32(offset, seg.conv, true);
    view.setUint8(offset + 4, seg.cmd);
    view.setUint8(offset + 5, seg.frg);
    view.setUint16(offset + 6, seg.wnd, true);
    view.setUint32(offset + 8, seg.ts, true);
    view.setUint32(offset + 12, seg.sn, true);
    view.setUint32(offset + 16, seg.una, true);
    view.setUint32(offset + 20, length, true);
    return offset + IKCP_OVERHEAD;
  }

  private wndUnused(): number {
    return this.rcv_queue.length < this.rcv_wnd ? this.rcv_wnd - this.rcv_queue.length : 0;
  }

  /** Sends what is due: acknowledgements, window probes, new and retransmitted data. */
  flush(): void {
    // 'update' hasn't been called yet.
    if (!this.updated) {
      return;
    }
    const current = this.current;
    const buffer = this.buffer;
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    let ptr = 0;
    let change = 0;
    let lost = false;
    const prior_cwnd = this.cwnd;

    const emit = () => {
      this.output(buffer.slice(0, ptr));
      ptr = 0;
    };

    const seg = newSegment(new Uint8Array(0));
    seg.conv = this.conv;
    seg.cmd = IKCP_CMD_ACK;
    seg.wnd = this.wndUnused();
    seg.una = this.rcv_nxt;

    // flush acknowledges
    for (let i = 0; i < this.acklist.length; i += 2) {
      if (ptr + IKCP_OVERHEAD > this.mtu) {
        emit();
      }
      seg.sn = this.acklist[i];
      seg.ts = this.acklist[i + 1];
      ptr = this.encodeSegment(view, ptr, seg, 0);
    }
    this.acklist = [];

    // probe window size (if remote window size equals zero)
    if (this.rmt_wnd === 0) {
      if (this.probe_wait === 0) {
        this.probe_wait = IKCP_PROBE_INIT;
        this.ts_probe = u32(this.current + this.probe_wait);
      } else if (timediff(this.current, this.ts_probe) >= 0) {
        if (this.probe_wait < IKCP_PROBE_INIT) {
          this.probe_wait = IKCP_PROBE_INIT;
        }
        this.probe_wait += Math.floor(this.probe_wait / 2);
        if (this.probe_wait > IKCP_PROBE_LIMIT) {
          this.probe_wait = IKCP_PROBE_LIMIT;
        }
        this.ts_probe = u32(this.current + this.probe_wait);
        this.probe |= IKCP_ASK_SEND;
      }
    } else {
      this.ts_probe = 0;
      this.probe_wait = 0;
    }

    // flush window probing commands
    if (this.probe & IKCP_ASK_SEND) {
      seg.cmd = IKCP_CMD_WASK;
      if (ptr + IKCP_OVERHEAD > this.mtu) {
        emit();
      }
      ptr = this.encodeSegment(view, ptr, seg, 0);
    }
    if (this.probe & IKCP_ASK_TELL) {
      seg.cmd = IKCP_CMD_WINS;
      if (ptr + IKCP_OVERHEAD > this.mtu) {
        emit();
      }
      ptr = this.encodeSegment(view, ptr, seg, 0);
    }
    this.probe = 0;

    // calculate window size
    let cwnd = Math.min(this.snd_wnd, this.rmt_wnd);
    if (this.nocwnd === 0) {
      cwnd = Math.min(this.cwnd, cwnd);
    }

    // move data from snd_queue to snd_buf
    while (timediff(this.snd_nxt, u32(this.snd_una + cwnd)) < 0) {
      const newseg = this.snd_queue.shift();
      if (!newseg) {
        break;
      }
      this.snd_buf.push(newseg);
      newseg.conv = this.conv;
      newseg.cmd = IKCP_CMD_PUSH;
      newseg.wnd = seg.wnd;
      newseg.ts = current;
      newseg.sn = this.snd_nxt;
      this.snd_nxt = u32(this.snd_nxt + 1);
      newseg.una = this.rcv_nxt;
      newseg.resendts = current;
      newseg.rto = this.rx_rto;
      newseg.fastack = 0;
      newseg.xmit = 0;
    }

    // calculate resent
    const resent = this.fastresend > 0 ? this.fastresend : 0xffffffff;
    const rtomin = this.nodelay === 0 ? this.rx_rto >> 3 : 0;

    // flush data segments
    for (const segment of this.snd_buf) {
      let needsend = false;
      if (segment.xmit === 0) {
        needsend = true;
        segment.xmit++;
        segment.rto = this.rx_rto;
        segment.resendts = u32(current + segment.rto + rtomin);
      } else if (timediff(current, segment.resendts) >= 0) {
        needsend = true;
        segment.xmit++;
        this.xmit++;
        if (this.nodelay === 0) {
          segment.rto += Math.max(segment.rto, this.rx_rto);
        } else {
          const step = this.nodelay < 2 ? segment.rto : this.rx_rto;
          segment.rto += Math.floor(step / 2);
        }
        segment.resendts = u32(current + segment.rto);
        lost = true;
      } else if (segment.fastack >= resent) {
        if (segment.xmit <= this.fastlimit || this.fastlimit <= 0) {
          needsend = true;
          segment.xmit++;
          segment.fastack = 0;
          segment.resendts = u32(current + segment.rto);
          change++;
        }
      }

      if (needsend) {
        segment.ts = current;
        segment.wnd = seg.wnd;
        segment.una = this.rcv_nxt;

        const need = IKCP_OVERHEAD + segment.data.length;
        if (ptr + need > this.mtu) {
          emit();
        }
        ptr = this.encodeSegment(view, ptr, segment, segment.data.length);
        if (segment.data.length > 0) {
          buffer.set(segment.data, ptr);
          ptr += segment.data.length;
        }
        if (segment.xmit >= this.dead_link) {
          this.state = -1;
        }
      }
    }

    // flash remaining segments
    if (ptr > 0) {
      emit();
    }

    // update ssthresh
    if (change) {
      const inflight = u32(this.snd_nxt - this.snd_una);
      this.ssthresh = Math.floor(inflight / 2);
      if (this.ssthresh < IKCP_THRESH_MIN) {
        this.ssthresh = IKCP_THRESH_MIN;
      }
      this.cwnd = this.ssthresh + resent;
      this.incr = this.cwnd * this.mss;
    }
    if (lost) {
      this.ssthresh = Math.floor(prior_cwnd / 2);
      if (this.ssthresh < IKCP_THRESH_MIN) {
        this.ssthresh = IKCP_THRESH_MIN;
      }
      this.cwnd = 1;
      this.incr = this.mss;
    }
    if (this.cwnd < 1) {
      this.cwnd = 1;
      this.incr = this.mss;
    }
  }

  /**
   * Drives the state machine. Call it repeatedly (every 10-100 ms), or ask {@link check} when to
   * call it next. `current` is a timestamp in milliseconds, taken modulo 2^32.
   */
  update(current: number): void {
    this.current = u32(current);
    if (!this.updated) {
      this.updated = true;
      this.ts_flush = this.current;
    }

    let slap = timediff(this.current, this.ts_flush);
    if (slap >= 10000 || slap < -10000) {
      this.ts_flush = this.current;
      slap = 0;
    }
    if (slap >= 0) {
      this.ts_flush = u32(this.ts_flush + this.interval);
      if (timediff(this.current, this.ts_flush) >= 0) {
        this.ts_flush = u32(this.current + this.interval);
      }
      this.flush();
    }
  }

  /** The timestamp at which {@link update} has to be called next, if nothing is sent or received before. */
  check(current: number): number {
    current = u32(current);
    let ts_flush = this.ts_flush;
    let tm_packet = 0x7fffffff;
    if (!this.updated) {
      return current;
    }
    if (timediff(current, ts_flush) >= 10000 || timediff(current, ts_flush) < -10000) {
      ts_flush = current;
    }
    if (timediff(current, ts_flush) >= 0) {
      return current;
    }
    const tm_flush = timediff(ts_flush, current);
    for (const seg of this.snd_buf) {
      const diff = timediff(seg.resendts, current);
      if (diff <= 0) {
        return current;
      }
      if (diff < tm_packet) {
        tm_packet = diff;
      }
    }
    let minimal = tm_packet < tm_flush ? tm_packet : tm_flush;
    if (minimal >= this.interval) {
      minimal = this.interval;
    }
    return u32(current + minimal);
  }

  setMtu(mtu: number): number {
    if (mtu < 50 || mtu < IKCP_OVERHEAD) {
      return -1;
    }
    this.mtu = mtu;
    this.mss = this.mtu - IKCP_OVERHEAD;
    this.buffer = new Uint8Array((mtu + IKCP_OVERHEAD) * 3);
    return 0;
  }

  noDelay(nodelay: number, interval: number, resend: number, nc: number): void {
    if (nodelay >= 0) {
      this.nodelay = nodelay;
      this.rx_minrto = nodelay ? IKCP_RTO_NDL : IKCP_RTO_MIN;
    }
    if (interval >= 0) {
      this.interval = Math.min(Math.max(interval, 10), 5000);
    }
    if (resend >= 0) {
      this.fastresend = resend;
    }
    if (nc >= 0) {
      this.nocwnd = nc;
    }
  }

  wndSize(sndwnd: number, rcvwnd: number): void {
    if (sndwnd > 0) {
      this.snd_wnd = sndwnd;
    }
    if (rcvwnd > 0) {
      // must be at least the largest number of fragments of one message
      this.rcv_wnd = Math.max(rcvwnd, IKCP_WND_RCV);
    }
  }
}
