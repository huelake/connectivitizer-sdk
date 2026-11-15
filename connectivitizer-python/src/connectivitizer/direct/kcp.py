"""KCP: a reliable, ordered stream over datagrams.

A port to Python of the reference implementation ikcp.c by Lin Wei (skywind3000/kcp, MIT licence, revision
b1a7a21), wire-compatible with it, following the TypeScript port of this repository line by line. The
pluggable congestion control of the original is left out, because the protocol runs KCP with congestion
control switched off.

MIT License - Copyright (c) 2017 Lin Wei (skywind3000 at gmail.com)
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without
limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
Software, and to permit persons to whom the Software is furnished to do so, subject to the following
conditions: The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
"""

from __future__ import annotations

import struct
from typing import Callable, List, Optional

IKCP_RTO_NDL = 30
IKCP_RTO_MIN = 100
IKCP_RTO_DEF = 200
IKCP_RTO_MAX = 60000
IKCP_CMD_PUSH = 81
IKCP_CMD_ACK = 82
IKCP_CMD_WASK = 83
IKCP_CMD_WINS = 84
IKCP_ASK_SEND = 1
IKCP_ASK_TELL = 2
IKCP_WND_SND = 32
IKCP_WND_RCV = 128
IKCP_MTU_DEF = 1400
IKCP_INTERVAL = 100
IKCP_OVERHEAD = 24
IKCP_DEADLINK = 20
IKCP_THRESH_INIT = 2
IKCP_THRESH_MIN = 2
IKCP_PROBE_INIT = 5000
IKCP_PROBE_LIMIT = 120000
IKCP_FASTACK_LIMIT = 5

_HEADER = struct.Struct("<IBBHIIII")


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _timediff(later: int, earlier: int) -> int:
    """Difference of two 32-bit timestamps or sequence numbers, correct across wrap-around."""
    diff = (later - earlier) & 0xFFFFFFFF
    return diff - 0x100000000 if diff >= 0x80000000 else diff


class _Segment:
    __slots__ = ("conv", "cmd", "frg", "wnd", "ts", "sn", "una", "resendts", "rto", "fastack", "xmit", "data")

    def __init__(self, data: bytes) -> None:
        self.conv = self.cmd = self.frg = self.wnd = self.ts = self.sn = self.una = 0
        self.resendts = self.rto = self.fastack = self.xmit = 0
        self.data = data


class Kcp:
    def __init__(self, conv: int, output: Callable[[bytes], None]) -> None:
        self.conv = _u32(conv)
        self._output = output
        self.stream = False
        """Stream mode: segment boundaries carry no meaning and small writes are merged."""
        self.state = 0
        """Set to -1 when a segment was retransmitted so often that the link must be considered dead."""
        self.snd_una = 0
        self.snd_nxt = 0
        self.rcv_nxt = 0
        self.ssthresh = IKCP_THRESH_INIT
        self.rx_rttval = 0
        self.rx_srtt = 0
        self.rx_rto = IKCP_RTO_DEF
        self.rx_minrto = IKCP_RTO_MIN
        self.snd_wnd = IKCP_WND_SND
        self.rcv_wnd = IKCP_WND_RCV
        self.rmt_wnd = IKCP_WND_RCV
        self.cwnd = 0
        self.probe = 0
        self.current = 0
        self.interval = IKCP_INTERVAL
        self.ts_flush = IKCP_INTERVAL
        self.xmit = 0
        self.nodelay = 0
        self.updated = False
        self.ts_probe = 0
        self.probe_wait = 0
        self.incr = 0
        self.mtu = IKCP_MTU_DEF
        self.mss = IKCP_MTU_DEF - IKCP_OVERHEAD
        self.fastresend = 0
        self.fastlimit = IKCP_FASTACK_LIMIT
        self.nocwnd = 0
        self.dead_link = IKCP_DEADLINK
        self.snd_queue: List[_Segment] = []
        self.rcv_queue: List[_Segment] = []
        self.snd_buf: List[_Segment] = []
        self.rcv_buf: List[_Segment] = []
        self.acklist: List[int] = []

    @property
    def wait_snd(self) -> int:
        """Segments waiting to be sent or acknowledged."""
        return len(self.snd_buf) + len(self.snd_queue)

    def peek_size(self) -> int:
        """Bytes that can be read now; -1 when there are none."""
        if not self.rcv_queue:
            return -1
        first = self.rcv_queue[0]
        if first.frg == 0:
            return len(first.data)
        if len(self.rcv_queue) < first.frg + 1:
            return -1
        length = 0
        for seg in self.rcv_queue:
            length += len(seg.data)
            if seg.frg == 0:
                break
        return length

    def recv(self) -> Optional[bytes]:
        """The next message (in stream mode: the next piece of the stream), or None when nothing is ready."""
        if self.peek_size() < 0:
            return None
        recover = len(self.rcv_queue) >= self.rcv_wnd
        # merge fragment
        parts = []
        while self.rcv_queue:
            seg = self.rcv_queue.pop(0)
            parts.append(seg.data)
            if seg.frg == 0:
                break
        # move available data from rcv_buf -> rcv_queue
        self._move_received()
        # fast recover
        if len(self.rcv_queue) < self.rcv_wnd and recover:
            # ready to send back IKCP_CMD_WINS in flush: tell remote my window size
            self.probe |= IKCP_ASK_TELL
        return b"".join(parts)

    def send(self, buffer: bytes) -> int:
        """Queues data for sending. Returns the number of bytes taken, or a negative value on error."""
        offset = 0
        length = len(buffer)
        sent = 0
        # append to previous segment in streaming mode (if possible)
        if self.stream:
            if self.snd_queue:
                old = self.snd_queue[-1]
                if len(old.data) < self.mss:
                    capacity = self.mss - len(old.data)
                    extend = length if length < capacity else capacity
                    seg = _Segment(old.data + bytes(buffer[:extend]))
                    seg.frg = 0
                    self.snd_queue[-1] = seg
                    offset += extend
                    length -= extend
                    sent = extend
            if length <= 0:
                return sent

        count = 1 if length <= self.mss else (length + self.mss - 1) // self.mss
        if count >= IKCP_WND_RCV:
            if self.stream and sent > 0:
                return sent
            return -2
        if count == 0:
            count = 1
        # fragment
        for i in range(count):
            size = self.mss if length > self.mss else length
            seg = _Segment(bytes(buffer[offset : offset + size]))
            seg.frg = 0 if self.stream else count - i - 1
            self.snd_queue.append(seg)
            offset += size
            length -= size
            sent += size
        return sent

    def _update_ack(self, rtt: int) -> None:
        if self.rx_srtt == 0:
            self.rx_srtt = rtt
            self.rx_rttval = rtt // 2
        else:
            delta = abs(rtt - self.rx_srtt)
            self.rx_rttval = (3 * self.rx_rttval + delta) // 4
            self.rx_srtt = (7 * self.rx_srtt + rtt) // 8
            if self.rx_srtt < 1:
                self.rx_srtt = 1
        rto = self.rx_srtt + max(self.interval, 4 * self.rx_rttval)
        self.rx_rto = min(max(self.rx_minrto, rto), IKCP_RTO_MAX)

    def _shrink_buf(self) -> None:
        self.snd_una = self.snd_buf[0].sn if self.snd_buf else self.snd_nxt

    def _parse_ack(self, sn: int) -> None:
        if _timediff(sn, self.snd_una) < 0 or _timediff(sn, self.snd_nxt) >= 0:
            return
        for i, seg in enumerate(self.snd_buf):
            if sn == seg.sn:
                del self.snd_buf[i]
                break
            if _timediff(sn, seg.sn) < 0:
                break

    def _parse_una(self, una: int) -> None:
        count = 0
        for seg in self.snd_buf:
            if _timediff(una, seg.sn) > 0:
                count += 1
            else:
                break
        if count > 0:
            del self.snd_buf[:count]

    def _parse_fastack(self, sn: int, ts: int) -> None:
        if _timediff(sn, self.snd_una) < 0 or _timediff(sn, self.snd_nxt) >= 0:
            return
        for seg in self.snd_buf:
            if _timediff(sn, seg.sn) < 0:
                break
            elif sn != seg.sn:
                # IKCP_FASTACK_CONSERVE, as the reference is built
                if _timediff(ts, seg.ts) >= 0:
                    seg.fastack += 1

    def _parse_data(self, newseg: _Segment) -> None:
        sn = newseg.sn
        if _timediff(sn, _u32(self.rcv_nxt + self.rcv_wnd)) >= 0 or _timediff(sn, self.rcv_nxt) < 0:
            return
        repeat = False
        index = len(self.rcv_buf) - 1
        while index >= 0:
            seg = self.rcv_buf[index]
            if seg.sn == sn:
                repeat = True
                break
            if _timediff(sn, seg.sn) > 0:
                break
            index -= 1
        if not repeat:
            self.rcv_buf.insert(index + 1, newseg)
        # move available data from rcv_buf -> rcv_queue
        self._move_received()

    def _move_received(self) -> None:
        while self.rcv_buf:
            seg = self.rcv_buf[0]
            if seg.sn == self.rcv_nxt and len(self.rcv_queue) < self.rcv_wnd:
                self.rcv_buf.pop(0)
                self.rcv_queue.append(seg)
                self.rcv_nxt = _u32(self.rcv_nxt + 1)
            else:
                break

    def input(self, data: bytes) -> int:
        """Feeds one received packet. Returns 0, or a negative value when the packet is not valid."""
        prev_una = self.snd_una
        maxack = 0
        latest_ts = 0
        flag = False
        offset = 0
        size = len(data)
        if size < IKCP_OVERHEAD:
            return -1
        while True:
            if size < IKCP_OVERHEAD:
                break
            conv, cmd, frg, wnd, ts, sn, una, length = _HEADER.unpack_from(data, offset)
            if conv != self.conv:
                return -1
            offset += IKCP_OVERHEAD
            size -= IKCP_OVERHEAD
            if size < length or length > 0x7FFFFFFF:
                return -2
            if cmd not in (IKCP_CMD_PUSH, IKCP_CMD_ACK, IKCP_CMD_WASK, IKCP_CMD_WINS):
                return -3

            self.rmt_wnd = wnd
            self._parse_una(una)
            self._shrink_buf()

            if cmd == IKCP_CMD_ACK:
                if _timediff(self.current, ts) >= 0:
                    self._update_ack(_timediff(self.current, ts))
                self._parse_ack(sn)
                self._shrink_buf()
                if not flag:
                    flag = True
                    maxack = sn
                    latest_ts = ts
                elif _timediff(sn, maxack) > 0:
                    # IKCP_FASTACK_CONSERVE
                    if _timediff(ts, latest_ts) > 0:
                        maxack = sn
                        latest_ts = ts
            elif cmd == IKCP_CMD_PUSH:
                if _timediff(sn, _u32(self.rcv_nxt + self.rcv_wnd)) < 0:
                    self.acklist.append(sn)
                    self.acklist.append(ts)
                    if _timediff(sn, self.rcv_nxt) >= 0:
                        seg = _Segment(bytes(data[offset : offset + length]))
                        seg.conv, seg.cmd, seg.frg, seg.wnd, seg.ts, seg.sn, seg.una = conv, cmd, frg, wnd, ts, sn, una
                        self._parse_data(seg)
            elif cmd == IKCP_CMD_WASK:
                # ready to send back IKCP_CMD_WINS in flush: tell remote my window size
                self.probe |= IKCP_ASK_TELL
            # IKCP_CMD_WINS: nothing to do, rmt_wnd is already updated
            offset += length
            size -= length

        if flag:
            self._parse_fastack(maxack, latest_ts)

        if _timediff(self.snd_una, prev_una) > 0:
            if self.cwnd < self.rmt_wnd:
                mss = self.mss
                if self.cwnd < self.ssthresh:
                    self.cwnd += 1
                    self.incr += mss
                else:
                    if self.incr < mss:
                        self.incr = mss
                    self.incr += (mss * mss) // self.incr + mss // 16
                    if (self.cwnd + 1) * mss <= self.incr:
                        self.cwnd = (self.incr + mss - 1) // (mss if mss > 0 else 1)
                if self.cwnd > self.rmt_wnd:
                    self.cwnd = self.rmt_wnd
                    self.incr = self.rmt_wnd * mss
        return 0

    def _wnd_unused(self) -> int:
        return self.rcv_wnd - len(self.rcv_queue) if len(self.rcv_queue) < self.rcv_wnd else 0

    def flush(self) -> None:
        """Sends what is due: acknowledgements, window probes, new and retransmitted data."""
        # 'update' hasn't been called yet.
        if not self.updated:
            return
        current = self.current
        buffer = bytearray()
        change = 0
        lost = False
        prior_cwnd = self.cwnd

        def emit() -> None:
            self._output(bytes(buffer))
            buffer.clear()

        wnd = self._wnd_unused()

        def encode(cmd: int, frg: int, seg_wnd: int, ts: int, sn: int, una: int, payload: bytes = b"") -> None:
            buffer.extend(_HEADER.pack(self.conv, cmd, frg, seg_wnd, ts, sn, una, len(payload)))
            if payload:
                buffer.extend(payload)

        # flush acknowledges
        acks = self.acklist
        for i in range(0, len(acks), 2):
            if len(buffer) + IKCP_OVERHEAD > self.mtu:
                emit()
            encode(IKCP_CMD_ACK, 0, wnd, acks[i + 1], acks[i], self.rcv_nxt)
        self.acklist = []

        # probe window size (if remote window size equals zero)
        if self.rmt_wnd == 0:
            if self.probe_wait == 0:
                self.probe_wait = IKCP_PROBE_INIT
                self.ts_probe = _u32(self.current + self.probe_wait)
            elif _timediff(self.current, self.ts_probe) >= 0:
                if self.probe_wait < IKCP_PROBE_INIT:
                    self.probe_wait = IKCP_PROBE_INIT
                self.probe_wait += self.probe_wait // 2
                if self.probe_wait > IKCP_PROBE_LIMIT:
                    self.probe_wait = IKCP_PROBE_LIMIT
                self.ts_probe = _u32(self.current + self.probe_wait)
                self.probe |= IKCP_ASK_SEND
        else:
            self.ts_probe = 0
            self.probe_wait = 0

        # flush window probing commands (the reference reuses the last ack's sn and ts here)
        last_sn = acks[-2] if acks else 0
        last_ts = acks[-1] if acks else 0
        if self.probe & IKCP_ASK_SEND:
            if len(buffer) + IKCP_OVERHEAD > self.mtu:
                emit()
            encode(IKCP_CMD_WASK, 0, wnd, last_ts, last_sn, self.rcv_nxt)
        if self.probe & IKCP_ASK_TELL:
            if len(buffer) + IKCP_OVERHEAD > self.mtu:
                emit()
            encode(IKCP_CMD_WINS, 0, wnd, last_ts, last_sn, self.rcv_nxt)
        self.probe = 0

        # calculate window size
        cwnd = min(self.snd_wnd, self.rmt_wnd)
        if self.nocwnd == 0:
            cwnd = min(self.cwnd, cwnd)

        # move data from snd_queue to snd_buf
        while _timediff(self.snd_nxt, _u32(self.snd_una + cwnd)) < 0:
            if not self.snd_queue:
                break
            newseg = self.snd_queue.pop(0)
            self.snd_buf.append(newseg)
            newseg.conv = self.conv
            newseg.cmd = IKCP_CMD_PUSH
            newseg.wnd = wnd
            newseg.ts = current
            newseg.sn = self.snd_nxt
            self.snd_nxt = _u32(self.snd_nxt + 1)
            newseg.una = self.rcv_nxt
            newseg.resendts = current
            newseg.rto = self.rx_rto
            newseg.fastack = 0
            newseg.xmit = 0

        # calculate resent
        resent = self.fastresend if self.fastresend > 0 else 0xFFFFFFFF
        rtomin = self.rx_rto >> 3 if self.nodelay == 0 else 0

        # flush data segments
        for segment in self.snd_buf:
            needsend = False
            if segment.xmit == 0:
                needsend = True
                segment.xmit += 1
                segment.rto = self.rx_rto
                segment.resendts = _u32(current + segment.rto + rtomin)
            elif _timediff(current, segment.resendts) >= 0:
                needsend = True
                segment.xmit += 1
                self.xmit += 1
                if self.nodelay == 0:
                    segment.rto += max(segment.rto, self.rx_rto)
                else:
                    step = segment.rto if self.nodelay < 2 else self.rx_rto
                    segment.rto += step // 2
                segment.resendts = _u32(current + segment.rto)
                lost = True
            elif segment.fastack >= resent:
                if segment.xmit <= self.fastlimit or self.fastlimit <= 0:
                    needsend = True
                    segment.xmit += 1
                    segment.fastack = 0
                    segment.resendts = _u32(current + segment.rto)
                    change += 1

            if needsend:
                segment.ts = current
                segment.wnd = wnd
                segment.una = self.rcv_nxt
                if len(buffer) + IKCP_OVERHEAD + len(segment.data) > self.mtu:
                    emit()
                encode(segment.cmd, segment.frg, segment.wnd, segment.ts, segment.sn, segment.una, segment.data)
                if segment.xmit >= self.dead_link:
                    self.state = -1

        # flash remaining segments
        if buffer:
            emit()

        # update ssthresh
        if change:
            inflight = _u32(self.snd_nxt - self.snd_una)
            self.ssthresh = max(inflight // 2, IKCP_THRESH_MIN)
            self.cwnd = self.ssthresh + resent
            self.incr = self.cwnd * self.mss
        if lost:
            self.ssthresh = max(prior_cwnd // 2, IKCP_THRESH_MIN)
            self.cwnd = 1
            self.incr = self.mss
        if self.cwnd < 1:
            self.cwnd = 1
            self.incr = self.mss

    def update(self, current: int) -> None:
        """Drives the state machine. Call it repeatedly (every 10-100 ms). ``current`` is a timestamp in
        milliseconds, taken modulo 2^32."""
        self.current = _u32(current)
        if not self.updated:
            self.updated = True
            self.ts_flush = self.current
        slap = _timediff(self.current, self.ts_flush)
        if slap >= 10000 or slap < -10000:
            self.ts_flush = self.current
            slap = 0
        if slap >= 0:
            self.ts_flush = _u32(self.ts_flush + self.interval)
            if _timediff(self.current, self.ts_flush) >= 0:
                self.ts_flush = _u32(self.current + self.interval)
            self.flush()

    def set_mtu(self, mtu: int) -> int:
        if mtu < 50 or mtu < IKCP_OVERHEAD:
            return -1
        self.mtu = mtu
        self.mss = mtu - IKCP_OVERHEAD
        return 0

    def no_delay(self, nodelay: int, interval: int, resend: int, nc: int) -> None:
        if nodelay >= 0:
            self.nodelay = nodelay
            self.rx_minrto = IKCP_RTO_NDL if nodelay else IKCP_RTO_MIN
        if interval >= 0:
            self.interval = min(max(interval, 10), 5000)
        if resend >= 0:
            self.fastresend = resend
        if nc >= 0:
            self.nocwnd = nc

    def wnd_size(self, sndwnd: int, rcvwnd: int) -> None:
        if sndwnd > 0:
            self.snd_wnd = sndwnd
        if rcvwnd > 0:
            # must be at least the largest number of fragments of one message
            self.rcv_wnd = max(rcvwnd, IKCP_WND_RCV)
