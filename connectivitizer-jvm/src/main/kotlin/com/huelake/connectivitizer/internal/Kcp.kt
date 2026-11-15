package com.huelake.connectivitizer.internal

import java.nio.ByteBuffer
import java.nio.ByteOrder

/*
 * KCP: a reliable, ordered stream over datagrams.
 *
 * A port to Kotlin of the reference implementation ikcp.c by Lin Wei (skywind3000/kcp, MIT licence, revision
 * b1a7a21), wire-compatible with it, following the TypeScript port of this repository line by line. The
 * pluggable congestion control of the original is left out: the protocol runs KCP with it switched off.
 * 32-bit unsigned values are kept in Long and masked.
 *
 * MIT License - Copyright (c) 2017 Lin Wei (skywind3000 at gmail.com)
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
 * following conditions: The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
internal class Kcp(conv: Long, private val output: (ByteArray) -> Unit) {
    private class Segment(val data: ByteArray) {
        var cmd = 0
        var frg = 0
        var wnd = 0L
        var ts = 0L
        var sn = 0L
        var una = 0L
        var resendts = 0L
        var rto = 0L
        var fastack = 0L
        var xmit = 0L
    }

    private val conv = conv and MASK
    var stream = false
    var state = 0
    private var sndUna = 0L
    private var sndNxt = 0L
    private var rcvNxt = 0L
    private var ssthresh = THRESH_INIT
    private var rxRttval = 0L
    private var rxSrtt = 0L
    private var rxRto = RTO_DEF
    private var rxMinrto = RTO_MIN
    private var sndWnd = WND_SND
    private var rcvWnd = WND_RCV
    private var rmtWnd = WND_RCV
    private var cwnd = 0L
    private var probe = 0
    private var current = 0L
    private var interval = INTERVAL
    private var tsFlush = INTERVAL
    private var xmit = 0L
    private var nodelay = 0L
    private var updated = false
    private var tsProbe = 0L
    private var probeWait = 0L
    private var incr = 0L
    private var mtu = MTU_DEF
    private var mss = MTU_DEF - OVERHEAD
    private var fastresend = 0L
    private val fastlimit = FASTACK_LIMIT
    private var nocwnd = 0L
    private val sndQueue = ArrayDeque<Segment>()
    private val rcvQueue = ArrayDeque<Segment>()
    private val sndBuf = ArrayList<Segment>()
    private val rcvBuf = ArrayList<Segment>()
    private var acklist = ArrayList<Long>()

    /** Segments waiting to be sent or acknowledged. */
    val waitSnd: Int get() = sndBuf.size + sndQueue.size

    /** Bytes that can be read now; -1 when there are none. */
    fun peekSize(): Int {
        val first = rcvQueue.firstOrNull() ?: return -1
        if (first.frg == 0) return first.data.size
        if (rcvQueue.size < first.frg + 1) return -1
        var length = 0
        for (seg in rcvQueue) {
            length += seg.data.size
            if (seg.frg == 0) break
        }
        return length
    }

    /** The next message (in stream mode: the next piece of the stream), or null when nothing is ready. */
    fun recv(): ByteArray? {
        val peeksize = peekSize()
        if (peeksize < 0) return null
        val recover = rcvQueue.size >= rcvWnd
        // merge fragment
        val result = ByteArray(peeksize)
        var length = 0
        while (rcvQueue.isNotEmpty()) {
            val seg = rcvQueue.removeFirst()
            System.arraycopy(seg.data, 0, result, length, seg.data.size)
            length += seg.data.size
            if (seg.frg == 0) break
        }
        // move available data from rcv_buf -> rcv_queue
        moveReceived()
        // fast recover: ready to send back IKCP_CMD_WINS in flush, to tell remote my window size
        if (rcvQueue.size < rcvWnd && recover) probe = probe or ASK_TELL
        return result
    }

    /** Queues data for sending. Returns the number of bytes taken, or a negative value on error. */
    fun send(buffer: ByteArray, from: Int = 0, to: Int = buffer.size): Int {
        var offset = from
        var len = to - from
        var sent = 0
        // append to previous segment in streaming mode (if possible)
        if (stream) {
            val old = sndQueue.lastOrNull()
            if (old != null && old.data.size < mss) {
                val capacity = (mss - old.data.size).toInt()
                val extend = minOf(len, capacity)
                val seg = Segment(old.data + buffer.copyOfRange(offset, offset + extend))
                sndQueue[sndQueue.size - 1] = seg
                offset += extend
                len -= extend
                sent = extend
            }
            if (len <= 0) return sent
        }
        var count = if (len <= mss) 1 else ((len + mss - 1) / mss).toInt()
        if (count >= WND_RCV) return if (stream && sent > 0) sent else -2
        if (count == 0) count = 1
        // fragment
        for (i in 0 until count) {
            val size = minOf(len.toLong(), mss).toInt()
            val seg = Segment(buffer.copyOfRange(offset, offset + size))
            seg.frg = if (stream) 0 else count - i - 1
            sndQueue.addLast(seg)
            offset += size
            len -= size
            sent += size
        }
        return sent
    }

    private fun updateAck(rtt: Long) {
        if (rxSrtt == 0L) {
            rxSrtt = rtt
            rxRttval = rtt / 2
        } else {
            val delta = Math.abs(rtt - rxSrtt)
            rxRttval = (3 * rxRttval + delta) / 4
            rxSrtt = (7 * rxSrtt + rtt) / 8
            if (rxSrtt < 1) rxSrtt = 1
        }
        val rto = rxSrtt + maxOf(interval, 4 * rxRttval)
        rxRto = minOf(maxOf(rxMinrto, rto), RTO_MAX)
    }

    private fun shrinkBuf() {
        sndUna = sndBuf.firstOrNull()?.sn ?: sndNxt
    }

    private fun parseAck(sn: Long) {
        if (diff(sn, sndUna) < 0 || diff(sn, sndNxt) >= 0) return
        for (i in sndBuf.indices) {
            val seg = sndBuf[i]
            if (sn == seg.sn) {
                sndBuf.removeAt(i)
                break
            }
            if (diff(sn, seg.sn) < 0) break
        }
    }

    private fun parseUna(una: Long) {
        var count = 0
        for (seg in sndBuf) if (diff(una, seg.sn) > 0) count++ else break
        if (count > 0) sndBuf.subList(0, count).clear()
    }

    private fun parseFastack(sn: Long, ts: Long) {
        if (diff(sn, sndUna) < 0 || diff(sn, sndNxt) >= 0) return
        for (seg in sndBuf) {
            if (diff(sn, seg.sn) < 0) break
            // IKCP_FASTACK_CONSERVE, as the reference is built
            if (sn != seg.sn && diff(ts, seg.ts) >= 0) seg.fastack++
        }
    }

    private fun parseData(newseg: Segment) {
        val sn = newseg.sn
        if (diff(sn, u32(rcvNxt + rcvWnd)) >= 0 || diff(sn, rcvNxt) < 0) return
        var repeat = false
        var index = rcvBuf.size - 1
        while (index >= 0) {
            val seg = rcvBuf[index]
            if (seg.sn == sn) {
                repeat = true
                break
            }
            if (diff(sn, seg.sn) > 0) break
            index--
        }
        if (!repeat) rcvBuf.add(index + 1, newseg)
        moveReceived()
    }

    private fun moveReceived() {
        while (rcvBuf.isNotEmpty()) {
            val seg = rcvBuf[0]
            if (seg.sn == rcvNxt && rcvQueue.size < rcvWnd) {
                rcvBuf.removeAt(0)
                rcvQueue.addLast(seg)
                rcvNxt = u32(rcvNxt + 1)
            } else {
                break
            }
        }
    }

    /** Feeds one received packet. Returns 0, or a negative value when the packet is not valid. */
    fun input(data: ByteArray, from: Int = 0, to: Int = data.size): Int {
        val prevUna = sndUna
        var maxack = 0L
        var latestTs = 0L
        var flag = false
        var offset = from
        var size = to - from
        if (size < OVERHEAD) return -1
        val view = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        while (size >= OVERHEAD) {
            val conv = view.getInt(offset).toLong() and MASK
            if (conv != this.conv) return -1
            val cmd = data[offset + 4].toInt() and 0xff
            val frg = data[offset + 5].toInt() and 0xff
            val wnd = (view.getShort(offset + 6).toInt() and 0xffff).toLong()
            val ts = view.getInt(offset + 8).toLong() and MASK
            val sn = view.getInt(offset + 12).toLong() and MASK
            val una = view.getInt(offset + 16).toLong() and MASK
            val len = view.getInt(offset + 20).toLong() and MASK
            offset += OVERHEAD.toInt()
            size -= OVERHEAD.toInt()
            if (size < len || len > 0x7fffffff) return -2
            if (cmd != CMD_PUSH && cmd != CMD_ACK && cmd != CMD_WASK && cmd != CMD_WINS) return -3
            rmtWnd = wnd
            parseUna(una)
            shrinkBuf()
            when (cmd) {
                CMD_ACK -> {
                    if (diff(current, ts) >= 0) updateAck(diff(current, ts))
                    parseAck(sn)
                    shrinkBuf()
                    if (!flag) {
                        flag = true
                        maxack = sn
                        latestTs = ts
                    } else if (diff(sn, maxack) > 0 && diff(ts, latestTs) > 0) {
                        // IKCP_FASTACK_CONSERVE
                        maxack = sn
                        latestTs = ts
                    }
                }
                CMD_PUSH -> if (diff(sn, u32(rcvNxt + rcvWnd)) < 0) {
                    acklist.add(sn)
                    acklist.add(ts)
                    if (diff(sn, rcvNxt) >= 0) {
                        val seg = Segment(data.copyOfRange(offset, offset + len.toInt()))
                        seg.cmd = cmd
                        seg.frg = frg
                        seg.wnd = wnd
                        seg.ts = ts
                        seg.sn = sn
                        seg.una = una
                        parseData(seg)
                    }
                }
                // ready to send back IKCP_CMD_WINS in flush: tell remote my window size
                CMD_WASK -> probe = probe or ASK_TELL
            }
            offset += len.toInt()
            size -= len.toInt()
        }
        if (flag) parseFastack(maxack, latestTs)
        if (diff(sndUna, prevUna) > 0 && cwnd < rmtWnd) {
            if (cwnd < ssthresh) {
                cwnd++
                incr += mss
            } else {
                if (incr < mss) incr = mss
                incr += (mss * mss) / incr + (mss / 16)
                if ((cwnd + 1) * mss <= incr) cwnd = (incr + mss - 1) / (if (mss > 0) mss else 1)
            }
            if (cwnd > rmtWnd) {
                cwnd = rmtWnd
                incr = rmtWnd * mss
            }
        }
        return 0
    }

    private fun wndUnused(): Long = if (rcvQueue.size < rcvWnd) rcvWnd - rcvQueue.size else 0

    /** Sends what is due: acknowledgements, window probes, new and retransmitted data. */
    fun flush() {
        if (!updated) return
        val current = this.current
        val buffer = ByteBuffer.allocate(((mtu + OVERHEAD) * 3).toInt()).order(ByteOrder.LITTLE_ENDIAN)
        var change = 0
        var lost = false
        val priorCwnd = cwnd
        fun emit() {
            output(buffer.array().copyOf(buffer.position()))
            buffer.clear()
        }
        fun encode(cmd: Int, frg: Int, wnd: Long, ts: Long, sn: Long, una: Long, payload: ByteArray?) {
            buffer.putInt(conv.toInt()).put(cmd.toByte()).put(frg.toByte()).putShort(wnd.toInt().toShort())
            buffer.putInt(ts.toInt()).putInt(sn.toInt()).putInt(una.toInt()).putInt(payload?.size ?: 0)
            if (payload != null) buffer.put(payload)
        }
        val wnd = wndUnused()
        // flush acknowledges
        val acks = acklist
        var i = 0
        while (i < acks.size) {
            if (buffer.position() + OVERHEAD > mtu) emit()
            encode(CMD_ACK, 0, wnd, acks[i + 1], acks[i], rcvNxt, null)
            i += 2
        }
        acklist = ArrayList()
        // probe window size (if remote window size equals zero)
        if (rmtWnd == 0L) {
            if (probeWait == 0L) {
                probeWait = PROBE_INIT
                tsProbe = u32(this.current + probeWait)
            } else if (diff(this.current, tsProbe) >= 0) {
                if (probeWait < PROBE_INIT) probeWait = PROBE_INIT
                probeWait += probeWait / 2
                if (probeWait > PROBE_LIMIT) probeWait = PROBE_LIMIT
                tsProbe = u32(this.current + probeWait)
                probe = probe or ASK_SEND
            }
        } else {
            tsProbe = 0
            probeWait = 0
        }
        // flush window probing commands (the reference reuses the last ack's sn and ts here)
        val lastSn = if (acks.isEmpty()) 0L else acks[acks.size - 2]
        val lastTs = if (acks.isEmpty()) 0L else acks[acks.size - 1]
        if (probe and ASK_SEND != 0) {
            if (buffer.position() + OVERHEAD > mtu) emit()
            encode(CMD_WASK, 0, wnd, lastTs, lastSn, rcvNxt, null)
        }
        if (probe and ASK_TELL != 0) {
            if (buffer.position() + OVERHEAD > mtu) emit()
            encode(CMD_WINS, 0, wnd, lastTs, lastSn, rcvNxt, null)
        }
        probe = 0
        // calculate window size
        var cwnd = minOf(sndWnd, rmtWnd)
        if (nocwnd == 0L) cwnd = minOf(this.cwnd, cwnd)
        // move data from snd_queue to snd_buf
        while (diff(sndNxt, u32(sndUna + cwnd)) < 0) {
            val newseg = sndQueue.removeFirstOrNull() ?: break
            sndBuf.add(newseg)
            newseg.cmd = CMD_PUSH
            newseg.wnd = wnd
            newseg.ts = current
            newseg.sn = sndNxt
            sndNxt = u32(sndNxt + 1)
            newseg.una = rcvNxt
            newseg.resendts = current
            newseg.rto = rxRto
            newseg.fastack = 0
            newseg.xmit = 0
        }
        // calculate resent
        val resent = if (fastresend > 0) fastresend else 0xffffffffL
        val rtomin = if (nodelay == 0L) rxRto shr 3 else 0
        // flush data segments
        for (segment in sndBuf) {
            var needsend = false
            if (segment.xmit == 0L) {
                needsend = true
                segment.xmit++
                segment.rto = rxRto
                segment.resendts = u32(current + segment.rto + rtomin)
            } else if (diff(current, segment.resendts) >= 0) {
                needsend = true
                segment.xmit++
                xmit++
                if (nodelay == 0L) {
                    segment.rto += maxOf(segment.rto, rxRto)
                } else {
                    val step = if (nodelay < 2) segment.rto else rxRto
                    segment.rto += step / 2
                }
                segment.resendts = u32(current + segment.rto)
                lost = true
            } else if (segment.fastack >= resent) {
                if (segment.xmit <= fastlimit || fastlimit <= 0) {
                    needsend = true
                    segment.xmit++
                    segment.fastack = 0
                    segment.resendts = u32(current + segment.rto)
                    change++
                }
            }
            if (needsend) {
                segment.ts = current
                segment.wnd = wnd
                segment.una = rcvNxt
                if (buffer.position() + OVERHEAD + segment.data.size > mtu) emit()
                encode(segment.cmd, segment.frg, segment.wnd, segment.ts, segment.sn, segment.una, segment.data)
                if (segment.xmit >= DEADLINK) state = -1
            }
        }
        // flash remaining segments
        if (buffer.position() > 0) emit()
        // update ssthresh
        if (change > 0) {
            val inflight = u32(sndNxt - sndUna)
            ssthresh = maxOf(inflight / 2, THRESH_MIN)
            this.cwnd = ssthresh + resent
            incr = this.cwnd * mss
        }
        if (lost) {
            ssthresh = maxOf(priorCwnd / 2, THRESH_MIN)
            this.cwnd = 1
            incr = mss
        }
        if (this.cwnd < 1) {
            this.cwnd = 1
            incr = mss
        }
    }

    /** Drives the state machine. [now] is a timestamp in milliseconds, taken modulo 2^32. */
    fun update(now: Long) {
        current = u32(now)
        if (!updated) {
            updated = true
            tsFlush = current
        }
        var slap = diff(current, tsFlush)
        if (slap >= 10000 || slap < -10000) {
            tsFlush = current
            slap = 0
        }
        if (slap >= 0) {
            tsFlush = u32(tsFlush + interval)
            if (diff(current, tsFlush) >= 0) tsFlush = u32(current + interval)
            flush()
        }
    }

    fun setMtu(value: Int): Int {
        if (value < 50 || value < OVERHEAD) return -1
        mtu = value.toLong()
        mss = mtu - OVERHEAD
        return 0
    }

    fun noDelay(nodelay: Int, interval: Int, resend: Int, nc: Int) {
        if (nodelay >= 0) {
            this.nodelay = nodelay.toLong()
            rxMinrto = if (nodelay != 0) RTO_NDL else RTO_MIN
        }
        if (interval >= 0) this.interval = interval.toLong().coerceIn(10, 5000)
        if (resend >= 0) fastresend = resend.toLong()
        if (nc >= 0) nocwnd = nc.toLong()
    }

    fun wndSize(sndwnd: Int, rcvwnd: Int) {
        if (sndwnd > 0) sndWnd = sndwnd.toLong()
        // must be at least the largest number of fragments of one message
        if (rcvwnd > 0) rcvWnd = maxOf(rcvwnd.toLong(), WND_RCV)
    }

    private companion object {
        const val MASK = 0xffffffffL
        const val RTO_NDL = 30L
        const val RTO_MIN = 100L
        const val RTO_DEF = 200L
        const val RTO_MAX = 60000L
        const val CMD_PUSH = 81
        const val CMD_ACK = 82
        const val CMD_WASK = 83
        const val CMD_WINS = 84
        const val ASK_SEND = 1
        const val ASK_TELL = 2
        const val WND_SND = 32L
        const val WND_RCV = 128L
        const val MTU_DEF = 1400L
        const val INTERVAL = 100L
        const val OVERHEAD = 24L
        const val DEADLINK = 20L
        const val THRESH_INIT = 2L
        const val THRESH_MIN = 2L
        const val PROBE_INIT = 5000L
        const val PROBE_LIMIT = 120000L
        const val FASTACK_LIMIT = 5L

        fun u32(value: Long): Long = value and MASK

        /** Difference of two 32-bit timestamps or sequence numbers, correct across wrap-around. */
        fun diff(later: Long, earlier: Long): Long = (later - earlier).toInt().toLong()
    }
}
