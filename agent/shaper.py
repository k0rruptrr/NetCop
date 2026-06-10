"""
NetCop traffic shaping engine.

Three layers, because no single trick shapes everything honestly:

  1. TCP DOWNLOAD  -> window clamping. We rewrite the advertised receive
     window on OUTBOUND ACKs so the remote sender never puts more on the
     wire than `rate * RTT`. The byte is never sent, so there is zero WAN
     waste and zero retransmits. This is the only honest way to shape
     *download* from an endpoint with no router access.

  2. UDP / QUIC / uTP DOWNLOAD -> delay queue + token bucket. Window
     clamping doesn't apply (these run their own congestion control), so
     we hold packets and re-inject them paced. Delay is gentler than a
     hard drop: it nudges the sender's RTT estimate up instead of forcing
     loss-driven backoff and the retransmit storm a raw drop causes.

  3. OUTBOUND (upload) throttle stays on NetQosPolicy in agent.py, which
     is the right tool for egress and needs no packet surgery.

The clamp is the star. Everything else is support.
"""

import time
import threading
import struct
import heapq
import socket

import psutil

try:
    import pydivert
except ImportError:  # let the agent decide what to do; don't crash on import
    pydivert = None


# Ethernet MTU. Used as a floor for burst so the bucket can never deadlock
# below one full packet, and as a sanity reference for segment sizing.
MTU = 1500
# Burst floor. 64 KiB matches the max unscaled TCP window and comfortably
# clears any single coalesced (LRO/RSC) super-segment Windows might hand us.
MIN_BURST_BYTES = 65536
# Window scale assumed for connections whose handshake we did not see.
# Windows receive autotuning ('normal') negotiates 2^8. Assuming 8 keeps the
# clamp effective for pre-existing flows: the sender multiplies our window
# field by the scale WE advertised, so guessing too small only clamps
# tighter, never looser. (The old fallback of 0 did the opposite -- the
# rewritten field came out so large the clamp never engaged at all.)
DEFAULT_WIN_SCALE = 8


def mbps_to_bytes_per_sec(mbps: float) -> float:
    """Megabits/sec -> bytes/sec. 1 Mbit = 1_000_000 bits = 125_000 bytes."""
    return mbps * 125_000.0


class TokenBucket:
    """Classic token bucket, but with a burst floor so it can't wedge.

    The original bug: burst = rate * 0.5. At low rates that floor drops
    below one MTU, so consume(1500) can never succeed -> not a throttle,
    a full stall. We clamp burst to at least one full packet (and then
    some) so the worst case is "bursty but flowing", never "frozen".
    """

    def __init__(self, rate_bytes_per_sec: float, burst_bytes: int = None):
        self.rate = rate_bytes_per_sec
        self.burst = self._calc_burst(rate_bytes_per_sec, burst_bytes)
        self.tokens = float(self.burst)
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    @staticmethod
    def _calc_burst(rate: float, override: int = None) -> int:
        if override is not None:
            return max(int(override), MTU)
        # Half a second of rate, but never below the floor.
        return max(int(rate * 0.5), MIN_BURST_BYTES)

    def _refill_locked(self):
        now = time.monotonic()
        elapsed = now - self.last_refill
        if elapsed > 0:
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last_refill = now

    def consume(self, num_bytes: int) -> bool:
        """Try to spend num_bytes. True if allowed, False if not enough."""
        with self.lock:
            self._refill_locked()
            if self.tokens >= num_bytes:
                self.tokens -= num_bytes
                return True
            return False

    def peek(self, num_bytes: int) -> bool:
        """Check affordability WITHOUT spending. Used to coordinate the
        per-process and global buckets so we never charge one bucket for a
        packet the other bucket is about to reject."""
        with self.lock:
            self._refill_locked()
            return self.tokens >= num_bytes

    def commit(self, num_bytes: int):
        """Unconditionally spend. Call only after all relevant buckets
        peek()'d OK, so both are charged together or neither is."""
        with self.lock:
            self._refill_locked()
            self.tokens -= num_bytes

    def time_until(self, num_bytes: int) -> float:
        """Seconds until num_bytes would be affordable. 0 if already is.
        Drives the UDP pacing delay."""
        with self.lock:
            self._refill_locked()
            if self.tokens >= num_bytes:
                return 0.0
            if self.rate <= 0:
                return float("inf")
            return (num_bytes - self.tokens) / self.rate

    def update_rate(self, new_rate_bytes_per_sec: float):
        with self.lock:
            self.rate = new_rate_bytes_per_sec
            self.burst = self._calc_burst(new_rate_bytes_per_sec)
            # Don't let stale tokens exceed the new (possibly smaller) burst.
            self.tokens = min(self.tokens, self.burst)


class ConnectionMapper:
    """Maps a local port -> owning process name, with a short TTL cache.

    Also remembers the TCP window scale negotiated per connection, captured
    from the SYN handshake. Clamping needs the scale: the 16-bit window
    field is multiplied by 2**scale, so to clamp to a true byte target we
    must divide the target by that same factor.
    """

    def __init__(self, refresh_interval: float = 5.0):
        self.cache = {}            # (port, proto) -> exe_name
        self.win_scale = {}        # (local_port, remote_ip, remote_port) -> shift
        self.last_refresh = 0.0
        self.refresh_interval = refresh_interval
        self.lock = threading.Lock()

    def refresh(self):
        new_cache = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid and conn.laddr:
                    port = conn.laddr.port
                    proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                    try:
                        new_cache[(port, proto)] = psutil.Process(conn.pid).name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception:
            pass
        with self.lock:
            self.cache = new_cache
            self.last_refresh = time.monotonic()

    def lookup(self, local_port: int, proto: str) -> str:
        if time.monotonic() - self.last_refresh > self.refresh_interval:
            self.refresh()
        with self.lock:
            return self.cache.get((local_port, proto), "unknown")

    # --- window scale tracking -------------------------------------------

    @staticmethod
    def parse_window_scale(tcp_payload: bytes, data_offset_words: int):
        """Pull the window scale shift from TCP options, if present.
        Returns the shift count (0..14) or None if the option is absent."""
        # Options live between the 20-byte fixed header and data_offset*4.
        opt_start = 20
        opt_end = data_offset_words * 4
        if opt_end <= opt_start or opt_end > len(tcp_payload):
            return None
        i = opt_start
        opts = tcp_payload
        while i < opt_end:
            kind = opts[i]
            if kind == 0:      # End of options
                break
            if kind == 1:      # NOP, no length byte
                i += 1
                continue
            if i + 1 >= opt_end:
                break
            length = opts[i + 1]
            if length < 2:
                break
            if kind == 3 and length == 3 and i + 2 < opt_end:  # Window Scale
                return opts[i + 2]
            i += length
        return None

    def remember_scale(self, key, shift):
        with self.lock:
            self.win_scale[key] = shift
            # Keep the table from growing unbounded on a busy box.
            if len(self.win_scale) > 4096:
                self.win_scale.clear()

    def get_scale(self, key):
        with self.lock:
            return self.win_scale.get(key)


class TrafficShaper:
    """Owns the WinDivert handles and the three shaping layers.

    Two diverts run on separate threads:
      * inbound  : pace UDP/QUIC via delay queue.
      * outbound : learn OUR advertised window scale from our own SYN /
                   SYN-ACK, then clamp the window field on the ACKs we
                   send back. The scale must come from the outbound
                   handshake: the remote sender multiplies our window
                   field by the shift WE advertised, not by its own.
    """

    def __init__(self, priority: int = 1000, default_rtt_ms: float = 50.0):
        self.buckets = {}          # exe_name -> TokenBucket (download budget)
        self.mapper = ConnectionMapper()
        self.priority = priority
        self.default_rtt = default_rtt_ms / 1000.0
        self.global_bucket = None

        self.running = False
        self._threads = []

        # UDP delay queue: a min-heap of (release_time, seq, packet).
        self._delay_heap = []
        self._delay_lock = threading.Lock()
        self._delay_seq = 0
        self._w_inbound = None

    # --- limit management (called from the agent command loop) -----------

    def set_limit(self, exe_name: str, rate_mbps: float):
        exe_name = exe_name.lower()
        rate_bps = mbps_to_bytes_per_sec(rate_mbps)
        if exe_name in self.buckets:
            self.buckets[exe_name].update_rate(rate_bps)
        else:
            self.buckets[exe_name] = TokenBucket(rate_bps)

    def remove_limit(self, exe_name: str):
        self.buckets.pop(exe_name.lower(), None)

    def set_global_limit(self, rate_mbps: float):
        self.global_bucket = TokenBucket(mbps_to_bytes_per_sec(rate_mbps))

    def clear_global_limit(self):
        self.global_bucket = None

    def _target_rate_for(self, exe_name: str):
        """Smallest applicable download rate (bytes/s) for this flow, or
        None if nothing limits it."""
        rates = []
        b = self.buckets.get(exe_name)
        if b:
            rates.append(b.rate)
        if self.global_bucket:
            rates.append(self.global_bucket.rate)
        return min(rates) if rates else None

    # --- TCP window clamping (outbound thread) ---------------------------

    def _clamp_loop(self):
        w = pydivert.WinDivert("outbound and tcp", priority=self.priority + 1)
        w.open()
        try:
            while self.running:
                try:
                    packet = w.recv()
                except Exception:
                    time.sleep(0.05)  # don't hot-spin if the handle hiccups
                    continue

                try:
                    self._maybe_clamp(packet)
                except Exception:
                    pass  # never let one weird packet kill the loop

                try:
                    w.send(packet)
                except Exception:
                    pass
        finally:
            w.close()

    @staticmethod
    def _tcp_header_bytes(packet):
        """TCP header (incl. options) sliced out of the raw packet, parsed
        by hand so we don't depend on pydivert header internals."""
        raw = bytes(packet.raw)
        version = raw[0] >> 4
        if version == 4:
            off = (raw[0] & 0x0F) * 4
        elif version == 6:
            if len(raw) < 40 or raw[6] != 6:  # Next Header must be TCP
                return None
            off = 40  # extension headers on a SYN are rare enough to skip
        else:
            return None
        if off + 20 > len(raw):
            return None
        end = off + ((raw[off + 12] >> 4) & 0xF) * 4
        if end > len(raw):
            return None
        return raw[off:end]

    def _learn_local_scale(self, packet):
        hdr = self._tcp_header_bytes(packet)
        if hdr is None:
            return
        shift = ConnectionMapper.parse_window_scale(hdr, (hdr[12] >> 4) & 0xF)
        key = (packet.src_port, packet.dst_addr, packet.dst_port)
        # Option absent on our SYN -> scaling is off for this connection.
        self.mapper.remember_scale(key, shift if shift is not None else 0)

    def _maybe_clamp(self, packet):
        tcp = packet.tcp
        if not tcp:
            return

        # Our own SYN / SYN-ACK carries the scale WE advertise; that is the
        # multiplier the remote applies to every later window field.
        if tcp.syn:
            self._learn_local_scale(packet)
            return  # never rewrite handshake packets

        exe = self.mapper.lookup(packet.src_port, "tcp")
        rate = self._target_rate_for(exe)
        if rate is None:
            return  # this flow isn't limited; leave its window alone

        scale_key = (packet.src_port, packet.dst_addr, packet.dst_port)
        shift = self.mapper.get_scale(scale_key)
        if shift is None:
            shift = DEFAULT_WIN_SCALE  # handshake predates the shaper

        # Desired receive window in real bytes = rate * RTT (the BDP).
        target_bytes = max(int(rate * self.default_rtt), MTU)

        # The wire field is target_bytes >> shift. Never advertise 0
        # (that's a zero-window stall); floor at one segment's worth.
        scaled = target_bytes >> shift
        if scaled < 1:
            scaled = 1
        if scaled > 0xFFFF:
            return  # our target is already >= what fits; no need to clamp

        if tcp.window_size <= scaled:
            return  # sender already advertising <= our target; don't raise it

        tcp.window_size = scaled
        # pydivert recalculates checksums on send() by default, so we don't
        # touch them here.

    # --- inbound: UDP pacing ----------------------------------------------

    def _inbound_loop(self):
        # TCP download is shaped by the outbound clamp; inbound TCP doesn't
        # need diverting at all, so the filter is UDP-only.
        w = pydivert.WinDivert("inbound and udp", priority=self.priority)
        w.open()
        self._w_inbound = w

        releaser = threading.Thread(target=self._release_loop, daemon=True)
        releaser.start()

        try:
            while self.running:
                try:
                    packet = w.recv()
                except Exception:
                    time.sleep(0.05)  # don't hot-spin if the handle hiccups
                    continue

                handled = False
                try:
                    handled = self._handle_udp(packet)
                except Exception:
                    handled = False

                if not handled:
                    try:
                        w.send(packet)
                    except Exception:
                        pass
        finally:
            w.close()
            self._w_inbound = None

    def _handle_udp(self, packet) -> bool:
        """Returns True if we took ownership of the packet (queued it),
        False if the caller should send it as-is."""
        exe = self.mapper.lookup(packet.dst_port, "udp")
        size = len(packet.raw)

        proc_bucket = self.buckets.get(exe)
        gbl = self.global_bucket

        # No limit on this flow -> not ours.
        if proc_bucket is None and gbl is None:
            return False

        # Coordinated check: only charge if BOTH (where present) can pay.
        # This kills the double-charge drift from the old code.
        if proc_bucket is not None and not proc_bucket.peek(size):
            return self._queue_udp(packet, proc_bucket, gbl, size)
        if gbl is not None and not gbl.peek(size):
            return self._queue_udp(packet, proc_bucket, gbl, size)

        # Both fine: commit together and let it through now.
        if proc_bucket is not None:
            proc_bucket.commit(size)
        if gbl is not None:
            gbl.commit(size)
        return False

    def _queue_udp(self, packet, proc_bucket, gbl, size) -> bool:
        """Hold a UDP packet until the tightest bucket can afford it, then
        the releaser re-injects it. Bounded wait so we never sit on a packet
        forever (better late-drop than infinite memory growth)."""
        waits = []
        if proc_bucket is not None:
            waits.append(proc_bucket.time_until(size))
        if gbl is not None:
            waits.append(gbl.time_until(size))
        wait = max(waits) if waits else 0.0

        # Cap the hold. Past ~250 ms a delayed datagram is usually useless
        # for realtime traffic anyway; let it drop by simply not queueing.
        if wait > 0.25 or wait == float("inf"):
            return True  # owned-and-dropped

        release_at = time.monotonic() + wait
        with self._delay_lock:
            self._delay_seq += 1
            heapq.heappush(
                self._delay_heap,
                (release_at, self._delay_seq, packet, proc_bucket, gbl, size),
            )
            # Safety valve against unbounded growth.
            if len(self._delay_heap) > 5000:
                heapq.heappop(self._delay_heap)
        return True

    def _release_loop(self):
        while self.running:
            now = time.monotonic()
            to_send = []
            with self._delay_lock:
                while self._delay_heap and self._delay_heap[0][0] <= now:
                    to_send.append(heapq.heappop(self._delay_heap))
            for _, _, packet, proc_bucket, gbl, size in to_send:
                # Charge on release so accounting matches what actually flows.
                if proc_bucket is not None:
                    proc_bucket.commit(size)
                if gbl is not None:
                    gbl.commit(size)
                if self._w_inbound is not None:
                    try:
                        self._w_inbound.send(packet)
                    except Exception:
                        pass
            time.sleep(0.005)  # 5 ms granularity is plenty for pacing

    # --- lifecycle -------------------------------------------------------

    def start(self):
        if pydivert is None:
            raise RuntimeError("pydivert not available")
        self.running = True
        self.mapper.refresh()

        t_in = threading.Thread(target=self._inbound_loop, daemon=True)
        t_clamp = threading.Thread(target=self._clamp_loop, daemon=True)
        t_in.start()
        t_clamp.start()
        self._threads = [t_in, t_clamp]

    def stop(self):
        self.running = False
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []
