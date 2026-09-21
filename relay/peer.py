"""WSS peer client for Chia full nodes (wallet protocol).

One binary WebSocket frame carries one raw serialized ``Message``
(``streamable.enc_message`` / ``dec_message``).  After the socket opens we
send the pinned wallet ``Handshake`` and require the peer to answer with a
``Handshake`` whose ``node_type`` is FullNode (1) and whose ``network_id``
matches the pinned network (e.g. ``"testnet11"``).  Anything else and the
peer is dropped — fail closed.

Protocol-version note: chia-blockchain only gates ``protocol_version`` for
farmer/harvester connections, not wallets (``ws_connection.py``), so we
send the pinned ``"0.0.37"`` and merely log what the peer reports.  We do
not invent compatibility behavior beyond that.

Message flow
------------
* Requests carry an incrementing uint16 id; one request is in flight per
  peer at a time (guarded by a lock), so responses are matched by type.
  Real full nodes answer with ``id=None`` (``make_msg``), which we accept.
* Unsolicited pushes — ``CoinStateUpdate`` (69) and ``NewPeakWallet``
  (50) — update the manager's coin cache / peak height via callbacks.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional

import aiohttp

from streamable import (
    CoinState,
    Handshake,
    Message,
    MsgType,
    NodeType,
    StreamableError,
    dec_coin_state_update,
    dec_handshake,
    dec_message,
    dec_new_peak_wallet,
    dec_respond_to_coin_updates,
    dec_respond_to_ph_updates,
    dec_transaction_ack,
    enc_message,
    enc_register_for_coin_updates,
    enc_register_for_ph_updates,
    enc_send_transaction,
    make_outbound_handshake,
    spend_bundle_txid,
)

log = logging.getLogger("relay.peer")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class PeerError(RuntimeError):
    pass


class HandshakeError(PeerError):
    pass


class NoPeersError(PeerError):
    pass


class RequestTimeout(PeerError):
    pass


# ---------------------------------------------------------------------------
# Single peer connection
# ---------------------------------------------------------------------------

HANDSHAKE_TIMEOUT = 15.0
REQUEST_TIMEOUT = 30.0
BROADCAST_TIMEOUT = 60.0


@dataclass
class PendingRequest:
    expect_type: int
    future: asyncio.Future
    sent_id: int


class ChiaPeer:
    """One WSS connection to a Chia full node, speaking the wallet protocol."""

    def __init__(
        self,
        host: str,
        port: int,
        ssl_context,
        network_id: str,
        session: aiohttp.ClientSession,
        on_coin_states: Optional[Callable[[List[CoinState]], Awaitable[None]]] = None,
        on_peak: Optional[Callable[[int], Awaitable[None]]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self._ssl = ssl_context
        self._network_id = network_id
        self._session = session
        self._on_coin_states = on_coin_states
        self._on_peak = on_peak

        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        self._next_id = 1
        self._pending: Optional[PendingRequest] = None
        self._handshake_done = asyncio.Event()
        self._handshake_result: Optional[Handshake] = None
        self._closed = asyncio.Event()
        self._peer_protocol_version: Optional[str] = None

    # -- properties ------------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._ws is not None and not self._ws.closed and self._handshake_done.is_set()

    @property
    def peer_protocol_version(self) -> Optional[str]:
        return self._peer_protocol_version

    @property
    def label(self) -> str:
        return f"{self.host}:{self.port}"

    # -- lifecycle -------------------------------------------------------
    async def connect(self) -> None:
        """Open the WSS connection and complete the Chia handshake.

        Raises HandshakeError / PeerError / asyncio.TimeoutError on failure.
        """
        url = f"wss://{self.host}:{self.port}/ws"
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        log.info("connecting to peer %s%s", self.label, " via proxy" if proxy else "")
        try:
            self._ws = await self._session.ws_connect(
                url, ssl=self._ssl, proxy=proxy, heartbeat=30.0,
                max_msg_size=32 * 1024 * 1024,
            )
        except Exception as e:  # noqa: BLE001
            raise PeerError(f"ws connect failed for {self.label}: {e}") from e

        self._closed.clear()
        self._handshake_done.clear()
        self._reader_task = asyncio.create_task(self._reader(), name=f"peer-reader-{self.label}")

        # Send our pinned handshake (no message id, like a real wallet).
        hs = make_outbound_handshake(self._network_id)
        from streamable import enc_handshake  # noqa: PLC0415

        await self._send_raw(enc_message(Message(MsgType.HANDSHAKE, None, enc_handshake(hs))))

        try:
            await asyncio.wait_for(self._handshake_done.wait(), HANDSHAKE_TIMEOUT)
        except asyncio.TimeoutError as e:
            await self.close()
            raise HandshakeError(f"{self.label}: no handshake response within {HANDSHAKE_TIMEOUT}s") from e

        hs_resp = self._handshake_result
        assert hs_resp is not None
        if hs_resp.node_type != NodeType.FULL_NODE:
            await self.close()
            raise HandshakeError(f"{self.label}: peer is node_type={hs_resp.node_type}, not a full node")
        if hs_resp.network_id != self._network_id:
            await self.close()
            raise HandshakeError(
                f"{self.label}: network_id={hs_resp.network_id!r} != pinned {self._network_id!r}"
            )
        self._peer_protocol_version = hs_resp.protocol_version
        if hs_resp.protocol_version != hs.protocol_version:
            log.warning(
                "%s: peer protocol_version=%s (we sent %s); continuing — "
                "chia does not gate wallets on protocol version",
                self.label, hs_resp.protocol_version, hs.protocol_version,
            )
        log.info("handshake complete with %s (protocol %s)", self.label, hs_resp.protocol_version)

    async def close(self) -> None:
        if self._ws is not None and not self._ws.closed:
            try:
                await self._ws.close()
            except Exception:  # noqa: BLE001
                pass
        self._ws = None
        self._closed.set()
        if self._pending is not None and not self._pending.future.done():
            self._pending.future.cancel()
            self._pending = None

    async def wait_closed(self) -> None:
        await self._closed.wait()

    # -- wire IO ---------------------------------------------------------
    async def _send_raw(self, payload: bytes) -> None:
        assert self._ws is not None
        await self._ws.send_bytes(payload)

    async def _reader(self) -> None:
        assert self._ws is not None
        try:
            async for ws_msg in self._ws:
                if ws_msg.type == aiohttp.WSMsgType.BINARY:
                    try:
                        message = dec_message(ws_msg.data)
                    except StreamableError as e:
                        log.warning("%s: dropping undecodable frame: %s", self.label, e)
                        continue
                    await self._dispatch(message)
                elif ws_msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED,
                                     aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.ERROR):
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001
            log.warning("%s: reader error: %s", self.label, e)
        finally:
            self._closed.set()
            if self._pending is not None and not self._pending.future.done():
                self._pending.future.set_exception(PeerError(f"{self.label}: connection lost"))
                self._pending = None

    async def _dispatch(self, message: Message) -> None:
        # Inbound handshake (only meaningful pre-handshake).
        if message.msg_type == MsgType.HANDSHAKE and not self._handshake_done.is_set():
            try:
                self._handshake_result = dec_handshake(message.data)
            except StreamableError as e:
                log.warning("%s: bad handshake payload: %s", self.label, e)
                return
            self._handshake_done.set()
            return

        # Response to our in-flight request?
        pending = self._pending
        if pending is not None and message.msg_type == pending.expect_type and (
            message.id is None or message.id == pending.sent_id
        ):
            if not pending.future.done():
                pending.future.set_result(message.data)
            self._pending = None
            return

        # Unsolicited pushes.
        try:
            if message.msg_type == MsgType.COIN_STATE_UPDATE:
                update = dec_coin_state_update(message.data)
                if self._on_peak is not None:
                    await self._on_peak(update["height"])
                if self._on_coin_states is not None:
                    await self._on_coin_states(update["items"])
            elif message.msg_type == MsgType.NEW_PEAK_WALLET:
                peak = dec_new_peak_wallet(message.data)
                if self._on_peak is not None:
                    await self._on_peak(peak["height"])
            elif message.msg_type == MsgType.RESPOND_TO_PH_UPDATES:
                resp = dec_respond_to_ph_updates(message.data)
                if self._on_coin_states is not None:
                    await self._on_coin_states(resp["coin_states"])
            elif message.msg_type == MsgType.RESPOND_TO_COIN_UPDATES:
                resp = dec_respond_to_coin_updates(message.data)
                if self._on_coin_states is not None:
                    await self._on_coin_states(resp["coin_states"])
            else:
                log.debug("%s: ignoring unsolicited msg type=%d", self.label, message.msg_type)
        except StreamableError as e:
            log.warning("%s: bad push payload (type=%d): %s", self.label, message.msg_type, e)

    async def _request(self, msg_type: int, payload: bytes, expect_type: int,
                       timeout: float = REQUEST_TIMEOUT) -> bytes:
        """Send one request, await the typed response. One at a time per peer."""
        async with self._lock:
            if not self.connected:
                raise PeerError(f"{self.label}: not connected")
            msg_id = self._next_id
            self._next_id = (self._next_id + 1) % 65536 or 1
            loop = asyncio.get_running_loop()
            future: asyncio.Future = loop.create_future()
            self._pending = PendingRequest(expect_type, future, msg_id)
            try:
                await self._send_raw(enc_message(Message(msg_type, msg_id, payload)))
                return await asyncio.wait_for(future, timeout)
            except asyncio.TimeoutError as e:
                self._pending = None
                raise RequestTimeout(f"{self.label}: no response to msg {msg_type} in {timeout}s") from e
            finally:
                if self._pending is not None and self._pending.future is future:
                    self._pending = None

    # -- wallet protocol -------------------------------------------------
    async def register_for_ph_updates(self, puzzle_hashes: List[bytes],
                                      min_height: int = 0) -> List[CoinState]:
        data = await self._request(
            MsgType.REGISTER_FOR_PH_UPDATES,
            enc_register_for_ph_updates(puzzle_hashes, min_height),
            MsgType.RESPOND_TO_PH_UPDATES,
        )
        return dec_respond_to_ph_updates(data)["coin_states"]

    async def register_for_coin_updates(self, coin_ids: List[bytes],
                                        min_height: int = 0) -> List[CoinState]:
        data = await self._request(
            MsgType.REGISTER_FOR_COIN_UPDATES,
            enc_register_for_coin_updates(coin_ids, min_height),
            MsgType.RESPOND_TO_COIN_UPDATES,
        )
        return dec_respond_to_coin_updates(data)["coin_states"]

    async def send_transaction(self, spend_bundle: bytes) -> dict:
        """Broadcast a signed bundle; return the TransactionAck dict."""
        data = await self._request(
            MsgType.SEND_TRANSACTION,
            enc_send_transaction(spend_bundle),
            MsgType.TRANSACTION_ACK,
            timeout=BROADCAST_TIMEOUT,
        )
        ack = dec_transaction_ack(data)
        expected = spend_bundle_txid(spend_bundle)
        if ack["txid"] != expected:
            # The ack's txid is canonical; a mismatch means something is off.
            log.warning("%s: ack txid %s != local sha256 %s",
                        self.label, ack["txid"].hex(), expected.hex())
        return ack


# ---------------------------------------------------------------------------
# Peer manager: pool of peers + coin cache + peak tracking
# ---------------------------------------------------------------------------

@dataclass
class ManagerConfig:
    network_id: str = "testnet11"
    peer_port: int = 58444
    introducer_host: str = "dns-introducer-testnet11.chia.net"
    peers_override: Optional[List[str]] = None  # ["host:port", ...]
    max_peers: int = 3
    target_peers: int = 2


class PeerManager:
    """Keeps N peer connections alive, with a shared coin-state cache."""

    def __init__(self, config: ManagerConfig, ssl_context, session: aiohttp.ClientSession) -> None:
        self.config = config
        self._ssl = ssl_context
        self._session = session
        self._peers: List[ChiaPeer] = []
        self._peers_lock = asyncio.Lock()
        self._maintainers: List[asyncio.Task] = []
        self._stopping = False

        self._coins: Dict[bytes, CoinState] = {}   # coin_id -> CoinState
        self._cache_lock = asyncio.Lock()
        self._watched: set[bytes] = set()          # puzzle hashes with live subs
        self._peak_height: Optional[int] = None
        self._rr_index = 0

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        addrs = await self._resolve_peer_addrs()
        if not addrs:
            log.warning("no peer addresses resolved; will retry in the background")
        for host, port in addrs[: self.config.max_peers]:
            self._maintainers.append(
                asyncio.create_task(self._maintain(host, port), name=f"maintain-{host}:{port}")
            )
        # Background re-resolve: keep trying to fill up to target_peers.
        self._maintainers.append(asyncio.create_task(self._refill_loop(), name="peer-refill"))

    async def stop(self) -> None:
        self._stopping = True
        for t in self._maintainers:
            t.cancel()
        async with self._peers_lock:
            peers = list(self._peers)
        for p in peers:
            await p.close()

    async def _resolve_peer_addrs(self) -> List[tuple]:
        if self.config.peers_override:
            out = []
            for item in self.config.peers_override:
                host, _, port = item.partition(":")
                out.append((host.strip(), int(port) if port else self.config.peer_port))
            return out
        try:
            infos = await asyncio.getaddrinfo(
                self.config.introducer_host, self.config.peer_port,
                type=socket.SOCK_STREAM,
            )
        except Exception as e:  # noqa: BLE001
            log.warning("introducer DNS lookup failed: %s", e)
            return []
        seen: set[str] = set()
        out: List[tuple] = []
        for _family, _type, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                out.append((ip, self.config.peer_port))
            if len(out) >= self.config.max_peers * 2:
                break
        log.info("introducer gave %d candidate peers", len(out))
        return out

    async def _refill_loop(self) -> None:
        while not self._stopping:
            try:
                await asyncio.sleep(120)
                async with self._peers_lock:
                    n = len(self._peers)
                if n < self.config.target_peers:
                    addrs = await self._resolve_peer_addrs()
                    async with self._peers_lock:
                        have = {p.label for p in self._peers}
                    for host, port in addrs:
                        if f"{host}:{port}" in have:
                            continue
                        async with self._peers_lock:
                            if len(self._peers) + sum(1 for t in self._maintainers if not t.done()) >= self.config.max_peers + 1:
                                break
                        self._maintainers.append(
                            asyncio.create_task(self._maintain(host, port), name=f"maintain-{host}:{port}")
                        )
                        break
            except asyncio.CancelledError:
                break
            except Exception as e:  # noqa: BLE001
                log.warning("refill loop error: %s", e)

    async def _maintain(self, host: str, port: int) -> None:
        backoff = 5.0
        while not self._stopping:
            peer = ChiaPeer(
                host, port, self._ssl, self.config.network_id, self._session,
                on_coin_states=self._ingest_coin_states,
                on_peak=self._ingest_peak,
            )
            try:
                await peer.connect()
            except Exception as e:  # noqa: BLE001
                log.warning("peer %s:%d connect failed: %s", host, port, e)
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120.0)
                continue
            async with self._peers_lock:
                self._peers.append(peer)
            log.info("peer %s:%d up (%d/%d)", host, port, len(self._peers), self.config.target_peers)
            backoff = 5.0
            # Re-subscribe watched puzzle hashes so pushes resume after reconnect.
            try:
                async with self._cache_lock:
                    watched = sorted(self._watched)
                if watched:
                    states = await peer.register_for_ph_updates(watched, 0)
                    await self._ingest_coin_states(states)
            except Exception as e:  # noqa: BLE001
                log.warning("peer %s:%d resubscribe failed: %s", host, port, e)
            await peer.wait_closed()
            async with self._peers_lock:
                if peer in self._peers:
                    self._peers.remove(peer)
            log.warning("peer %s:%d disconnected", host, port)
            if not self._stopping:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 120.0)

    # -- cache ingestion ---------------------------------------------------
    async def _ingest_coin_states(self, states: List[CoinState]) -> None:
        async with self._cache_lock:
            for cs in states:
                self._coins[cs.coin.coin_id()] = cs
                for h in (cs.spent_height, cs.created_height):
                    if h is not None and (self._peak_height is None or h > self._peak_height):
                        self._peak_height = h

    async def _ingest_peak(self, height: int) -> None:
        async with self._cache_lock:
            if self._peak_height is None or height > self._peak_height:
                self._peak_height = height

    # -- public API ----------------------------------------------------------
    def _pick_peer(self) -> ChiaPeer:
        peers = [p for p in self._peers if p.connected]
        if not peers:
            raise NoPeersError("no connected peers")
        peer = peers[self._rr_index % len(peers)]
        self._rr_index += 1
        return peer

    async def get_coins(self, puzzle_hashes: List[bytes]) -> List[CoinState]:
        """Subscribe + fetch current CoinStates for puzzle hashes."""
        peer = self._pick_peer()
        states = await peer.register_for_ph_updates(puzzle_hashes, 0)
        await self._ingest_coin_states(states)
        async with self._cache_lock:
            self._watched.update(puzzle_hashes)
            wanted = set(puzzle_hashes)
            return [cs for cs in self._coins.values() if cs.coin.puzzle_hash in wanted]

    async def get_coin(self, coin_id: bytes) -> Optional[CoinState]:
        async with self._cache_lock:
            hit = self._coins.get(coin_id)
        if hit is not None:
            return hit
        peer = self._pick_peer()
        states = await peer.register_for_coin_updates([coin_id], 0)
        await self._ingest_coin_states(states)
        async with self._cache_lock:
            return self._coins.get(coin_id)

    async def broadcast(self, spend_bundle: bytes) -> dict:
        peer = self._pick_peer()
        return await peer.send_transaction(spend_bundle)

    # -- introspection -------------------------------------------------------
    def peer_labels(self) -> List[dict]:
        return [
            {"host": p.host, "port": p.port, "connected": p.connected,
             "protocol_version": p.peer_protocol_version}
            for p in self._peers
        ]

    def connected_count(self) -> int:
        return sum(1 for p in self._peers if p.connected)

    async def snapshot(self) -> dict:
        async with self._cache_lock:
            return {
                "peak_height": self._peak_height,
                "watched_puzzle_hashes": len(self._watched),
                "cached_coins": len(self._coins),
            }
