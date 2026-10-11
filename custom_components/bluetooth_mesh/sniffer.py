"""Passive mesh traffic log: decrypt what the nodes broadcast on the ADV bearer.

The GATT link only carries what a proxy node chooses to forward to us, and a
Häfele box does not forward its own wired sensor's publications. The same
messages also go out over the air as Mesh Message advertisements (AD type
0x2A), which an ESPHome Bluetooth proxy already hands to Home Assistant. Home
Assistant's Bluetooth manager drops them, though: it only dispatches an advert
whose parsed fields (manufacturer/service data, UUIDs, name) changed, and a
mesh advert has none of those, so every one after the first looks identical.

So this listens one level lower, on the ESPHome API connection itself: an extra
message handler for the raw-advertisement responses the proxy is already
streaming. It subscribes to nothing (a second subscription would take the
stream away from Home Assistant), it only reads.

Each network PDU is de-obfuscated and decrypted with the NetKey, access PDUs
with the AppKey, and one line is logged per (src, seq) on the
``custom_components.bluetooth_mesh.sniffer`` logger at INFO.
"""

from __future__ import annotations

import logging
import struct
from collections import OrderedDict
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from datetime import timedelta

from .btmesh import network
from .btmesh.access import parse_access
from .btmesh.crypto import k4
from .btmesh.errors import BtMeshError
from .btmesh.transport import UnsegmentedAccess, decrypt_access, parse_access_lower

_LOGGER = logging.getLogger(__name__)

AD_TYPE_MESH_MESSAGE = 0x2A
REATTACH_INTERVAL = timedelta(seconds=30)
SEEN_CAPACITY = 512

OPCODES: dict[int, str] = {
    0x8201: "OnOff Get",
    0x8202: "OnOff Set",
    0x8203: "OnOff Set Unack",
    0x8204: "OnOff Status",
    0x8205: "Level Get",
    0x8206: "Level Set",
    0x8207: "Level Set Unack",
    0x8208: "Level Status",
    0x8209: "Level Delta Set",
    0x820A: "Level Delta Set Unack",
    0x820B: "Level Move Set",
    0x820C: "Level Move Set Unack",
    0x8241: "Scene Get",
    0x8242: "Scene Recall",
    0x8243: "Scene Recall Unack",
    0x5E: "Scene Status",
    0x824B: "Lightness Get",
    0x824C: "Lightness Set",
    0x824D: "Lightness Set Unack",
    0x824E: "Lightness Status",
    0x5D: "Time Status",
}


def _describe_params(opcode: int, params: bytes) -> str:
    """Readable values for the handful of opcodes this mesh actually uses."""
    try:
        if opcode in (0x8202, 0x8203) and len(params) >= 2:
            return f"on={params[0]} tid={params[1]}"
        if opcode == 0x8204 and params:
            extra = f" target={params[1]}" if len(params) >= 2 else ""
            return f"present={params[0]}{extra}"
        if opcode in (0x8206, 0x8207) and len(params) >= 3:
            level, tid = struct.unpack_from("<hB", params)
            return f"level={level} tid={tid}"
        if opcode in (0x8209, 0x820A) and len(params) >= 5:
            delta, tid = struct.unpack_from("<iB", params)
            return f"delta={delta} tid={tid}"
        if opcode in (0x820B, 0x820C) and len(params) >= 3:
            delta, tid = struct.unpack_from("<hB", params)
            return f"move={delta} tid={tid}"
        if opcode == 0x8208 and len(params) >= 2:
            (level,) = struct.unpack_from("<h", params)
            return f"level={level}"
        if opcode in (0x824C, 0x824D) and len(params) >= 3:
            light, tid = struct.unpack_from("<HB", params)
            return f"lightness={light} tid={tid}"
        if opcode == 0x824E and len(params) >= 2:
            (light,) = struct.unpack_from("<H", params)
            return f"lightness={light}"
    except struct.error:
        pass
    return params.hex()


def _ad_structures(data: bytes):
    """Yield (ad_type, payload) from a raw advertisement."""
    i = 0
    while i < len(data):
        length = data[i]
        if length == 0 or i + 1 + length > len(data):
            return
        yield data[i + 1], data[i + 2 : i + 1 + length]
        i += 1 + length


def _mac(address: int) -> str:
    return ":".join(f"{b:02X}" for b in address.to_bytes(6, "big"))


class MeshSniffer:
    """Read-only tap on every ESPHome proxy's raw advertisement stream."""

    def __init__(self, hass: HomeAssistant, coordinator) -> None:
        self._hass = hass
        self._coordinator = coordinator
        self._app_keys: dict[int, bytes] | None = None  # AID -> AppKey, built lazily
        self._names: dict[int, str] = {}
        self._ctx: network.NetworkContext | None = None
        self._attached: dict[str, tuple[Any, Any]] = {}  # entry_id -> (conn, remove)
        self._seen: OrderedDict[tuple[int, int], None] = OrderedDict()
        self._unsub_timer = None

    @callback
    def async_start(self) -> None:
        self._attach_all()
        self._unsub_timer = async_track_time_interval(
            self._hass, lambda _now: self._attach_all(), REATTACH_INTERVAL
        )
        _LOGGER.info("mesh sniffer started")

    @callback
    def async_stop(self) -> None:
        if self._unsub_timer:
            self._unsub_timer()
            self._unsub_timer = None
        for _conn, remove in self._attached.values():
            try:
                remove()
            except Exception:  # noqa: BLE001 - connection may already be gone
                pass
        self._attached.clear()

    @callback
    def _attach_all(self) -> None:
        try:
            from aioesphomeapi.api_pb2 import BluetoothLERawAdvertisementsResponse
        except ImportError:
            _LOGGER.warning("mesh sniffer: aioesphomeapi not available")
            return
        for entry in self._hass.config_entries.async_entries("esphome"):
            data = getattr(entry, "runtime_data", None)
            client = getattr(data, "client", None)
            conn = getattr(client, "_connection", None)
            held = self._attached.get(entry.entry_id)
            if held is not None and held[0] is conn:
                continue
            if held is not None:
                try:
                    held[1]()
                except Exception:  # noqa: BLE001
                    pass
                del self._attached[entry.entry_id]
            if conn is None:
                continue
            remove = conn.add_message_callback(
                self._on_raw_adverts, (BluetoothLERawAdvertisementsResponse,)
            )
            self._attached[entry.entry_id] = (conn, remove)
            _LOGGER.info("mesh sniffer attached to ESPHome %s", entry.title)

    def _context(self) -> network.NetworkContext:
        if self._app_keys is None:
            net = self._coordinator.network
            self._app_keys = {k4(key.key): key.key for key in net.app_keys} or {
                k4(net.app_key): net.app_key
            }
            self._names = _address_names(net)
        iv = self._coordinator.iv_index
        if self._ctx is None or self._ctx.iv_index != iv:
            self._ctx = network.NetworkContext(
                net_key=self._coordinator.network.net_key, iv_index=iv
            )
        return self._ctx

    def _on_raw_adverts(self, msg) -> None:
        for adv in msg.advertisements:
            for ad_type, payload in _ad_structures(adv.data):
                if ad_type == AD_TYPE_MESH_MESSAGE:
                    try:
                        self._handle(payload, _mac(adv.address), adv.rssi)
                    except Exception:  # noqa: BLE001 - never break the proxy stream
                        _LOGGER.debug("mesh sniffer: failed on a PDU", exc_info=True)

    def _handle(self, raw: bytes, mac: str, rssi: int) -> None:
        try:
            pdu = network.decode(self._context(), raw)
        except BtMeshError:
            return  # another network, or noise
        key = (pdu.src, pdu.seq)
        if key in self._seen:
            return
        self._seen[key] = None
        if len(self._seen) > SEEN_CAPACITY:
            self._seen.popitem(last=False)

        head = (
            f"{self._name(pdu.src)} -> {self._name(pdu.dst)} "
            f"seq={pdu.seq:#x} ttl={pdu.ttl} via {mac} rssi={rssi}"
        )
        if pdu.ctl:
            _LOGGER.info("MESH %s CONTROL %s", head, pdu.transport_pdu.hex())
            return
        try:
            lower = parse_access_lower(pdu.transport_pdu)
        except BtMeshError:
            _LOGGER.info("MESH %s unparseable lower transport", head)
            return
        if not isinstance(lower, UnsegmentedAccess):
            _LOGGER.info("MESH %s segmented access (not reassembled)", head)
            return
        app_key = (self._app_keys or {}).get(lower.aid) if lower.akf else None
        if app_key is None:
            _LOGGER.info("MESH %s device-key message (not decrypted)", head)
            return
        try:
            payload = decrypt_access(
                app_key, akf=True, seq=pdu.seq, src=pdu.src, dst=pdu.dst,
                iv_index=self._context().iv_index, upper_pdu=lower.upper_pdu,
            )
            opcode, params = parse_access(payload)
        except BtMeshError:
            _LOGGER.info("MESH %s access decrypt failed", head)
            return
        name = OPCODES.get(opcode, f"opcode {opcode:#x}")
        _LOGGER.info("MESH %s %s %s", head, name, _describe_params(opcode, params))

    def _name(self, address: int) -> str:
        name = self._names.get(address)
        return f"{address:#06x}({name})" if name else f"{address:#06x}"


def _address_names(net) -> dict[int, str]:
    names: dict[int, str] = {}
    for node in net.nodes:
        for element in node.elements:
            label = element.name or node.name
            names[element.unicast] = f"{node.name}/{label}" if element.name else label
    for group in getattr(net, "groups", ()):
        names[group.address] = f"group {group.name}"
    return names
