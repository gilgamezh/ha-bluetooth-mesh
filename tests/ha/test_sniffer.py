"""The mesh sniffer decrypts what a wall sensor publishes on the ADV bearer."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

pytest.importorskip("homeassistant")

from custom_components.bluetooth_mesh.btmesh import network  # noqa: E402
from custom_components.bluetooth_mesh.btmesh.access import encode_opcode  # noqa: E402
from custom_components.bluetooth_mesh.btmesh.crypto import k4  # noqa: E402
from custom_components.bluetooth_mesh.btmesh.transport import (  # noqa: E402
    build_unsegmented_access,
    encrypt_access,
)
from custom_components.bluetooth_mesh.sniffer import MeshSniffer  # noqa: E402

NETKEY = bytes(range(16))
APPKEY = bytes(range(16, 32))


def _sensor_onoff_pdu(seq: int) -> bytes:
    access = encode_opcode(0x8203) + bytes([1, 7])
    upper = encrypt_access(
        APPKEY, akf=True, seq=seq, src=0x0033, dst=0xC00F, iv_index=0,
        access_pdu=access,
    )
    lower = build_unsegmented_access(upper, akf=True, aid=k4(APPKEY))
    ctx = network.NetworkContext(net_key=NETKEY, iv_index=0)
    return network.encode(
        ctx, ctl=False, ttl=5, seq=seq, src=0x0033, dst=0xC00F, transport_pdu=lower
    )


def _sniffer() -> MeshSniffer:
    net = SimpleNamespace(
        net_key=NETKEY,
        app_key=APPKEY,
        app_keys=(SimpleNamespace(key=APPKEY),),
        nodes=(
            SimpleNamespace(
                name="Mesh Box 2",
                elements=(SimpleNamespace(unicast=0x0033, name="Sensore 1"),),
            ),
        ),
        groups=(SimpleNamespace(address=0xC00F, name="Camera"),),
    )
    return MeshSniffer(None, SimpleNamespace(network=net, iv_index=0))


def test_logs_a_sensor_publication_once(caplog):
    sniffer = _sniffer()
    pdu = _sensor_onoff_pdu(0x123)
    adv = SimpleNamespace(
        address=0xEDCD20F5FCBE, rssi=-66,
        data=bytes([len(pdu) + 1, 0x2A]) + pdu,
    )
    msg = SimpleNamespace(advertisements=[adv, adv])  # network transmit repeats
    with caplog.at_level(logging.INFO, logger="custom_components.bluetooth_mesh.sniffer"):
        sniffer._on_raw_adverts(msg)
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("MESH")]
    assert len(lines) == 1
    assert "0x0033(Mesh Box 2/Sensore 1) -> 0xc00f(group Camera)" in lines[0]
    assert "OnOff Set Unack on=1 tid=7" in lines[0]
    assert "via ED:CD:20:F5:FC:BE" in lines[0]


def test_ignores_other_networks(caplog):
    sniffer = _sniffer()
    adv = SimpleNamespace(address=1, rssi=-90, data=bytes([5, 0x2A, 1, 2, 3, 4]))
    with caplog.at_level(logging.INFO):
        sniffer._on_raw_adverts(SimpleNamespace(advertisements=[adv]))
    assert not [r for r in caplog.records if r.getMessage().startswith("MESH")]
