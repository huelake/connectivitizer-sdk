"""A device that opens sessions itself: how the signals of its one connection to the platform are shared between
the device and its calling half. The signaling connection is a stand-in; nothing here reaches a platform."""

from __future__ import annotations

import asyncio
import base64
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from connectivitizer import Agent, Client
from connectivitizer.errors import ConnectivitizerError, ErrorCodes
from connectivitizer.grants import E2eMethods
from connectivitizer.noise import generate_shared_key, parse_shared_key

from .support import StubSignaling


def candidates(session_id: str, blob: bytes = b"{}") -> Dict[str, Any]:
    return {"t": "path.candidates", "d": {"sid": session_id, "blob": base64.b64encode(blob).decode("ascii")}}


def grant_reply(session_id: str) -> Dict[str, Any]:
    return {"t": "connect.grant", "d": {"sid": session_id, "grant": "not-a-grant", "peer": {"id": "d2", "name": "lamp", "caps": []}}}


async def turns(count: int = 5) -> None:
    """Lets the tasks that are ready run."""
    for _ in range(count):
        await asyncio.sleep(0)


def new_agent(log: Optional[List[str]] = None, shared_key: Any = None) -> Agent:
    return Agent(
        "https://api.example",
        device_key="czd_x",
        name="panel",
        shared_key=shared_key or generate_shared_key(),
        services={},
        log=log.append if log is not None else None,
    )


def connected(agent: Agent) -> StubSignaling:
    """Puts the agent into the state run() reaches after the platform welcomed it."""
    signaling = StubSignaling()
    agent._signaling = signaling  # type: ignore[assignment]
    agent._connected.set()
    return signaling


class _Session:
    """As much of a session as a revocation touches."""

    def __init__(self, session_id: str) -> None:
        self.info = SimpleNamespace(session_id=session_id)
        self.ended: List[str] = []

    async def end(self, reason: str) -> None:
        self.ended.append(reason)


class DeviceOpensSessions(unittest.IsolatedAsyncioTestCase):
    async def test_the_request_goes_over_the_devices_connection_once_it_is_connected(self) -> None:
        agent = new_agent()
        connecting = asyncio.ensure_future(agent.connect("lamp", ["api"]))
        await turns()
        self.assertFalse(connecting.done())  # not connected yet: it waits

        signaling = connected(agent)
        await turns()
        self.assertEqual(signaling.requests, [("connect.request", {"device": "lamp", "services": ["api"], "e2e": [E2eMethods.SHARED_KEY]})])

        signaling.fail_request(ConnectivitizerError(ErrorCodes.FORBIDDEN, "The device key may not connect."))
        with self.assertRaises(ConnectivitizerError) as refused:
            await connecting
        self.assertEqual(refused.exception.code, ErrorCodes.FORBIDDEN)
        self.assertEqual(agent.outgoing_sessions, [])

    async def test_answer_and_candidates_of_an_outgoing_session_reach_the_calling_half(self) -> None:
        agent = new_agent()
        signaling = connected(agent)
        caller = agent._caller
        connecting = asyncio.ensure_future(agent.connect("lamp", ["api"]))
        await turns()

        # While the platform's reply is awaited the session id is unknown: both halves keep what passes by.
        agent._on_signal(signaling, candidates("out-1", b"early"))  # type: ignore[arg-type]
        agent._on_signal(signaling, candidates("in-1"))  # type: ignore[arg-type]
        self.assertEqual(set(caller._candidates), {"out-1", "in-1"})
        self.assertEqual(set(agent._candidates), {"out-1", "in-1"})

        signaling.answer_request(grant_reply("out-1"))
        await turns()
        self.assertTrue(caller._owns("out-1"))
        self.assertFalse(caller._owns("in-1"))
        # The calling half keeps the candidates of its own session and drops those of the session opened to the device.
        self.assertEqual(set(caller._candidates), {"out-1"})
        self.assertEqual(caller._candidates["out-1"].result(), b"early")

        # Candidates of the owned session stay out of the device's own table; those of other sessions stay out of the caller's.
        agent._candidates.clear()
        agent._on_signal(signaling, candidates("out-1"))  # type: ignore[arg-type]
        agent._on_signal(signaling, candidates("in-2"))  # type: ignore[arg-type]
        self.assertEqual(set(agent._candidates), {"in-2"})
        self.assertEqual(set(caller._candidates), {"out-1"})

        # The other device's answer travels on the same connection and ends the wait.
        agent._on_signal(signaling, {"t": "connect.answer", "d": {"sid": "out-1", "accept": False, "error": ErrorCodes.E2E_NO_COMMON_METHOD}})  # type: ignore[arg-type]
        with self.assertRaises(ConnectivitizerError) as refused:
            await connecting
        self.assertEqual(refused.exception.code, ErrorCodes.E2E_NO_COMMON_METHOD)
        self.assertFalse(caller._owns("out-1"))
        self.assertEqual(caller._candidates, {})
        self.assertEqual(caller._answers, {})
        self.assertEqual(set(agent._candidates), {"in-2"})
        self.assertIn(("session.update", {"sid": "out-1", "state": "failed", "error": ErrorCodes.E2E_NO_COMMON_METHOD}), signaling.sent)

    async def test_what_the_early_signals_of_an_outgoing_session_left_with_the_device_is_dropped(self) -> None:
        agent = new_agent()
        signaling = connected(agent)
        connecting = asyncio.ensure_future(agent.connect("lamp", ["api"]))
        await turns()
        agent._on_signal(signaling, candidates("out-1"))  # type: ignore[arg-type]
        agent._on_signal(signaling, {"t": "path.fallback", "d": {"sid": "in-1", "reason": "probe_timeout"}})  # type: ignore[arg-type]
        signaling.answer_request(grant_reply("out-1"))
        await turns()
        agent._on_signal(signaling, {"t": "connect.answer", "d": {"sid": "out-1", "accept": False}})  # type: ignore[arg-type]
        with self.assertRaises(ConnectivitizerError) as refused:
            await connecting
        self.assertEqual(refused.exception.code, ErrorCodes.DEVICE_REJECTED)
        self.assertEqual(agent._candidates, {})
        self.assertEqual(set(agent._fallbacks), {"in-1"})

    async def test_candidates_are_the_devices_alone_while_it_opens_nothing(self) -> None:
        agent = new_agent()
        signaling = connected(agent)
        agent._on_signal(signaling, candidates("in-1", b"offer"))  # type: ignore[arg-type]
        self.assertEqual(agent._caller._candidates, {})
        self.assertEqual(agent._candidates["in-1"].result(), b"offer")

    async def test_a_revocation_ends_incoming_and_outgoing_sessions(self) -> None:
        log: List[str] = []
        agent = new_agent(log)
        signaling = connected(agent)
        incoming, outgoing, other = _Session("in-1"), _Session("out-1"), _Session("out-2")
        agent._sessions["in-1"] = incoming  # type: ignore[assignment]
        agent._caller._sessions["out-1"] = outgoing  # type: ignore[assignment]
        agent._caller._sessions["out-2"] = other  # type: ignore[assignment]

        agent._on_signal(signaling, {"t": "revoke", "d": {"sids": ["out-1"], "reason": ErrorCodes.SESSION_REVOKED}})  # type: ignore[arg-type]
        await turns()
        self.assertEqual((incoming.ended, outgoing.ended, other.ended), ([], [ErrorCodes.SESSION_REVOKED], []))

        agent._on_signal(signaling, {"t": "revoke", "d": {"reason": ErrorCodes.CREDENTIAL_REVOKED}})  # type: ignore[arg-type]
        await turns()
        self.assertEqual(incoming.ended, [ErrorCodes.CREDENTIAL_REVOKED])
        self.assertEqual(outgoing.ended, [ErrorCodes.SESSION_REVOKED, ErrorCodes.CREDENTIAL_REVOKED])
        self.assertEqual(other.ended, [ErrorCodes.CREDENTIAL_REVOKED])
        self.assertEqual(log, [f"session in-1 revoked by the platform ({ErrorCodes.CREDENTIAL_REVOKED})"])

    async def test_the_shared_key_is_chosen_as_an_application_chooses_it(self) -> None:
        keys = [parse_shared_key(generate_shared_key(), "lamp"), parse_shared_key(generate_shared_key(), "default")]
        caller = new_agent(shared_key=keys)._caller
        self.assertEqual(caller._select_shared_key("Lamp").name, "lamp")  # type: ignore[union-attr]
        self.assertEqual(caller._select_shared_key("door").name, "default")  # type: ignore[union-attr]
        only = new_agent(shared_key=[parse_shared_key(generate_shared_key(), "hall")])._caller
        self.assertEqual(only._select_shared_key("door").name, "hall")  # type: ignore[union-attr]
        none = new_agent(shared_key=[parse_shared_key(generate_shared_key(), "a"), parse_shared_key(generate_shared_key(), "b")])
        connected(none)
        with self.assertRaises(ConnectivitizerError) as missing:
            await none.connect("door", ["api"])
        self.assertEqual(missing.exception.code, ErrorCodes.E2E_NO_COMMON_METHOD)

    async def test_a_stopped_device_opens_nothing_and_leaves_closing_the_connection_to_itself(self) -> None:
        agent = new_agent()
        waiting = asyncio.ensure_future(agent.connect("lamp", ["api"]))  # asked before the device is connected
        await turns()
        signaling = StubSignaling()
        agent._signaling = signaling  # type: ignore[assignment]
        await agent._caller.close()
        self.assertEqual(signaling.closes, 0)  # the calling half does not own the connection
        await agent.stop()
        self.assertEqual(signaling.closes, 1)
        for attempt in (waiting, asyncio.ensure_future(agent.connect("lamp", ["api"]))):
            with self.assertRaises(ConnectivitizerError) as stopped:
                await attempt
            self.assertEqual(stopped.exception.code, ErrorCodes.SESSION_CLOSED)
        self.assertEqual(signaling.requests, [])


class ApplicationCandidates(unittest.IsolatedAsyncioTestCase):
    async def test_an_application_keeps_the_candidates_of_every_session_on_its_connection(self) -> None:
        # Its connection carries only its own sessions, and the device may answer before the platform's reply is read.
        client = Client("https://api.example", api_key="czk_x", shared_key=generate_shared_key())
        client._on_signal(candidates("s1", b"blob"))
        self.assertEqual(client._candidates["s1"].result(), b"blob")


if __name__ == "__main__":
    unittest.main()
