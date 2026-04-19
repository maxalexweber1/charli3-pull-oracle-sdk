"""Thread-local registry of chained UTxOs for tx-chaining.

When `build_odv_tx` gets a `reward_account_utxo_override`, that UTxO is not
yet in the on-chain ledger — the ogmios-backed `evaluateTransaction` call
doesn't know how to resolve it and fails with code 3010 ("Some scripts
terminate"). The node-fork's ogmios monkey-patch reads from this registry
during evaluate and forwards the entries as Ogmios `additionalUtxo`, so
the script context can resolve the virtual input.

Thread-local because multiple coordinators may run concurrent builds in
the same process (we don't today, but pycardano uses threading for some
blockfrost calls and this keeps the side-effect scoped).
"""
from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pycardano import UTxO

_PENDING: dict[int, list] = {}


def register(utxos: "list[UTxO]") -> None:
    """Store UTxOs as 'virtually available' for the current thread's next evaluate call."""
    _PENDING[threading.get_ident()] = list(utxos)


def clear() -> None:
    """Drop the current thread's pending UTxO list."""
    _PENDING.pop(threading.get_ident(), None)


def get_current() -> "list[UTxO]":
    """Return the current thread's pending UTxOs (possibly empty)."""
    return _PENDING.get(threading.get_ident(), [])
