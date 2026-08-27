"""Cross-platform local process lock for the mutating pipeline."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from importlib import import_module
from pathlib import Path
from typing import Any, BinaryIO


def _try_lock(handle: BinaryIO) -> bool:
    handle.seek(0)
    if os.name == "nt":
        msvcrt: Any = import_module("msvcrt")

        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return False
        return True
    fcntl: Any = import_module("fcntl")

    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return False
    return True


def _unlock(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":
        msvcrt: Any = import_module("msvcrt")

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    fcntl: Any = import_module("fcntl")

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class LocalPipelineLock:
    def __init__(self, path: Path) -> None:
        self.path = path

    @contextmanager
    def acquire(self) -> Iterator[bool]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.path.open("a+b")
        try:
            if self.path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
            acquired = _try_lock(handle)
            try:
                yield acquired
            finally:
                if acquired:
                    _unlock(handle)
        finally:
            handle.close()
