"""Egress enforcement. NOTE: in-process socket guard = defense-in-depth demo, NOT a security boundary.
Production should enforce this outside the agent process (container/sandbox/network policy)."""
import socket, contextlib

@contextlib.contextmanager
def egress_guard(allow):
    orig = socket.socket.connect
    def guarded(self, addr):
        if isinstance(addr, tuple) and f"{addr[0]}:{addr[1]}" not in allow:
            raise PermissionError(f"egress blocked: {addr[0]}:{addr[1]}")
        return orig(self, addr)
    socket.socket.connect = guarded
    try: yield
    finally: socket.socket.connect = orig
