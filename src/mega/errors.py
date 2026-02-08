from __future__ import annotations

from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from mega.data_structures import NodeID


class MegaNzError(Exception): ...


class ValidationError(MegaNzError, ValueError):
    """Error in validation stage"""


class MultipleNodesFoundError(MegaNzError, LookupError):
    def __init__(self, msg: str, nodes: tuple[NodeID, ...]) -> None:
        self.nodes: tuple[NodeID, ...] = nodes
        super().__init__(msg)


_CODE_TO_DESCRIPTIONS: Final = {
    -1: (
        "EINTERNAL",
        "An internal error has occurred",
    ),
    -2: ("EARGS", "You have passed invalid arguments to this command"),
    -3: ("EAGAIN", "Request failed. No data was altered. Please retry"),
    -4: ("ERATELIMIT", "Rate limited. Please wait a few seconds, then try again"),
    -5: ("EFAILED", "The upload failed. Please restart it from scratch"),
    -6: ("ETOOMANY", "Too many concurrent connections or transfers"),
    -7: ("ERANGE", "The upload file packet is out of range or not starting and ending on a chunk boundary"),
    -8: ("EEXPIRED", "The URL has expired"),
    -9: ("ENOENT", "Resource not found"),
    -10: ("ECIRCULAR", "Circular linkage attempted"),
    -11: ("EACCESS", "Access violation (e.g., trying to write to a read-only share)"),
    -12: ("EEXIST", "Trying to create an object that already exists"),
    -13: ("EINCOMPLETE", "Trying to access an incomplete resource"),
    -14: ("EKEY", "Cryptographic error, invalid key"),  # Only used within the client. Never returned by the API
    -15: ("ESID", "Invalid or expired user session, please relogin"),
    -16: (
        "EBLOCKED",
        "File can't be downloaded as it violates our Terms of Service",
    ),  # or Suspended account during login
    -17: ("EOVERQUOTA", "Request exceeds transfer quota"),
    -18: ("ETEMPUNAVAIL", "Resource temporarily not available, please try again later"),
    -19: ("ETOOMANYCONNECTIONS", "Too many connections"),
    -24: ("EGOINGOVERQUOTA", "Not enough quota"),
    -25: ("EROLLEDBACK", "Request rolled back"),
    -26: ("EMFAREQUIRED", "Multi-Factor Authentication Required"),
    -27: ("EMASTERONLY", "Access denied for sub-users"),
    -28: ("EBUSINESSPASTDUE", "Business account expired"),
    -29: ("EPAYWALL", "Over Disk Quota Paywall"),
    -400: ("ETOOERR", "Too many concurrent errors"),
    -401: ("ESHAREROVERQUOTA", "Share owner is over storage quota"),
}


class RequestError(MegaNzError):
    """Error in API request"""

    def __init__(self, msg: str | int) -> None:
        self.code = code = msg if isinstance(msg, int) else None
        if code:
            code_desc, long_desc = _CODE_TO_DESCRIPTIONS[code]
            self.message = f"{code_desc}, {long_desc}"
        else:
            self.message = str(msg)

        super().__init__(msg)

    def __str__(self) -> str:
        return self.message


class RetryRequestError(RequestError):
    def __init__(self) -> None:
        super().__init__(-3)
