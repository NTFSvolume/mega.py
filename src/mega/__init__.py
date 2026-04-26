import importlib.metadata
from contextvars import ContextVar

_package_name_ = "async-mega-py"
__version__ = importlib.metadata.version(_package_name_)

LOG_FILE_PROGRESS: ContextVar[bool] = ContextVar("LOG_PROGRESS", default=True)
LOG_HTTP_TRAFFIC: ContextVar[bool] = ContextVar("LOG_HTTP_TRAFFIC", default=False)
