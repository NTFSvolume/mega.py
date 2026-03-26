import os
from typing import Self

_DOT_ENV: dict[str, str | None] = {}

try:
    from dotenv import dotenv_values
except ImportError:
    pass
else:
    _DOT_ENV.update(dotenv_values())


class EnvVar(str):
    __slots__ = ("name",)

    def __new__(cls, env_name: str) -> Self:
        env_name = f"MEGA_{env_name}"
        value = os.getenv(env_name) or _DOT_ENV.get(env_name) or ""
        obj = super().__new__(cls, value)
        obj.name = env_name
        return obj


EMAIL = EnvVar("EMAIL")
PASSWORD = EnvVar("PWD")
