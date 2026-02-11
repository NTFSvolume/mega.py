import os
from typing import Self

try:
    from dotenv import dotenv_values
except ImportError:

    def dotenv_values() -> dict[str, str | None]:
        return {}


_DOT_ENV: dict[str, str | None] = dotenv_values()


class EnvVar(str):
    __slots__ = ("name",)

    def __new__(cls, name: str, value: str) -> Self:
        obj = super().__new__(cls, value)
        obj.name = name
        return obj

    @classmethod
    def env(cls, name: str) -> Self:
        name = f"MEGA_{name}"
        value = os.getenv(name) or _DOT_ENV.get(name) or ""
        return cls(name, value)


EMAIL = EnvVar.env("EMAIL")
PASSWORD = EnvVar.env("PWD")
