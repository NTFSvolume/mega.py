import os

from dotenv import dotenv_values

_DOT_ENV = dotenv_values()
_ENV_NAMES: set[str] = set()


def env(name: str) -> str | None:
    env_name = f"MEGA_NZ_{name}"
    _ENV_NAMES.add(env_name)
    return os.getenv(env_name) or _DOT_ENV.get(env_name)


EMAIL = env("EMAIL")
PASSWORD = env("PASSWORD")
