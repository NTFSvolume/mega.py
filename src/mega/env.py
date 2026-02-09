import os

try:
    from dotenv import dotenv_values
except ImportError:

    def dotenv_values() -> dict[str, str | None]:
        return {}


class EnvVarNames(dict[str, str]):
    def __getattr__(self, value: str) -> str:
        return self[value]


NAMES = EnvVarNames()
_DOT_ENV = dotenv_values()
_ENV_NAMES: set[str] = set()


def env(name: str) -> str | None:
    NAMES[name] = env_name = f"MEGA_NZ_{name}"
    return os.getenv(env_name) or _DOT_ENV.get(env_name)


EMAIL = env("EMAIL")
PASSWORD = env("PASSWORD")
