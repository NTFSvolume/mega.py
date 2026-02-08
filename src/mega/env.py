import os

from dotenv import dotenv_values

dot_env = dotenv_values()


def get_env_var(name: str) -> str | None:
    env_name = f"MEGA_NZ_{name}"
    return os.getenv(env_name) or dot_env.get(env_name)


EMAIL = get_env_var("EMAIL")
PASSWORD = get_env_var("PASSWORD")
