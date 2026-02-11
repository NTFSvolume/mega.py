import pytest

from mega.errors import _CODE_TO_DESCRIPTIONS, RequestError


@pytest.mark.parametrize(
    ("code", "exp_message"),
    [(code, f"{desc[0]}, {desc[1]}") for code, desc in _CODE_TO_DESCRIPTIONS.items()],
)
def test_request_error(code: int, exp_message: str) -> None:
    exc = RequestError(code)

    assert exc.code == code
    assert exc.message == exp_message
    assert str(exc) == exp_message
