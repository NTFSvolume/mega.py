import pytest

from mega.crypto import get_chunks


@pytest.mark.parametrize(
    "file_size, exp_result",
    [
        (10, ((0, 10),)),
        (1000, ((0, 1000),)),
        (1000000, ((0, 131072), (131072, 262144), (393216, 393216), (786432, 213568))),
        (
            10000000,
            (
                (0, 131072),
                (131072, 262144),
                (393216, 393216),
                (786432, 524288),
                (1310720, 655360),
                (1966080, 786432),
                (2752512, 917504),
                (3670016, 1048576),
                (4718592, 1048576),
                (5767168, 1048576),
                (6815744, 1048576),
                (7864320, 1048576),
                (8912896, 1048576),
                (9961472, 38528),
            ),
        ),
    ],
)
def test_get_chunks(file_size: int, exp_result: tuple[int, int]) -> None:
    result = tuple(get_chunks(file_size))

    assert result == exp_result
