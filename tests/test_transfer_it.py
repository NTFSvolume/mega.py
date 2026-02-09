import pytest

from mega.transfer_it import TransferItClient


class TestParseURL:
    @pytest.mark.parametrize(
        "url, expected",
        [
            (
                "https://transfer.it/t/M6apuyoXALsz",
                "M6apuyoXALsz",
            ),
        ],
    )
    def test_parse_url(self, url: str, expected: str) -> None:
        transfer_id = TransferItClient.parse_url(url)
        assert transfer_id == expected

    @pytest.mark.parametrize(
        "url",
        [
            "https://mega.nz/t/M6apuyoXALsz",
            "https://google.com/t/M6apuyoXALsz",
            "https://youtube.com/t/M6apuyoXALsz",
        ],
    )
    def test_url_from_other_sites_should_raise_value_error(self, url: str) -> None:
        with pytest.raises(ValueError) as e:
            TransferItClient.parse_url(url)

        assert "Not a transfer.it URL" in str(e.value)

    @pytest.mark.parametrize(
        "url",
        [
            "https://transfer.it/tff/M6apuyoXALsz",
            "https://transfer.it/t",
        ],
    )
    def test_url_without_transfer_id_should_raise_value_error(self, url: str) -> None:
        with pytest.raises(ValueError) as e:
            TransferItClient.parse_url(url)

        assert "Unknown URL format" in str(e.value)
