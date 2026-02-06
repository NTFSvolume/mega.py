from mega.transfer_it import TransferItClient


def test_parse_url() -> None:
    transfer_id = TransferItClient.parse_url("https://transfer.it/t/M6apuyoXALsz")
    assert transfer_id == "M6apuyoXALsz"
