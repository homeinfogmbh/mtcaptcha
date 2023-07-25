"""Test TokenInfo."""

from unittest import TestCase

from mtcaptcha import TokenInfo


TOKEN_INFO = (
    "v1(000eda01,eee7c778,MTPublic-hal9000uJ,4a774475f03ba00a2f122110af25461d,"
    "yCq1U1SO8fjrXGhcwRk8KWM9SFcOWWfYSwmgJHcbV_Uupa7bLOtXA5NaOaZQkMy0gLDWp72iV"
    "kizPTgy9HBFLihmXHUcLs2zHGjQXB1NoWObCWBNiKG3HcqIvSEbQNRfE6yig-vO5O1D3BPH7w"
    "doUl_0YpzZZ4Vi1r--5IYVbZLmYa8Et1lKTHb7m9B40Zn1gspdO34wUYiWZX6WGmSBHSuCTe2"
    "-s4FOVTQh1-5qnfGUnWfZYpRN4zLvbnqFq3NpAL_PZvn0PyjNvCbmwv2K16GUCTxkm14nfVHT"
    "P_CovJoXJo7LV-arGFVFYixCnwzf4C5DHFJkfn76Kgy3wS1Eog**)"
)


class TestTokenInfo(TestCase):
    """Test TokenInfo."""

    def setUp(self) -> None:
        self.token_info = TokenInfo.from_string(TOKEN_INFO)

    def test_mtcaptcha_checksum(self):
        self.assertEqual("000eda01", self.token_info.mtcaptcha_checksum)

    def test_customer_checksum(self):
        self.assertEqual("eee7c778", self.token_info.customer_checksum)

    def test_sitekey(self):
        self.assertEqual("MTPublic-hal9000uJ", self.token_info.sitekey)

    def test_random_seed(self):
        self.assertEqual(
            "4a774475f03ba00a2f122110af25461d", self.token_info.random_seed
        )

    def test_encrypted_token_info(self):
        self.assertEqual(
            "yCq1U1SO8fjrXGhcwRk8KWM9SFcOWWfYSwmgJHcbV_Uupa7bLOtXA5NaOaZQkMy0g"
            "LDWp72iVkizPTgy9HBFLihmXHUcLs2zHGjQXB1NoWObCWBNiKG3HcqIvSEbQNRfE6"
            "yig-vO5O1D3BPH7wdoUl_0YpzZZ4Vi1r--5IYVbZLmYa8Et1lKTHb7m9B40Zn1gsp"
            "dO34wUYiWZX6WGmSBHSuCTe2-s4FOVTQh1-5qnfGUnWfZYpRN4zLvbnqFq3NpAL_P"
            "Zvn0PyjNvCbmwv2K16GUCTxkm14nfVHTP_CovJoXJo7LV-arGFVFYixCnwzf4C5DH"
            "FJkfn76Kgy3wS1Eog**",
            self.token_info.encrypted_token_info,
        )
