"""Test TokenInfo."""

from unittest import TestCase

from mtcaptcha import TokenInfo


TOKEN_INFO = 'v1(2f03cc7d,1058dfde,MTPublic-hal9000uJ,' \
             '34715559cd42d3955114303c925c3582,kSdkIYAqOCQ**)'


class TestTokenInfo(TestCase):
    """Test TokenInfo."""

    def setUp(self) -> None:
        self.token_info = TokenInfo.from_string(TOKEN_INFO)

    def test_mtcaptcha_checksum(self):
        self.assertEqual('2f03cc7d', self.token_info.mtcaptcha_checksum)

    def test_customer_checksum(self):
        self.assertEqual('1058dfde', self.token_info.customer_checksum)

    def test_sitekey(self):
        self.assertEqual('MTPublic-hal9000uJ', self.token_info.sitekey)

    def test_random_seed(self):
        self.assertEqual(
            '34715559cd42d3955114303c925c3582',
            self.token_info.random_seed
        )

    def test_encrypted_token_info(self):
        self.assertEqual('kSdkIYAqOCQ**', self.token_info.encrypted_token_info)

    def test_encrypted_token_info_binary(self):
        self.assertEqual(
            b"\x91'd!\x80*8$",
            self.token_info.encrypted_token_info_binary
        )
