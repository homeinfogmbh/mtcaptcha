"""Test decryption."""

from unittest import TestCase

from mtcaptcha import decode


class TestDecryption(TestCase):
    """Test token decryption."""

    def setUp(self) -> None:
        self.private_key = (
            'MTPrivat-hal9000uJ-'
            'WsPXwe3BatWpGZaEbja2mcO5r7h1h1PkFW2fRoyGRrp4ZH6yfq'
        )
        self.tokens = {
            'v1(000eda01,eee7c778,MTPublic-hal9000uJ,4a774475f03ba00a2f122110a'
            'f25461d,yCq1U1SO8fjrXGhcwRk8KWM9SFcOWWfYSwmgJHcbV_Uupa7bLOtXA5NaO'
            'aZQkMy0gLDWp72iVkizPTgy9HBFLihmXHUcLs2zHGjQXB1NoWObCWBNiKG3HcqIvS'
            'EbQNRfE6yig-vO5O1D3BPH7wdoUl_0YpzZZ4Vi1r--5IYVbZLmYa8Et1lKTHb7m9B'
            '40Zn1gspdO34wUYiWZX6WGmSBHSuCTe2-s4FOVTQh1-5qnfGUnWfZYpRN4zLvbnqF'
            'q3NpAL_PZvn0PyjNvCbmwv2K16GUCTxkm14nfVHTP_CovJoXJo7LV-arGFVFYixCn'
            'wzf4C5DHFJkfn76Kgy3wS1Eog**)': {
                "v": "1.0",
                "code": 201,
                "codeDesc": "valid:captcha-solved",
                "tokID": "4a774475f03ba00a2f122110af25461d",
                "timestampSec": 981173106,
                "timestampISO": "2001-02-03T04:05:06Z",
                "hostname": "some.example.com",
                "isDevHost": False,
                "action": "",
                "ip": "10.10.10.10"
            },
            'v1(980daee9,c265c978,MTPublic-hal9000uJ,495dbab6165529c22c38dfd34'
            '94bcfd5,n25YpNxDyzRURm_msNoW9bACoDg4HmqdXirSjqOfRSCuzwFKNI5z1L-Kh'
            'HPe0hRz7tTIzjlFpHlkkdUYSlVZdxAAZq4_rkoCGUZ8FmngAr2-6t6EHXgD43l7Aq'
            'yCReeReAkGeckV2eNfDzqToAC5epo0LBxJ7X0y-PcNIlseN4BPAbhFm5hV_9YhXGu'
            'XdWjqDxQSbqzwBXh2CjQ2893cRHAbFEyQzZShsiiubXdQYoY-jszt5DySVjnEQRFl'
            'zRnWT6H9gk6EioSX0U5BvSu1cH86Rfg1MwUSXpjYapt_eZWctp9VSWkDdPE1hw8hB'
            '6LVYHIjjrSvBqit8lrCpNRoNQ**)': {
                "v": "1.0",
                "code": 211,
                "codeDesc": "valid:ip-whitelisted",
                "tokID": "495dbab6165529c22c38dfd3494bcfd5",
                "timestampSec": 981173106,
                "timestampISO": "2001-02-03T04:05:06Z",
                "hostname": "more.example.com",
                "isDevHost": True,
                "action": "login",
                "ip": "10.10.10.10"
            }
        }

    def test_token_decryption(self):
        for code, token in self.tokens.items():
            self.assertEqual(decode(code, private_key=self.private_key), token)
