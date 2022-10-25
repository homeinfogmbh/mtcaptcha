"""MTCaptcha decryption and validation."""

from __future__ import annotations
from base64 import b64decode
from hashlib import md5
from json import load
from pathlib import Path
from re import fullmatch
from typing import NamedTuple, Optional

from Crypto.Cipher import AES


__all__ = ['TokenInfo', 'decrypt']


PATH = '/etc/mtcaptcha.json'
REGEX = r'v1\(([a-z0-9]+),([a-z0-9]+),([A-Za-z0-9\-]+),([a-z0-9]+),(.+)\)'


class TokenInfo(NamedTuple):
    """Information about the token."""

    mtcaptcha_checksum: str
    customer_checksum: str
    sitekey: str
    random_seed: str
    encrypted_token_info: str

    @classmethod
    def from_string(cls, string: str) -> TokenInfo:
        """Create a TokenInfo instance from a string."""
        if match := fullmatch(REGEX, string):
            return cls(*match.groups())

        raise ValueError('Invalid token info:', str)

    @property
    def encrypted_token_info_binary(self) -> bytes:
        """Returns the EncryptedTokenInfoBinary."""
        return b64decode(self.encrypted_token_info.replace('*', '='))

    def calculate_customer_checksum(self, private_key: str) -> str:
        """Calculate the customer checksum."""
        return md5(
            private_key.encode()
            + self.sitekey.encode()
            + self.random_seed.encode()
            + self.encrypted_token_info.encode()
        ).hexdigest()[:8]

    def single_use_decryption_key(self, private_key: str) -> bytes:
        """Calculate the single use decryption key."""
        return md5(private_key.encode() + self.random_seed.encode()).digest()


def decrypt(
        token_info: TokenInfo,
        *,
        private_key: Optional[str] = None,
) -> bytes:
    """Decrypt the token."""

    if private_key is None:
        private_key = private_key_by_sitekey(token_info.sitekey)

    cipher = AES.new(
        key := token_info.single_use_decryption_key(private_key),
        AES.MODE_CBC,
        key
    )
    return cipher.decrypt(token_info.encrypted_token_info_binary)


def private_key_by_sitekey(sitekey: str) -> str:
    """Return the private key by the given sitekey."""

    return load_keymap()[sitekey]


def load_keymap(path: Path = PATH) -> dict[str, str]:
    """Load a map of sitekey -> private key mappings."""

    with path.open('rb') as file:
        return load(file)
