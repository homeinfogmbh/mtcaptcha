"""MTCaptcha decryption and validation."""

from __future__ import annotations
from base64 import urlsafe_b64decode
from datetime import datetime, timedelta
from hashlib import md5
from json import JSONDecodeError, load, loads
from pathlib import Path
from re import fullmatch
from typing import Any, NamedTuple, Optional, Union

from Crypto.Cipher import AES


__all__ = ['VerificationError', 'TokenInfo', 'decode', 'decrypt', 'verify']


PATH = '/etc/mtcaptcha.json'
REGEX = r'v1\(([a-z0-9]+),([a-z0-9]+),([A-Za-z0-9\-]+),([a-z0-9]+),(.+)\)'
SINGLE_USE_DECRYPTION_KEYS = set()


class VerificationError(Exception):
    """Indicate that the verification failed."""

    def __init__(self, message: str, json: Optional[dict[str, Any]] = None):
        super().__init__(message, json)
        self.message = message
        self.json = json


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
        return urlsafe_b64decode(self.encrypted_token_info.replace('*', '='))

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
        key = md5(private_key.encode() + self.random_seed.encode()).digest()

        if key in SINGLE_USE_DECRYPTION_KEYS:
            raise VerificationError('Key already used.')

        SINGLE_USE_DECRYPTION_KEYS.add(key)
        return key


def verify(
        token_info: Union[TokenInfo, str],
        *,
        private_key: Optional[str] = None,
        max_lifetime: timedelta = timedelta(seconds=60),
        now: Optional[datetime] = None
) -> bool:
    """Verify a token."""

    try:
        json = decode(token_info, private_key=private_key)
    except (UnicodeEncodeError, JSONDecodeError) as error:
        raise VerificationError('Decryption failed.') from error

    if not json.get('codeDesc', '').startswith('valid:'):
        raise VerificationError('codeDesc not valid.', json=json)

    if not (timestamp := json.get('timestampSec')):
        raise VerificationError('timestampSec not set.', json=json)

    if now is None:
        now = datetime.now()

    if (timestamp := datetime.fromtimestamp(timestamp)) > now:
        raise VerificationError('Token not yet valid.', json=json)

    if timestamp + max_lifetime > now:
        return True

    raise VerificationError('Token no longer valid.', json=json)


def decode(
        token_info: Union[TokenInfo, str],
        *,
        private_key: Optional[str] = None,
) -> dict[str, Any]:
    """Decode a token."""

    if isinstance(token_info, str):
        token_info = TokenInfo.from_string(token_info)

    if private_key is None:
        private_key = private_key_by_sitekey(token_info.sitekey)

    return loads(unpad_pkcs5(decrypt(token_info, private_key)))


def decrypt(token_info: TokenInfo, private_key: str) -> bytes:
    """Decrypt the token."""

    cipher = AES.new(
        key := token_info.single_use_decryption_key(private_key),
        AES.MODE_CBC,
        key
    )
    return cipher.decrypt(token_info.encrypted_token_info_binary)


def unpad_pkcs5(message: bytes) -> bytes:
    """Unpad the decoded message."""

    return message[:-message[-1]]


def private_key_by_sitekey(sitekey: str) -> str:
    """Return the private key by the given sitekey."""

    return load_keymap()[sitekey]


def load_keymap(path: Path = PATH) -> dict[str, str]:
    """Load a map of sitekey -> private key mappings."""

    try:
        with path.open('rb') as file:
            return load(file)
    except FileNotFoundError:
        return {}
