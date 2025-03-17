# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.hazmat.primitives import hashes
from cryptography.utils import Buffer

class HMAC(hashes.HashContext):
    def __init__(
        self,
        key: Buffer,
        algorithm: hashes.HashAlgorithm,
        backend: typing.Any = None,
    ) -> None: ...
    @property
    def algorithm(self) -> hashes.HashAlgorithm: ...
    def update(self, data: Buffer) -> None: ...
    def finalize(self) -> bytes: ...
    def verify(self, signature: bytes) -> None: ...
    def copy(self) -> HMAC: ...
