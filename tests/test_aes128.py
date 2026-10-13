import os
import unittest

from nsz.nut import aes128

try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
except ImportError:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util import Counter


def referenceCtr(key, prefix, offset, data):
    # The pycryptodome construction upstream nsz uses
    counter = Counter.new(64, prefix=bytes(prefix), initial_value=offset >> 4)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    if offset & 0xF:
        cipher.encrypt(b"\x00" * (offset & 0xF))
    return cipher.encrypt(data)


class AESCTRTest(unittest.TestCase):
    OFFSETS = (0, 5, 0x10, 0x4000, 0x4007, 123456789)

    def setUp(self):
        self.key = os.urandom(16)
        self.nonce = bytearray(os.urandom(16))
        self.data = os.urandom(300000)

    def assertMatchesReference(self):
        for offset in self.OFFSETS:
            ctr = aes128.AESCTR(self.key, self.nonce, offset)
            # Two calls: the keystream must continue across encrypt() calls
            got = ctr.encrypt(self.data[:1000]) + ctr.encrypt(memoryview(self.data)[1000:])
            expected = referenceCtr(self.key, self.nonce[:8], offset, self.data)
            self.assertEqual(got, expected, "offset %x" % offset)

            ctr.bktrSeek(offset, 0x1234)
            prefix = self.nonce[:4] + (0x1234).to_bytes(4, "big")
            expected = referenceCtr(self.key, prefix, offset, self.data[:4096])
            self.assertEqual(ctr.encrypt(self.data[:4096]), expected, "bktr offset %x" % offset)

    def test_default_backend_matches_pycryptodome(self):
        self.assertMatchesReference()

    def test_pycryptodome_fallback(self):
        saved = aes128._OsslCipher
        aes128._OsslCipher = None
        try:
            self.assertMatchesReference()
        finally:
            aes128._OsslCipher = saved


if __name__ == "__main__":
    unittest.main()
