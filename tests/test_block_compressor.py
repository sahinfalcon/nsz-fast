import os
import unittest

from zstandard import ZstdCompressionParameters, ZstdCompressor

from nsz import Pipeline
from nsz.BlockCompressor import makeBlockCompressor


def upstreamCompressBlock(buffer, compressionLevel, useLongDistanceMode, blockSize):
    # The per-block logic of upstream compressBlockTask: a fresh compressor for every block
    if compressionLevel == 0 and len(buffer) == blockSize:
        return buffer
    params = ZstdCompressionParameters.from_level(
        compressionLevel, enable_ldm=useLongDistanceMode
    )
    compressed = ZstdCompressor(compression_params=params).compress(buffer)
    return compressed if len(compressed) < len(buffer) else buffer


class BlockCompressorTest(unittest.TestCase):
    BLOCK_SIZE = 2**16

    def blocks(self):
        b = self.BLOCK_SIZE
        data = (b"switch " * b) [: b * 3] + os.urandom(b * 3) + bytes(range(256)) * (b // 128) + b"tail" * 1000
        return [data[o : o + b] for o in range(0, len(data), b)]

    def assertSameAsUpstream(self, level, ldm):
        blocks = self.blocks()
        compressBlock = makeBlockCompressor(level, ldm, self.BLOCK_SIZE)
        # Compressors are reused across blocks and threads, unlike upstream
        results = list(Pipeline.orderedMap(compressBlock, blocks, 4, 8))
        for block, (inputLength, result) in zip(blocks, results):
            self.assertEqual(inputLength, len(block))
            self.assertEqual(result, upstreamCompressBlock(block, level, ldm, self.BLOCK_SIZE))

    def test_default_level(self):
        self.assertSameAsUpstream(18, False)

    def test_long_distance_mode(self):
        self.assertSameAsUpstream(18, True)

    def test_fast_level(self):
        self.assertSameAsUpstream(3, False)

    def test_level_zero_stores_full_blocks_raw(self):
        # https://github.com/nicoboss/nsz/issues/79
        self.assertSameAsUpstream(0, False)


if __name__ == "__main__":
    unittest.main()
