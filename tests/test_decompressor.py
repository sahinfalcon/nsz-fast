import io
import os
import unittest

from zstandard import ZstdCompressor, ZstdDecompressor

import nsz.Decompressor as Decompressor
from nsz import BlockDecompressorReader, Header
from nsz.nut import aes128

streamPieces = getattr(Decompressor, "__streamPieces")
reencrypt = getattr(Decompressor, "__reencrypt")
readBlocks = getattr(Decompressor, "__readBlocks")

INCOMPRESSIBLE_HEADER_SIZE = 0x4000


class Section:
    def __init__(self, offset, size, cryptoType=3):
        self.offset = offset
        self.size = size
        self.cryptoType = cryptoType
        self.cryptoKey = os.urandom(16)
        self.cryptoCounter = os.urandom(16)


def upstreamReencrypt(sections, stream):
    # The per-section loop from upstream __decompressNcz, without I/O and progress
    out = bytearray()
    firstSection = True
    for s in sections:
        i = s.offset
        crypto = None
        if s.cryptoType in (3, 4):
            crypto = aes128.AESCTR(s.cryptoKey, s.cryptoCounter)
        end = s.offset + s.size
        if firstSection:
            firstSection = False
            uncompressedSize = INCOMPRESSIBLE_HEADER_SIZE - sections[0].offset
            if uncompressedSize > 0:
                i += uncompressedSize
        while i < end:
            if crypto is not None:
                crypto.seek(i)
            chunkSz = 0x10000 if end - i > 0x10000 else end - i
            inputChunk = stream.read(chunkSz)
            if not len(inputChunk):
                break
            if crypto is not None:
                inputChunk = crypto.encrypt(inputChunk)
            out += inputChunk
            i += len(inputChunk)
    return bytes(out)


def pipelineReencrypt(sections, plain, chunkSize):
    pieces = streamPieces(sections, INCOMPRESSIBLE_HEADER_SIZE)
    out = []
    for offset in range(0, len(plain), chunkSize):
        chunk = reencrypt(pieces, offset, plain[offset : offset + chunkSize])
        if not chunk:
            break
        out.append(chunk)
    return b"".join(out)


class ReencryptTest(unittest.TestCase):
    def assertSameAsUpstream(self, sections, plainLength):
        plain = os.urandom(plainLength)
        expected = upstreamReencrypt(sections, io.BytesIO(plain))
        # Odd chunk sizes make chunks straddle section boundaries
        for chunkSize in (0x2345, 0x10000, 0x100000):
            self.assertEqual(pipelineReencrypt(sections, plain, chunkSize), expected, hex(chunkSize))

    def test_fake_section_then_ctr_sections(self):
        sections = [
            Header.FakeSection(0x4000, 0x1000),
            Section(0x5000, 0x30000),
            Section(0x35000, 0x12345),
            Section(0x47345, 0x8000, cryptoType=1),
        ]
        self.assertSameAsUpstream(sections, 0x1000 + 0x30000 + 0x12345 + 0x8000)

    def test_first_section_overlaps_incompressible_header(self):
        sections = [Section(0xC00, 0x50000), Section(0x50C00, 0x7777, cryptoType=4)]
        self.assertSameAsUpstream(sections, 0x50000 - (0x4000 - 0xC00) + 0x7777)

    def test_stream_longer_than_sections_is_cut(self):
        sections = [Section(0x4000, 0x20000)]
        self.assertSameAsUpstream(sections, 0x20000 + 0x5000)

    def test_truncated_stream(self):
        sections = [Section(0x4000, 0x20000), Section(0x24000, 0x20000)]
        self.assertSameAsUpstream(sections, 0x2ABCD)


class FakeFile(io.BytesIO):
    pass


class FakeBlockHeader:
    def __init__(self, blockSizeExponent, decompressedSize, compressedBlockSizeList):
        self.blockSizeExponent = blockSizeExponent
        self.decompressedSize = decompressedSize
        self.compressedBlockSizeList = compressedBlockSizeList


class ReadBlocksTest(unittest.TestCase):
    def makeBlockStream(self, exponent=16):
        blockSize = 2**exponent
        # Compressible, incompressible and a partial last block
        plain = (b"nsz " * (blockSize // 2)) + os.urandom(blockSize * 2) + b"\x00" * (blockSize // 3)
        blocks = []
        for offset in range(0, len(plain), blockSize):
            raw = plain[offset : offset + blockSize]
            compressed = ZstdCompressor(level=3).compress(raw)
            blocks.append(compressed if len(compressed) < len(raw) else raw)
        prefix = b"\xAA" * 123  # data before the blocks, like the NCZ headers
        f = FakeFile(prefix + b"".join(blocks))
        f.seek(len(prefix))
        header = FakeBlockHeader(exponent, len(plain), [len(b) for b in blocks])
        return f, header, plain

    def test_matches_upstream_block_reader(self):
        f, header, plain = self.makeBlockStream()
        start = f.tell()
        upstream = BlockDecompressorReader.BlockDecompressorReader(f, header)
        expected = b"".join(upstream.read(0x10000) for _ in range(0, len(plain), 0x10000))

        f.seek(start)
        out = []
        streamOffset = 0
        for offset, data, isCompressed in readBlocks(f, header):
            self.assertEqual(offset, streamOffset)
            plainBlock = ZstdDecompressor().decompress(data) if isCompressed else data
            out.append(plainBlock)
            streamOffset += len(plainBlock)
        self.assertEqual(b"".join(out), expected)
        self.assertEqual(expected, plain)

    def test_rejects_corrupt_block_size(self):
        f, header, _ = self.makeBlockStream()
        header.blockSizeExponent = 13
        with self.assertRaises(ValueError):
            list(readBlocks(f, header))


if __name__ == "__main__":
    unittest.main()
