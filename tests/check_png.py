"""Validate encoding.cpp output using Python's independent PNG/zlib primitives."""
import binascii
import pathlib
import struct
import sys
import zlib

for scale in (1, 16):
    prefix = sys.argv[1] + str(scale)
    png = pathlib.Path(prefix + ".png").read_bytes()
    matrix = pathlib.Path(prefix + ".matrix").read_text().splitlines()
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    offset, compressed, kinds = 8, bytearray(), []
    while offset < len(png):
        length = struct.unpack_from(">I", png, offset)[0]
        kind = png[offset + 4:offset + 8]
        data = png[offset + 8:offset + 8 + length]
        crc = struct.unpack_from(">I", png, offset + 8 + length)[0]
        assert crc == binascii.crc32(kind + data)
        kinds.append(kind)
        if kind == b"IHDR":
            width, height, depth, color, compression, filtering, interlace = struct.unpack(">IIBBBBB", data)
            assert (depth, color, compression, filtering, interlace) == (8, 0, 0, 0, 0)
            assert width == height == (len(matrix) + 8) * scale
        if kind == b"IDAT":
            compressed.extend(data)
        offset += length + 12
    assert offset == len(png) and kinds == [b"IHDR", b"IDAT", b"IEND"]
    raw = zlib.decompress(compressed)
    assert len(raw) == height * (width + 1)
    assert scale == 1 or len(raw) > 65535  # Exercise multiple stored DEFLATE blocks.
    for y in range(height):
        assert raw[y * (width + 1)] == 0
        for x in range(width):
            mx, my = x // scale - 4, y // scale - 4
            dark = 0 <= mx < len(matrix) and 0 <= my < len(matrix) and matrix[my][mx] == "1"
            assert raw[y * (width + 1) + x + 1] == (0 if dark else 255)
print("PNG CRCs, zlib stream, dimensions, quiet zone, and every pixel passed")
