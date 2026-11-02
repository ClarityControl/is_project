"""Create tiny valid PNG, BMP, and TGA inputs using only Python's stdlib."""

from __future__ import annotations

import struct
import shutil
import sys
import zlib
from pathlib import Path


def png_chunk(kind: bytes, data: bytes) -> bytes:
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))


def write_png(path: Path) -> None:
    header = struct.pack(">2I5B", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00\xff")
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", pixels)
        + png_chunk(b"IEND", b"")
    )


def write_bmp(path: Path) -> None:
    pixel = b"\x00\x00\xff\x00"  # one red BGR pixel plus row padding
    file_size = 14 + 40 + len(pixel)
    file_header = struct.pack("<2sIHHI", b"BM", file_size, 0, 0, 54)
    dib_header = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, 4, 2835, 2835, 0, 0)
    path.write_bytes(file_header + dib_header + pixel)


def write_tga(path: Path) -> None:
    header = struct.pack("<BBBHHBHHHHBB", 0, 0, 2, 0, 0, 0, 0, 0, 1, 1, 24, 0x20)
    path.write_bytes(header + b"\x00\x00\xff")


def write_gif(path: Path, final_disposal: int = 2) -> None:
    header = b"GIF89a" + struct.pack("<HHBBB", 1, 1, 0x80, 0, 0)
    palette = b"\x00\x00\x00\xff\xff\xff"
    pixel_index_0 = b"\x02\x02\x44\x01\x00"
    pixel_index_1 = b"\x02\x02\x4c\x01\x00"
    frames = bytearray()
    for disposal, pixel in ((1, pixel_index_0), (1, pixel_index_1),
                            (final_disposal, pixel_index_0)):
        frames.extend(b"\x21\xf9\x04")
        frames.extend(bytes((disposal << 2, 1, 0, 0)))
        frames.extend(b"\x2c" + struct.pack("<HHHHB", 0, 0, 1, 1, 0))
        frames.extend(b"\x02" + pixel)
    path.write_bytes(header + palette + bytes(frames) + b"\x3b")


def write_zlib_samples(target: Path) -> None:
    payload = (b"stb_image standalone zlib API seed\n" * 8) + bytes(range(256))
    (target / "zlib_header.zlib").write_bytes(zlib.compress(payload))
    compressor = zlib.compressobj(level=6, wbits=-15)
    raw_deflate = compressor.compress(payload) + compressor.flush()
    (target / "zlib_raw.deflate").write_bytes(raw_deflate)


def main() -> None:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("corpus")
    target.mkdir(parents=True, exist_ok=True)
    write_png(target / "tiny.png")
    write_bmp(target / "tiny.bmp")
    write_tga(target / "tiny.tga")
    write_gif(target / "tiny.gif")
    write_zlib_samples(target)

    upstream = Path(__file__).with_name("upstream_seeds")
    image_extensions = {".png", ".bmp", ".tga", ".jpg", ".jpeg", ".gif",
                        ".psd", ".hdr", ".pic", ".ppm", ".pgm", ".pnm"}
    if upstream.is_dir():
        for sample in upstream.rglob("*"):
            if sample.is_file() and sample.suffix.lower() in image_extensions:
                flat_name = sample.relative_to(upstream).as_posix().replace("/", "__")
                shutil.copyfile(sample, target / flat_name)


if __name__ == "__main__":
    main()
