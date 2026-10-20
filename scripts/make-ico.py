#!/usr/bin/env python3
"""Собирает многоразмерную .ico для Windows 7+ из одного изображения (PNG/ICO любого размера ≥ 256 px).
Кадры 16-128 px — классический BMP (совместимость), 256 px — PNG.
Использование: make-ico.py исходник выход.ico"""
import io
import struct
import sys

from PIL import Image


def bmp_frame(img):
    w, h = img.size
    px = img.load()
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, w * h * 4, 0, 0, 0, 0)
    rows = bytearray()
    for y in range(h - 1, -1, -1):
        for x in range(w):
            r, g, b, a = px[x, y]
            rows += bytes((b, g, r, a))
    mask = bytes((((w + 31) // 32) * 4) * h)
    return hdr + bytes(rows) + mask


def main(src, dst):
    base = Image.open(src).convert("RGBA")
    if min(base.size) < 256:
        sys.exit("исходное изображение меньше 256 px")
    if base.size != (256, 256):
        base = base.resize((256, 256), Image.LANCZOS)
    sizes = [16, 24, 32, 48, 64, 128, 256]
    frames = []
    for s in sizes:
        im = base if s == 256 else base.resize((s, s), Image.LANCZOS)
        if s == 256:
            buf = io.BytesIO()
            im.save(buf, "PNG", optimize=True)
            frames.append((s, buf.getvalue()))
        else:
            frames.append((s, bmp_frame(im)))
    out = bytearray(struct.pack("<HHH", 0, 1, len(frames)))
    off = 6 + 16 * len(frames)
    for s, data in frames:
        out += struct.pack("<BBBBHHII", 0 if s == 256 else s, 0 if s == 256 else s, 0, 0, 1, 32, len(data), off)
        off += len(data)
    for _, data in frames:
        out += data
    open(dst, "wb").write(out)
    print("записано %s: %d байт, кадры: %s" % (dst, len(out), ", ".join(str(s) for s, _ in frames)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
