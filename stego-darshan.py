#!/usr/bin/env python3
import argparse
import struct
import sys
from pathlib import Path
from PIL import Image
import secrets
import getpass
import zlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Config
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERATIONS = 200_000
MAGIC = b"SDAR"
HEADER_FMT = ">4sB I"
TYPE_TEXT = 1
TYPE_FILE = 2


def _info(s): print(f"[+] {s}")
def _err(s): print(f"[-] {s}", file=sys.stderr)

# Crypto helpers
def derive_key(passkey: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return kdf.derive(passkey.encode("utf-8"))

def encrypt_payload(plain: bytes, passkey: str) -> bytes:
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(passkey, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plain, None)
    return salt + nonce + ct

def decrypt_payload(blob: bytes, passkey: str) -> bytes:
    if len(blob) < SALT_SIZE + NONCE_SIZE + 1:
        raise ValueError("Malformed payload.")
    salt = blob[:SALT_SIZE]
    nonce = blob[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ct = blob[SALT_SIZE + NONCE_SIZE:]
    key = derive_key(passkey, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# Bit helpers
def _bytes_to_bits(data: bytes):
    for b in data:
        for i in range(7, -1, -1):
            yield (b >> i) & 1

def _bits_to_bytes(bits):
    b = 0; count = 0
    for bit in bits:
        b = (b << 1) | bit
        count += 1
        if count == 8:
            yield b
            b = 0; count = 0

# LSB image embedding/extraction (RGB channels only)
def embed_bits(img: Image.Image, bits_iter):
    rgba = img.convert("RGBA")
    pixels = bytearray(rgba.tobytes())
    total_channels = (len(pixels) // 4) * 3  # per pixel: R,G,B used (skip alpha)
    idx = 0
    for bit in bits_iter:
        if idx >= total_channels:
            raise ValueError("Image capacity exceeded while embedding.")
        pixel_idx = idx // 3
        channel = idx % 3   # 0->R,1->G,2->B
        byte_pos = pixel_idx * 4 + channel  # skip alpha at +3
        pixels[byte_pos] = (pixels[byte_pos] & 0xFE) | bit
        idx += 1
    new_img = Image.frombytes("RGBA", rgba.size, bytes(pixels))
    return new_img.convert("RGB")

def extract_bits(img: Image.Image, nbits: int):
    rgba = img.convert("RGBA")
    pixels = rgba.tobytes()
    total_channels = (len(pixels) // 4) * 3
    if nbits > total_channels:
        raise ValueError("Requested more bits than image capacity.")
    for idx in range(nbits):
        pixel_idx = idx // 3
        channel = idx % 3
        byte_pos = pixel_idx * 4 + channel
        yield pixels[byte_pos] & 1

def calc_capacity_bits(img: Image.Image) -> int:
    w, h = img.size
    return w * h * 3

# High-level embed/extract functions
def build_payload_from_text(text: str, compress: bool) -> bytes:
    data = text.encode("utf-8")
    if compress:
        data = zlib.compress(data)
    return struct.pack(">H", 0) + data

def build_payload_from_file(file_path: Path, compress: bool) -> bytes:
    body = file_path.read_bytes()
    if compress:
        body = zlib.compress(body)
    fname = file_path.name.encode("utf-8")
    fname_len = len(fname)
    if fname_len > 0xFFFF:
        raise ValueError("Filename too long.")
    return struct.pack(">H", fname_len) + fname + body

''' 
Hy My self Darshan Rao and I Create this tool for Steganography use for Hacking and Security Testing 
so if you like this tool then please give me a star on github where you find this tool and if you reading 
this code then you are a good programmer and interested in Security and Hacking 
so if you want to contribute to this tool then please fork this repository and make a pull request 
and commet your suggestion and feedback for making this tool better and more advanced
Dm me on instagram @indgaming_262. Thank you'''

def embed(args):
    infile = Path(args.infile)
    if not infile.exists():
        _err("Input file not found.")
        return
    img = Image.open(infile)
    out_path = Path(args.outfile)
    passkey = args.passkey or getpass.getpass("Passkey: ")
    if args.file:
        secret_path = Path(args.file)
        if not secret_path.exists():
            _err("Secret file not found.")
            return
        ptype = TYPE_FILE
        payload_body = build_payload_from_file(secret_path, args.compress)
    else:
        ptype = TYPE_TEXT
        payload_body = build_payload_from_text(args.text, args.compress)

    enc = encrypt_payload(payload_body, passkey)

    payload_len = len(enc)
    header = struct.pack(">4sB I", MAGIC, ptype, payload_len)
    full = header + enc
    needed_bits = len(full) * 8
    cap_bits = calc_capacity_bits(img)
    _info(f"Image capacity: {cap_bits} bits ({cap_bits//8} bytes). Payload needs {needed_bits} bits ({needed_bits//8} bytes).")
    if needed_bits > cap_bits:
        _err("Not enough capacity in image. Use a larger image or enable compression / reduce payload size.")
        return
    bits = _bytes_to_bits(full)
    stego_img = embed_bits(img, bits)
    stego_img.save(out_path, format="PNG")
    _info(f"Saved stego image: {out_path}")

def extract(args):
    stego_path = Path(args.stego)
    if not stego_path.exists():
        _err("Stego image not found.")
        return
    img = Image.open(stego_path)
    passkey = args.passkey or getpass.getpass("Passkey: ")

    header_bits = list(extract_bits(img, 9 * 8))
    header_bytes = bytes(_bits_to_bytes(header_bits))
    if len(header_bytes) < 9:
        _err("Failed to read header.")
        return
    magic, ptype, plen = struct.unpack(">4sB I", header_bytes)
    if magic != MAGIC:
        _err("No valid steganographic payload found (magic mismatch).")
        return
    _info(f"Found payload type={ptype}, encrypted length={plen} bytes.")
    total_bits = 9 * 8 + plen * 8
    payload_bits = list(extract_bits(img, total_bits))[9 * 8:]  # skip header bits
    payload_bytes = bytes(_bits_to_bytes(payload_bits))
    try:
        plain = decrypt_payload(payload_bytes, passkey)
    except Exception:
        _err("Decryption failed — wrong passkey or corrupted payload.")
        return

    if len(plain) < 2:
        _err("Malformed payload body.")
        return
    fname_len = struct.unpack(">H", plain[:2])[0]
    if fname_len == 0:
        body = plain[2:]
        try:
            text = zlib.decompress(body).decode("utf-8")
            _info("Payload was compressed — decompressed successfully.")
        except Exception:
            try:
                text = body.decode("utf-8", errors="replace")
            except Exception:
                text = "<binary data (could not decode)>"
        print("\n--- BEGIN SECRET (text) ---")
        print(text)
        print("--- END SECRET ---\n")
    else:
        if len(plain) < 2 + fname_len:
            _err("Malformed file payload.")
            return
        fname = plain[2:2 + fname_len].decode("utf-8", errors="replace")
        fbody = plain[2 + fname_len:]
        try:
            fbody = zlib.decompress(fbody)
            _info("Payload was compressed — decompressed successfully.")
        except Exception:
            pass
        outdir = Path(args.outdir) if args.outdir else Path(".")
        outdir.mkdir(parents=True, exist_ok=True)
        out_path = outdir / fname
        out_path.write_bytes(fbody)
        _info(f"Extracted file written to: {out_path}")

def info_cmd(args):
    img_path = Path(args.img)
    if not img_path.exists():
        _err("File not found.")
        return
    img = Image.open(img_path)
    cap = calc_capacity_bits(img)
    print(f"Image: {img_path}  Size: {img.size}  Capacity: {cap} bits ({cap//8} bytes)")
    try:
        header_bits = list(extract_bits(img, 9 * 8))
        header_bytes = bytes(_bits_to_bytes(header_bits))
        if len(header_bytes) >= 9:
            magic, ptype, plen = struct.unpack(">4sB I", header_bytes)
            if magic == MAGIC:
                _info(f"Found embedded payload: type={ptype}, encrypted_len={plen} bytes")
                return
    except Exception:
        pass
    _info("No recognized embedded payload found.")

# CLI
def build_parser():
    p = argparse.ArgumentParser(prog="stego-darshan", description="stego-darshan - embed/extract encrypted payloads in images")
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("embed", help="Embed text or file into an image")
    e.add_argument("-i", "--in", dest="infile", required=True, help="Cover image (png/jpg)")
    e.add_argument("-o", "--out", dest="outfile", default="stego_output.png", help="Output stego PNG(default: stego_output.png)")
    group = e.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--text", dest="text", help="Secret text to embed")
    group.add_argument("-f", "--file", dest="file", help="Secret file to embed")
    e.add_argument("--compress", action="store_true", help="Compress payload (gzip) before encryption")
    e.add_argument("-p", "--pass", dest="passkey", help="Passkey (will prompt if omitted)")
    e.set_defaults(func=embed)

    x = sub.add_parser("extract", help="Extract secret from stego image")
    x.add_argument("-i", "--in", dest="stego", required=True, help="Stego image (png)")
    x.add_argument("-d", "--outdir", dest="outdir", help="Directory to write extracted file(default: current directory)")
    x.add_argument("-p", "--pass", dest="passkey", help="Passkey (will prompt if omitted)")
    x.set_defaults(func=extract)

    info_p = sub.add_parser("info", help="Show image capacity and detect payload (if any)")
    info_p.add_argument("-i", "--in", dest="img", required=True, help="Image path")
    info_p.set_defaults(func=info_cmd)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        _err("Interrupted by user...")
        sys.exit(130)
    except Exception as e:
        _err(str(e))
        sys.exit(1)

if __name__ == "__main__":
    main()