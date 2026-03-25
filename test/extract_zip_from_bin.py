import os
import io
import struct
import zipfile

ZIP_LOCAL_SIG = b"PK\x03\x04"
ZIP_EOCD_SIG = b"PK\x05\x06"
EOCD_FIXED_SIZE = 22
CHUNK_SIZE = 1024 * 1024  # 1MB
chunk_size = CHUNK_SIZE


def extract_simple_zip_from_bin(bin_path, output_path="output.zip"):
    ZIP_LOCAL_SIG = b"PK\x03\x04"
    ZIP_EOCD_SIG = b"PK\x05\x06"
    EOCD_FIXED_SIZE = 22
    #chunk_size = 1024 * 1024

    def find_first_signature(f, signature):
        f.seek(0, os.SEEK_SET)
        sig_len = len(signature)
        overlap = sig_len - 1
        offset = 0
        tail = b""

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                return -1

            data = tail + chunk
            pos = data.find(signature)
            if pos != -1:
                return offset - len(tail) + pos

            tail = data[-overlap:] if len(data) >= overlap else data
            offset += len(chunk)

    def find_last_signature(f, signature):
        f.seek(0, os.SEEK_SET)
        sig_len = len(signature)
        overlap = sig_len - 1
        offset = 0
        tail = b""
        last_pos = -1

        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                return last_pos

            data = tail + chunk
            search_from = 0

            while True:
                pos = data.find(signature, search_from)
                if pos == -1:
                    break
                last_pos = offset - len(tail) + pos
                search_from = pos + 1

            tail = data[-overlap:] if len(data) >= overlap else data
            offset += len(chunk)

    def copy_range(src_path, dst_path, start, end):
        remaining = end - start
        with open(src_path, "rb") as src, open(dst_path, "wb") as dst:
            src.seek(start)
            while remaining > 0:
                chunk = src.read(min(chunk_size, remaining))
                if not chunk:
                    break
                dst.write(chunk)
                remaining -= len(chunk)

    with open(bin_path, "rb") as f:
        zip_start = find_first_signature(f, ZIP_LOCAL_SIG)
        if zip_start == -1:
            raise RuntimeError("没找到 ZIP 头 PK\\x03\\x04")

        eocd_pos = find_last_signature(f, ZIP_EOCD_SIG)
        if eocd_pos == -1:
            raise RuntimeError("没找到 ZIP 尾 PK\\x05\\x06")

        f.seek(eocd_pos + 20)
        comment_len_bytes = f.read(2)
        if len(comment_len_bytes) != 2:
            raise RuntimeError("EOCD 不完整，无法读取 comment length")

        comment_len = struct.unpack("<H", comment_len_bytes)[0]
        zip_end = eocd_pos + EOCD_FIXED_SIZE + comment_len

        f.seek(0, os.SEEK_END)
        file_size = f.tell()
        if zip_end > file_size:
            raise RuntimeError("计算出的 ZIP 结尾超出文件范围，文件可能损坏")

    copy_range(bin_path, output_path, zip_start, zip_end)
    return output_path