import webview
import os
import struct
import zipfile
import shutil
import json
import io
import sys
import threading

# 常量定义
CHUNK_SIZE = 4 * 1024 * 1024  # 4MB，适合处理 1-2GB 大文件
HIDE_BOX_TYPE = b'hide'
ZIP_LOCAL_SIG = b"PK\x03\x04"   # local file header
ZIP_EOCD_SIG = b"PK\x05\x06"    # End of Central Directory
EOCD_FIXED_SIZE = 22

class StegoApi:
    def __init__(self):
        self._window = None

    def set_window(self, window):
        self._window = window

    # --- 1. 前端 UI 交互辅助方法 ---
    def log(self, msg):
        """推送日志到前端"""
        # 替换单引号，防止 JS 语法错误
        #safe_msg = str(msg).replace("'", "\\'")
        #self._window.evaluate_js(f"addLog('{safe_msg}')")
        safe_msg = json.dumps(msg, ensure_ascii=False)
        self._window.evaluate_js(f"addLog({safe_msg})")

    def progress(self, percent):
        """推送进度条到前端"""
        self._window.evaluate_js(f"updateProgress({percent})")

    def remove_outer_quotes(self, text):
        text = str(text).strip()

        if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
            text = text[1:-1]

        if os.path.isdir(text)==False and os.path.isfile(text)==False:
            self.log(f"{text} #File Path is NOT Compliant")

        return text

    def select_file(self):
        try:
            result = self._window.create_file_dialog(webview.FileDialog.OPEN)
            #print(result,type(result),type(result[0]))
            result=list(result)
            #print(result, type(result), type(result[0]))
            result[0]=self.remove_outer_quotes(result[0])
            return result[0] if result else None
        except:
            return None

    def select_folder(self):
        try:
            result = self._window.create_file_dialog(webview.FileDialog.FOLDER)
            result=list(result)
            result[0] = self.remove_outer_quotes(result[0])
            return result[0] if result else None
        except:
            return None


    # --- 2. 核心文件处理工具 ---
    def get_unique_path(self, target_path):
        """处理文件/目录名冲突，生成类似 xxx(1).mp4 的名字"""
        if not os.path.exists(target_path):
            return target_path
        base, ext = os.path.splitext(target_path)
        counter = 1
        while True:
            new_path = f"{base}({counter}){ext}"
            if not os.path.exists(new_path):
                return new_path
            counter += 1

    def is_zip_encrypted(self, filepath):
        """检测 ZIP 文件是否包含加密内容"""
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        return True
            return False
        except Exception:
            return False

    def get_archive_type(self, filepath):
        """根据文件头（Magic Number）判断压缩包格式"""
        with open(filepath, 'rb') as f:
            magic = f.read(8)
            if magic.startswith(b'PK\x03\x04'): return 'zip'
            if magic.startswith(b'Rar!\x1A\x07'): return 'rar'
            if magic.startswith(b'7z\xBC\xAF\x27\x1C'): return '7z'
        return 'unknown'

    def parse_mp4_boxes(self, filepath):
        """解析 MP4 顶层 Box，检查是否有效以及是否包含 hide box"""
        boxes = []
        file_size = os.path.getsize(filepath)
        try:
            with open(filepath, 'rb') as f:
                offset = 0
                while offset < file_size:
                    f.seek(offset)
                    header = f.read(8)
                    if len(header) < 8: break
                    box_size, box_type = struct.unpack(">I4s", header)
                    
                    payload_offset = offset + 8
                    # 处理 64 位 Box Size
                    if box_size == 1:
                        large_size = struct.unpack(">Q", f.read(8))[0]
                        box_size = large_size
                        payload_offset = offset + 16
                    elif box_size == 0:
                        box_size = file_size - offset
                    
                    payload_size = box_size - (payload_offset - offset)
                    boxes.append({'type': box_type, 'payload_offset': payload_offset, 'payload_size': payload_size})
                    offset += box_size
                    if box_size < 8:
                        break
            return boxes
        except Exception as e:
            return None # 解析失败，非有效 MP4

    def validate_shell_video(self, shell_path):
        """校验外壳视频是否有效且无 hide box"""
        if not os.path.isfile(shell_path):
            self.log(f"<span style='color:red;'>Error: The shell video does not exist - {shell_path}</span>")
            return False
        boxes = self.parse_mp4_boxes(shell_path)
        if boxes is None or not any(b['type'] == b'ftyp' for b in boxes):
            self.log(f"<span style='color:red;'>Error: This file is not a valid MP4 video.</span>")
            return False
        if any(b['type'] == HIDE_BOX_TYPE for b in boxes):
            self.log(f"<span style='color:red;'>Error: This embedded video already contains a hide box and cannot be embedded again.</span>")
            return False
        return True

    def create_temp_zip(self, source, temp_dir, include_parent):
        """将文件或文件夹打包成 ZIP 存入缓存目录"""
        base_name = os.path.basename(source.rstrip('/\\'))
        temp_zip_path = self.get_unique_path(os.path.join(temp_dir, f"temp_{base_name}.zip"))
        
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            if os.path.isfile(source):
                zf.write(source, arcname=base_name)
            elif os.path.isdir(source):
                for root, _, files in os.walk(source):
                    for file in files:
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, source)
                        arcname = os.path.join(base_name, rel_path) if include_parent else rel_path
                        zf.write(file_path, arcname)
        return temp_zip_path

    # --- 3. 批量植入模块 ---
    def process_batch_injection(self, shell_video, target_list, temp_dir, output_dir, include_parent):

        shell_video=self.remove_outer_quotes(shell_video)
        temp_dir=self.remove_outer_quotes(temp_dir)
        output_dir=self.remove_outer_quotes(output_dir)
        #print(shell_video,type(shell_video))
        #print(temp_dir,type(temp_dir))
        #print(output_dir, type(output_dir))

        if os.path.exists(temp_dir)==False: os.makedirs(temp_dir)
        if os.path.exists(output_dir)==False: os.makedirs(output_dir)

        if not self.validate_shell_video(shell_video):
            return

        shell_size = os.path.getsize(shell_video)

        for target in target_list:
            #print('165'+target,type(target))
            target = self.remove_outer_quotes(target)
            if not os.path.exists(target):
                self.log(f"Warning: Path not found. Skipping. - {target}")
                continue

            self.log(f"Start processing the target: {target}")
            payload_path = None
            is_temp_created = False

            # 逻辑1：判断是压缩包、文件还是目录
            if os.path.isfile(target):
                if target.lower().endswith('.zip'):
                    if not self.is_zip_encrypted(target):
                        self.log("A password-less ZIP file has been detected; preparing to embed it...")
                        payload_path = target
                    else:
                        self.log("An encrypted ZIP file was detected; repackage it as a nested ZIP archive and then embed it...")
                        payload_path = self.create_temp_zip(target, temp_dir, include_parent)
                        is_temp_created = True

                elif target.lower().endswith('.bin'):
                    self.log("A BIN file has been detected; preparing to embed it...")
                    payload_path = target
                else:
                    self.log("This is not a ZIP file; creating a compressed archive in the cache directory...")
                    payload_path = self.create_temp_zip(target, temp_dir, include_parent)
                    is_temp_created = True
            else:
                self.log("This is not a ZIP file or is a directory; creating a compressed archive in the cache directory...")
                payload_path = self.create_temp_zip(target, temp_dir, include_parent)
                is_temp_created = True

            # 逻辑2：创建输出 MP4 路径
            base_target_name = os.path.basename(target.rstrip('/\\'))
            out_mp4_path = self.get_unique_path(os.path.join(output_dir, f"{base_target_name}_stego.mp4"))

            payload_size = os.path.getsize(payload_path)
            total_work = shell_size + payload_size
            written = 0

            # 逻辑3：二进制合并 (Shell + Box Header + Payload)
            try:
                with open(out_mp4_path, 'wb') as f_out:
                    # 复制原视频
                    with open(shell_video, 'rb') as f_shell:
                        while chunk := f_shell.read(CHUNK_SIZE):
                            f_out.write(chunk)
                            written += len(chunk)
                            self.progress(int(written / total_work * 100))
                    
                    # 写入 64位 hide box 头 (16字节)
                    box_total_size = payload_size + 16
                    f_out.write(struct.pack(">I4sQ", 1, HIDE_BOX_TYPE, box_total_size))
                    
                    # 写入 Payload
                    with open(payload_path, 'rb') as f_payload:
                        while chunk := f_payload.read(CHUNK_SIZE):
                            f_out.write(chunk)
                            written += len(chunk)
                            self.progress(int(written / total_work * 100))
                            
                self.log(f"<span style='color:lime;'>Success: Embedding complete -> {out_mp4_path}</span>")
            except Exception as e:
                self.log(f"<span style='color:red;'>An error occurred during the merge: {e}</span>")
            finally:
                # 逻辑4：清理临时文件
                if is_temp_created and os.path.exists(payload_path):
                    os.remove(payload_path)

        self.progress(100)
        self.log("All embedding tasks have been completed!")

    # --- 4. 批量提取模块 ---
    def process_batch_extraction(self, target_list, output_dir):

        #os.makedirs(output_dir, exist_ok=True)
        # 使用缓存目录存放提取出来的 raw payload
        output_dir=self.remove_outer_quotes(output_dir)
        if os.path.exists(output_dir)==False: os.makedirs(output_dir)
        temp_dir = os.path.abspath("./.temp")
        os.makedirs(temp_dir, exist_ok=True)

        for mp4_target in target_list:
            mp4_target = self.remove_outer_quotes(mp4_target)
            if not os.path.isfile(mp4_target):
                self.log(f"Warning: File does not exist and will be skipped - {mp4_target}")
                continue


            self.log(f"分析视频: {mp4_target}")

            boxes = self.parse_mp4_boxes(mp4_target)
            if boxes is None:
                self.log(f"<span style='color:red;'>Error: Invalid MP4 file - {mp4_target}</span>")
                continue

            hide_boxes = [b for b in boxes if b['type'] == HIDE_BOX_TYPE]
            if not hide_boxes:
                base_name = os.path.splitext(os.path.basename(mp4_target))[0]
                zip_out = os.path.join(output_dir, f"{base_name}_extracted.zip")
                rst = self.extract_simple_zip_from_bin(mp4_target, zip_out)
                if rst == None:
                    self.log("No hide boxes or hidden data were found.")
                if type(rst) == str:
                    self.log("The steganographic data embedded by the SteganographierGUI software has been extracted.")

                continue

            self.log(f"{len(hide_boxes)} hidden data blocks found; preparing to extract them")

            with open(mp4_target, 'rb') as f_in:
                for idx, hb in enumerate(hide_boxes):
                    # 1. 将 payload 提取到临时文件
                    temp_payload = os.path.join(temp_dir, f"raw_payload_{idx}.tmp")
                    f_in.seek(hb['payload_offset'])
                    bytes_to_read = hb['payload_size']
                    
                    with open(temp_payload, 'wb') as f_tmp:
                        while bytes_to_read > 0:
                            chunk = f_in.read(min(CHUNK_SIZE, bytes_to_read))
                            if not chunk: break
                            f_tmp.write(chunk)
                            bytes_to_read -= len(chunk)

                    # 2. 判断文件类型
                    arc_type = self.get_archive_type(temp_payload)
                    base_name = os.path.splitext(os.path.basename(mp4_target))[0]

                    if arc_type in ['rar', '7z']:
                        # 非 ZIP，直接移动到输出目录
                        out_file = self.get_unique_path(os.path.join(output_dir, f"{base_name}_extracted.{arc_type}"))
                        shutil.move(temp_payload, out_file)
                        self.log(f"<span style='color:lime;'>Success: {arc_type.upper()} file extracted -> {out_file}</span>")

                    elif arc_type == 'zip':
                        if self.is_zip_encrypted(temp_payload):
                            # 加密 ZIP，不解压，直接输出
                            out_file = self.get_unique_path(os.path.join(output_dir, f"{base_name}_extracted.zip"))
                            shutil.move(temp_payload, out_file)
                            self.log(f"<span style='color:lime;'>Success: Encrypted ZIP file extracted -> {out_file}</span>")
                        else:
                            # 无密码 ZIP，解压里面内容
                            out_folder = self.get_unique_path(os.path.join(output_dir, f"{base_name}_contents"))
                            os.makedirs(out_folder)
                            try:
                                with zipfile.ZipFile(temp_payload, 'r') as zf:
                                    zf.extractall(out_folder)
                                self.log(f"<span style='color:lime;'>Success: Unzipped the password-less ZIP file -> {out_folder}</span>")
                            except Exception as e:
                                self.log(f"<span style='color:red;'>Extraction failed: {e}</span>")
                            finally:
                                os.remove(temp_payload)
                    else:
                        # 未知格式，当成 raw 数据抛出
                        out_file = self.get_unique_path(os.path.join(output_dir, f"{base_name}_unknown.bin"))
                        shutil.move(temp_payload, out_file)
                        self.log(f"警告：未知格式数据，已保存为 -> {out_file}")

        self.progress(100)
        self.log("所有提取任务处理完毕！")

    def extract_simple_zip_from_bin(self,bin_path:str, output_path:str):
        #ZIP_LOCAL_SIG = b"PK\x03\x04"
        #ZIP_EOCD_SIG = b"PK\x05\x06"
        #EOCD_FIXED_SIZE = 22

        def find_first_signature(f, signature):
            f.seek(0, os.SEEK_SET)
            sig_len = len(signature)
            overlap = sig_len - 1
            offset = 0
            tail = b""

            while True:
                chunk = f.read(CHUNK_SIZE)
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
                chunk = f.read(CHUNK_SIZE)
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
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        break
                    dst.write(chunk)
                    remaining -= len(chunk)

        with open(bin_path, "rb") as f:
            zip_start = find_first_signature(f, ZIP_LOCAL_SIG)
            if zip_start == -1:
                self.log("no zip header found")
                return None

            eocd_pos = find_last_signature(f, ZIP_EOCD_SIG)
            if eocd_pos == -1:
                self.log("no eocd header found")
                return None

            f.seek(eocd_pos + 20)
            comment_len_bytes = f.read(2)
            if len(comment_len_bytes) != 2:
                self.log("EOCD 不完整，无法读取 comment length")
                raise RuntimeError("EOCD 不完整，无法读取 comment length")

            comment_len = struct.unpack("<H", comment_len_bytes)[0]
            zip_end = eocd_pos + EOCD_FIXED_SIZE + comment_len

            f.seek(0, os.SEEK_END)
            file_size = f.tell()
            if zip_end > file_size:
                raise RuntimeError("计算出的 ZIP 结尾超出文件范围，文件可能损坏")


        parent = os.path.dirname(output_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        copy_range(bin_path, output_path, zip_start, zip_end)
        return output_path


if __name__ == '__main__':
    api = StegoApi()

    window = webview.create_window('PhantomMan MP4 Video Steganography Tool v1.0.1.1', 'gui.html', js_api=api, width=950, height=850)
    api.set_window(window)
    webview.start()