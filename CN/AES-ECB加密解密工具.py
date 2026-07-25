#####################################################################
# Copyright (c) 2024, SanJerry007
# Licensed under the GNU General Public License v3.0.
# See the LICENSE file on https://www.gnu.org/licenses/gpl-3.0.html for details.
# Project repository: https://github.com/SanJerry007/AES-ECB-Minimal-Windows
#####################################################################

import base64
import tkinter as tk
from tkinter import messagebox, ttk

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

# ===== AES-GCM / KDF 参数 =====
_GCM_SALT_LEN = 16   # scrypt 盐长度
_GCM_NONCE_LEN = 12  # GCM 推荐 nonce 长度
_GCM_TAG_LEN = 16    # GCM 认证标签长度
_SCRYPT_N = 2 ** 14  # scrypt 计算成本（越大越抗暴力，也越慢）
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32        # AES-256


class AESCipher:
    def __init__(self, key: str):
        """
        初始化 AES 加密器（ECB 模式使用）。
        :param key: 加密密钥。
        """
        self.key = key.encode('utf-8')

    def _pad(self, plaintext: bytes, mode: str = "ZeroPadding") -> bytes:
        """
        根据选择的模式对明文进行填充。
        :param plaintext: 需要填充的明文。
        :param mode: 填充模式。
        :return: 填充后的明文。
        """
        remainder = len(plaintext) % AES.block_size
        if mode == "ZeroPadding":
            # ZeroPadding：已是整块则不填充（注意：明文末尾的真实 \x00 在解密时会被误删）
            if remainder == 0:
                return plaintext
            padding_length = AES.block_size - remainder
            return plaintext + b'\x00' * padding_length
        # 其余模式：即使明文恰好是整块，也必须补一整块，否则解密无法无歧义地还原
        padding_length = AES.block_size - remainder  # remainder == 0 时为一整块
        if mode == "PKCS7":
            return plaintext + bytes([padding_length] * padding_length)
        elif mode == "AnsiX923":
            return plaintext + b'\x00' * (padding_length - 1) + bytes([padding_length])
        elif mode == "ISO10126":
            # 使用密码学安全随机字节填充（不再使用固定种子）
            return plaintext + get_random_bytes(padding_length - 1) + bytes([padding_length])
        elif mode == "ISO97971":
            return plaintext + b'\x80' + b'\x00' * (padding_length - 1)
        else:
            raise ValueError("不支持的填充模式")

    def _unpad(self, plaintext: bytes, mode: str = "ZeroPadding") -> bytes:
        """
        根据选择的模式去除明文的填充。
        :param plaintext: 填充后的明文。
        :param mode: 填充模式。
        :return: 去除填充后的明文。
        """
        if mode == "ZeroPadding":
            return plaintext.rstrip(b'\x00')
        elif mode == "PKCS7":
            padding_length = plaintext[-1]
            return plaintext[:-padding_length]
        elif mode == "AnsiX923":
            padding_length = plaintext[-1]
            return plaintext[:-padding_length]
        elif mode == "ISO10126":
            padding_length = plaintext[-1]
            return plaintext[:-padding_length]
        elif mode == "ISO97971":
            return plaintext.rstrip(b'\x00').rstrip(b'\x80')
        else:
            raise ValueError("不支持的填充模式")

    def encrypt(self, plaintext: str, mode: str = "ZeroPadding", output_format: str = "base64") -> str:
        """
        使用 AES 在 ECB 模式下加密明文。
        注意：ECB 不安全（相同明文块产生相同密文块、无完整性校验），仅供学习/兼容旧数据使用。
        :param plaintext: 需要加密的明文。
        :param mode: 填充模式。
        :param output_format: 密文的输出格式。
        :return: 编码后的密文。
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_plaintext = self._pad(plaintext.encode('utf-8'), mode)
        ciphertext = cipher.encrypt(padded_plaintext)
        if output_format == "base64":
            return base64.b64encode(ciphertext).decode('utf-8')
        elif output_format == "hex":
            return ciphertext.hex()
        else:
            raise NotImplementedError(f"不支持的输出格式: {output_format}")

    def decrypt(self, ciphertext: str, mode: str = "ZeroPadding", input_format: str = "base64") -> str:
        """
        使用 AES 在 ECB 模式下解密密文。
        :param ciphertext: 需要解密的编码密文。
        :param mode: 填充模式。
        :param input_format: 密文的输入格式。
        :return: 原始明文。
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        if input_format == "base64":
            decoded_ciphertext = base64.b64decode(ciphertext)
        elif input_format == "hex":
            decoded_ciphertext = bytes.fromhex(ciphertext)
        else:
            raise NotImplementedError(f"不支持的输入格式: {input_format}")
        plaintext = cipher.decrypt(decoded_ciphertext)
        return self._unpad(plaintext, mode).decode('utf-8')


def gcm_encrypt(passphrase: str, plaintext: str, output_format: str = "base64") -> str:
    """
    使用 AES-256-GCM 进行认证加密（推荐用于保存密码等敏感信息）。
    - 口令经 scrypt 派生为 256 位密钥（每次加密使用随机盐）。
    - 每次加密使用随机 nonce，相同明文也会得到不同密文。
    - 自带完整性校验：密文被篡改或口令错误时解密会失败。
    输出 = 编码( salt(16) | nonce(12) | tag(16) | ciphertext )。
    :param passphrase: 任意长度的口令。
    :param plaintext: 需要加密的明文。
    :param output_format: 密文的输出格式（base64 / hex）。
    :return: 编码后的密文。
    """
    salt = get_random_bytes(_GCM_SALT_LEN)
    nonce = get_random_bytes(_GCM_NONCE_LEN)
    key = scrypt(passphrase.encode('utf-8'), salt, key_len=_KEY_LEN, N=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
    token = salt + nonce + tag + ciphertext
    if output_format == "base64":
        return base64.b64encode(token).decode('utf-8')
    elif output_format == "hex":
        return token.hex()
    else:
        raise NotImplementedError(f"不支持的输出格式: {output_format}")


def gcm_decrypt(passphrase: str, token_str: str, input_format: str = "base64") -> str:
    """
    解密 gcm_encrypt 生成的密文，并验证完整性。
    口令错误或密文被篡改时会抛出 ValueError。
    :param passphrase: 加密时使用的口令。
    :param token_str: 编码后的密文。
    :param input_format: 密文的输入格式（base64 / hex）。
    :return: 原始明文。
    """
    if input_format == "base64":
        token = base64.b64decode(token_str)
    elif input_format == "hex":
        token = bytes.fromhex(token_str)
    else:
        raise NotImplementedError(f"不支持的输入格式: {input_format}")
    header_len = _GCM_SALT_LEN + _GCM_NONCE_LEN + _GCM_TAG_LEN
    if len(token) < header_len:
        raise ValueError("密文长度不足或格式错误")
    salt = token[:_GCM_SALT_LEN]
    nonce = token[_GCM_SALT_LEN:_GCM_SALT_LEN + _GCM_NONCE_LEN]
    tag = token[_GCM_SALT_LEN + _GCM_NONCE_LEN:header_len]
    ciphertext = token[header_len:]
    key = scrypt(passphrase.encode('utf-8'), salt, key_len=_KEY_LEN, N=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # MAC 校验失败会抛 ValueError
    return plaintext.decode('utf-8')


def main():
    KEY_LENGTHS = {"128bit(16字符)": 16, "192bit(24字符)": 24, "256bit(32字符)": 32}
    GCM_KEY_WIDTH = 40  # GCM 口令长度任意，用固定的较宽输入框

    def clear_results():
        encrypted_text.set("")
        decrypted_text.set("")

    def copy_result(value):
        if not value:
            return
        root.clipboard_clear()
        root.clipboard_append(value)
        root.update()  # 让复制内容在窗口关闭后依然保留在剪贴板

    def update_cipher_mode(*args):
        mode = cipher_mode_var.get()
        if mode == "GCM":
            # GCM：口令任意长度，无需选择密钥长度与填充模式
            key_length_combobox.config(state="disabled")
            padding_mode_combobox.config(state="disabled")
            key_entry.config(validate="none", width=GCM_KEY_WIDTH)
            key_label_var.set("输入口令")
        else:  # ECB
            key_length_combobox.config(state="readonly")
            padding_mode_combobox.config(state="readonly")
            key_label_var.set("输入密钥")
            update_key_length()

    def update_key_length(*args):
        length = KEY_LENGTHS.get(key_length_combobox.get(), 32)
        # 输入框宽度随密钥长度联动，正好容纳该长度的密钥字符
        key_entry.config(width=length, validate="key",
                         validatecommand=(root.register(limit_key_length), "%P", length))
        if len(key_entry.get()) > length:
            key_entry.delete(length, "end")

    def limit_key_length(new_value, max_length):
        if len(new_value) > int(max_length):
            return False
        return True

    def encrypt_action():
        input_text = input_entry.get()
        key = key_entry.get()
        output_format = format_combobox.get()
        cipher_mode = cipher_mode_var.get()
        clear_results()

        if cipher_mode == "GCM":
            if not key:
                encrypted_text.set("[加密失败，请输入口令]")
                messagebox.showerror("口令错误", "请输入口令！")
                return
            try:
                encrypted_text.set(gcm_encrypt(key, input_text, output_format))
            except Exception as e:
                encrypted_text.set("[加密失败，请检查输入]")
                messagebox.showerror("加密错误", f"加密失败：{str(e)}")
            return

        # ECB 模式
        padding_mode = padding_mode_combobox.get()
        length = KEY_LENGTHS.get(key_length_combobox.get(), 32)
        if len(key) != length:
            encrypted_text.set("[加密失败，请检查密钥是否输入正确]")
            messagebox.showerror("密钥错误", f"密钥长度必须是{length}字符！")
        else:
            try:
                aes = AESCipher(key)
                encrypted_text.set(aes.encrypt(input_text, padding_mode, output_format))
            except ValueError as e:
                encrypted_text.set("[加密失败，请检查原文与密钥是否输入正确]")
                messagebox.showerror("加密错误", f"输入有误：{str(e)}")
            except Exception as e:
                encrypted_text.set("[加密失败，请检查原文与密钥是否输入正确]")
                messagebox.showerror("未知错误", f"加密失败：{str(e)}")

    def decrypt_action():
        input_text = input_entry.get()
        key = key_entry.get()
        input_format = format_combobox.get()
        cipher_mode = cipher_mode_var.get()
        clear_results()

        if cipher_mode == "GCM":
            if not key:
                decrypted_text.set("[解密失败，请输入口令]")
                messagebox.showerror("口令错误", "请输入口令！")
                return
            if not input_text:
                decrypted_text.set("[解密失败，请检查密文是否输入正确]")
                messagebox.showerror("密文错误", "请输入有效的解密文本！")
                return
            try:
                decrypted_text.set(gcm_decrypt(key, input_text, input_format))
            except ValueError as e:
                decrypted_text.set("[解密失败：口令错误或密文已被篡改]")
                messagebox.showerror("解密错误", f"口令错误或密文已被篡改：{str(e)}")
            except Exception as e:
                decrypted_text.set("[解密失败，请检查密文与口令是否输入正确]")
                messagebox.showerror("未知错误", f"解密失败：{str(e)}")
            return

        # ECB 模式
        padding_mode = padding_mode_combobox.get()
        length = KEY_LENGTHS.get(key_length_combobox.get(), 32)
        if len(key) != length:
            decrypted_text.set("[解密失败，请检查密钥是否输入正确]")
            messagebox.showerror("密钥错误", f"密钥长度必须是{length}字符！")
        elif not input_text:
            decrypted_text.set("[解密失败，请检查密文是否输入正确]")
            messagebox.showerror("密文错误", "请输入有效的解密文本！")
        else:
            try:
                aes = AESCipher(key)
                decrypted_text.set(aes.decrypt(input_text, padding_mode, input_format))
            except ValueError as e:
                decrypted_text.set("[解密失败，请检查密文与密钥是否输入正确]")
                messagebox.showerror("解密错误", f"输入有误：{str(e)}")
            except Exception as e:
                decrypted_text.set("[解密失败，请检查密文与密钥是否输入正确]")
                messagebox.showerror("未知错误", f"解密失败：{str(e)}")

    root = tk.Tk()
    root.title("AES加密工具 (支持 ECB / GCM 模式)")
    root.option_add("*Font", "Courier 16")

    tk.Label(root, text="加密模式").grid(row=0, column=0, padx=5, pady=10, sticky="w")
    cipher_mode_var = tk.StringVar(value="ECB")
    frame_cipher_mode = tk.Frame(root)
    frame_cipher_mode.grid(row=0, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Radiobutton(frame_cipher_mode, text="ECB", variable=cipher_mode_var, value="ECB",
                   indicatoron=False, width=8, command=update_cipher_mode).pack(side="left", padx=(0, 10))
    tk.Radiobutton(frame_cipher_mode, text="GCM", variable=cipher_mode_var, value="GCM",
                   indicatoron=False, width=8, command=update_cipher_mode).pack(side="left", padx=(0, 10))

    tk.Label(root, text="输入文本").grid(row=1, column=0, padx=5, pady=10, sticky="w")
    input_entry = tk.Entry(root, width=52)
    input_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=10, sticky="w")

    key_label_var = tk.StringVar(value="输入密钥")
    tk.Label(root, textvariable=key_label_var).grid(row=2, column=0, padx=5, pady=10, sticky="w")
    frame_key = tk.Frame(root)
    frame_key.grid(row=2, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    key_length_combobox = ttk.Combobox(frame_key, values=list(KEY_LENGTHS.keys()), state="readonly", width=14)
    key_length_combobox.pack(side="left", padx=(0, 10))
    key_length_combobox.set("256bit(32字符)")
    key_length_combobox.bind("<<ComboboxSelected>>", update_key_length)
    key_entry = tk.Entry(frame_key, width=40)
    key_entry.pack(side="left", padx=(0, 10))

    tk.Label(root, text="填充模式").grid(row=3, column=0, padx=5, pady=10, sticky="w")
    padding_mode_combobox = ttk.Combobox(root, values=["ZeroPadding", "PKCS7", "AnsiX923", "ISO10126", "ISO97971"], state="readonly", width=14)
    padding_mode_combobox.grid(row=3, column=1, padx=5, pady=10, sticky="w")
    padding_mode_combobox.set("ZeroPadding")

    tk.Label(root, text="密文格式").grid(row=4, column=0, padx=5, pady=10, sticky="w")
    format_combobox = ttk.Combobox(root, values=["base64", "hex"], state="readonly", width=14)
    format_combobox.grid(row=4, column=1, padx=5, pady=10, sticky="w")
    format_combobox.set("base64")

    tk.Label(root, text="加密结果").grid(row=5, column=0, padx=5, pady=10, sticky="w")
    frame_encrypt = tk.Frame(root)
    frame_encrypt.grid(row=5, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_encrypt, text="加密", command=encrypt_action).pack(side="left", padx=(0, 10))
    encrypted_text = tk.StringVar()
    tk.Entry(frame_encrypt, textvariable=encrypted_text, state="readonly", width=46).pack(side="left", padx=(0, 10))
    tk.Button(frame_encrypt, text="复制", command=lambda: copy_result(encrypted_text.get())).pack(side="left", padx=(0, 10))

    tk.Label(root, text="解密结果").grid(row=6, column=0, padx=5, pady=10, sticky="w")
    frame_decrypt = tk.Frame(root)
    frame_decrypt.grid(row=6, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_decrypt, text="解密", command=decrypt_action).pack(side="left", padx=(0, 10))
    decrypted_text = tk.StringVar()
    tk.Entry(frame_decrypt, textvariable=decrypted_text, state="readonly", width=46).pack(side="left", padx=(0, 10))
    tk.Button(frame_decrypt, text="复制", command=lambda: copy_result(decrypted_text.get())).pack(side="left", padx=(0, 10))

    update_cipher_mode()  # 按默认模式（ECB）初始化各控件状态
    root.mainloop()


if __name__ == "__main__":
    main()


# 示例用法
def func_test():
    plaintext = "Hello world!"

    # AES-GCM（推荐）：使用任意长度口令
    passphrase = "my secret passphrase"
    encrypted_gcm = gcm_encrypt(passphrase, plaintext, "base64")
    decrypted_gcm = gcm_decrypt(passphrase, encrypted_gcm, "base64")
    print("\nAES-GCM")
    print("Encrypted:", encrypted_gcm)
    print("Decrypted:", decrypted_gcm)

    # AES-ECB（仅供学习/兼容）：使用固定长度密钥
    key_256 = "12345678909876543212345678909876"  # 32字符密钥用于256位加密
    aes_256 = AESCipher(key_256)
    encrypted_256 = aes_256.encrypt(plaintext, "PKCS7", "base64")
    decrypted_256 = aes_256.decrypt(encrypted_256, "PKCS7", "base64")
    print("\nAES-ECB (256-bit Key)")
    print("Encrypted:", encrypted_256)
    print("Decrypted:", decrypted_256)
