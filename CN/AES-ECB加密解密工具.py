#####################################################################
# Copyright (c) 2024, SanJerry007
# Licensed under the GNU General Public License v3.0.
# See the LICENSE file on https://www.gnu.org/licenses/gpl-3.0.html for details.
# Project repository: https://github.com/SanJerry007/AES-ECB-Minimal-Windows/tree/main
#####################################################################

import base64
import random
import tkinter as tk
from tkinter import messagebox, ttk

from Cryptodome.Cipher import AES


class AESCipher:
    def __init__(self, key: str):
        """
        初始化 AES 加密器。
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
        if len(plaintext) % AES.block_size == 0:  # 无需填充
            return plaintext
        else:  # 按块大小进行填充
            padding_length = AES.block_size - len(plaintext) % AES.block_size
            if mode == "ZeroPadding":
                return plaintext + b'\x00' * padding_length
            elif mode == "PKCS7":
                return plaintext + bytes([padding_length] * padding_length)
            elif mode == "AnsiX923":
                return plaintext + b'\x00' * (padding_length - 1) + bytes([padding_length])
            elif mode == "ISO10126":
                random.seed(114514)
                return plaintext + bytes(random.randint(0, 255) for _ in range(padding_length - 1)) + bytes([padding_length])
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


def main():
    def clear_results():
        encrypted_text.set("")
        decrypted_text.set("")

    def update_key_length(*args):
        selected_value = key_length_combobox.get()
        if selected_value == "128bit(16字符)":
            length = 16
        elif selected_value == "192bit(24字符)":
            length = 24
        elif selected_value == "256bit(32字符)":
            length = 32
        key_entry.config(validate="key", validatecommand=(root.register(limit_key_length), "%P", length), width=length)
        if len(key_entry.get()) > length:
            key_entry.delete(length, "end")

    def limit_key_length(new_value, max_length):
        if len(new_value) > int(max_length):
            return False
        return True

    def encrypt_action():
        input_text = input_entry.get()
        key = key_entry.get()
        padding_mode = padding_mode_combobox.get()
        output_format = format_combobox.get()
        selected_key_length = key_length_combobox.get()
        clear_results()

        if selected_key_length == "128bit(16字符)":
            length = 16
        elif selected_key_length == "192bit(24字符)":
            length = 24
        elif selected_key_length == "256bit(32字符)":
            length = 32

        if len(key) != length:
            encrypted_text.set("[加密失败，请检查密钥是否输入正确]")
            messagebox.showerror("密钥错误", f"密钥长度必须是{length}字符！")
        else:
            try:
                aes = AESCipher(key)
                encrypted = aes.encrypt(input_text, padding_mode, output_format)
                encrypted_text.set(encrypted)
            except ValueError as e:
                encrypted_text.set("[加密失败，请检查原文与密钥是否输入正确]")
                messagebox.showerror("加密错误", f"输入有误：{str(e)}")
            except Exception as e:
                encrypted_text.set("[加密失败，请检查原文与密钥是否输入正确]")
                messagebox.showerror("未知错误", f"加密失败：{str(e)}")

    def decrypt_action():
        input_text = input_entry.get()
        key = key_entry.get()
        padding_mode = padding_mode_combobox.get()
        input_format = format_combobox.get()
        selected_key_length = key_length_combobox.get()
        clear_results()

        if selected_key_length == "128bit(16字符)":
            length = 16
        elif selected_key_length == "192bit(24字符)":
            length = 24
        elif selected_key_length == "256bit(32字符)":
            length = 32

        if len(key) != length:
            decrypted_text.set("[解密失败，请检查密钥是否输入正确]")
            messagebox.showerror("密钥错误", f"密钥长度必须是{length}字符！")
        elif not input_text:
            decrypted_text.set("[解密失败，请检查密文是否输入正确]")
            messagebox.showerror("密文错误", "请输入有效的解密文本！")
        else:
            try:
                aes = AESCipher(key)
                decrypted = aes.decrypt(input_text, padding_mode, input_format)
                decrypted_text.set(decrypted)
            except ValueError as e:
                decrypted_text.set("[解密失败，请检查密文与密钥是否输入正确]")
                messagebox.showerror("解密错误", f"输入有误：{str(e)}")
            except Exception as e:
                decrypted_text.set("[解密失败，请检查密文与密钥是否输入正确]")
                messagebox.showerror("未知错误", f"解密失败：{str(e)}")

    root = tk.Tk()
    root.title("AES加密工具 (目前仅支持ECB密码本加密模式)")
    root.option_add("*Font", "Courier 16")

    tk.Label(root, text="输入文本").grid(row=0, column=0, padx=5, pady=10, sticky="w")
    input_entry = tk.Entry(root, width=52)
    input_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=10, sticky="w")

    tk.Label(root, text="输入密钥").grid(row=1, column=0, padx=5, pady=10, sticky="w")
    frame_key = tk.Frame(root)
    frame_key.grid(row=1, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    key_length_combobox = ttk.Combobox(frame_key, values=["128bit(16字符)", "192bit(24字符)", "256bit(32字符)"], state="readonly", width=14)
    key_length_combobox.pack(side="left", padx=(0, 10))
    key_length_combobox.set("256bit(32字符)")
    key_length_combobox.bind("<<ComboboxSelected>>", update_key_length)
    key_entry = tk.Entry(frame_key, validate="key", validatecommand=(root.register(limit_key_length), "%P", 32), width=32)
    key_entry.pack(side="left", padx=(0, 10))

    tk.Label(root, text="填充模式").grid(row=2, column=0, padx=5, pady=10, sticky="w")
    padding_mode_combobox = ttk.Combobox(root, values=["ZeroPadding", "PKCS7", "AnsiX923", "ISO10126", "ISO97971"], state="readonly", width=14)
    padding_mode_combobox.grid(row=2, column=1, padx=5, pady=10, sticky="w")
    padding_mode_combobox.set("ZeroPadding")

    tk.Label(root, text="密文格式").grid(row=3, column=0, padx=5, pady=10, sticky="w")
    format_combobox = ttk.Combobox(root, values=["base64", "hex"], state="readonly", width=14)
    format_combobox.grid(row=3, column=1, padx=5, pady=10, sticky="w")
    format_combobox.set("base64")

    tk.Label(root, text="加密结果").grid(row=4, column=0, padx=5, pady=10, sticky="w")
    frame_encrypt = tk.Frame(root)
    frame_encrypt.grid(row=4, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_encrypt, text="加密", command=encrypt_action).pack(side="left", padx=(0, 10))
    encrypted_text = tk.StringVar()
    tk.Entry(frame_encrypt, textvariable=encrypted_text, state="readonly", width=46).pack(side="left", padx=(0, 10))

    tk.Label(root, text="解密结果").grid(row=5, column=0, padx=5, pady=10, sticky="w")
    frame_decrypt = tk.Frame(root)
    frame_decrypt.grid(row=5, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_decrypt, text="解密", command=decrypt_action).pack(side="left", padx=(0, 10))
    decrypted_text = tk.StringVar()
    tk.Entry(frame_decrypt, textvariable=decrypted_text, state="readonly", width=46).pack(side="left", padx=(0, 10))

    root.mainloop()


if __name__ == "__main__":
    main()


# 示例用法
def func_test():
    plaintext = "Hello world!"
    key_256 = "12345678909876543212345678909876"  # 32字符密钥用于256位加密
    mode = "ZeroPadding"
    format = "base64"

    # 使用256位密钥
    aes_256 = AESCipher(key_256)
    encrypted_256 = aes_256.encrypt(plaintext, mode, format)
    decrypted_256 = aes_256.decrypt(encrypted_256, mode, format)
    print("\n256-bit Key")
    print("Encrypted:", encrypted_256)
    print("Decrypted:", decrypted_256)
