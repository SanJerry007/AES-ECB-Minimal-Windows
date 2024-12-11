#####################################################################
# Copyright(c) 2024, SanJerry007
# Licensed under the GNU General Public License v3.0.
# See the LICENSE file on https://www.gnu.org/licenses/gpl-3.0.html for details.
# Project repository: https://github.com/SanJerry007/AES-ECB-Minimal-Windows
#####################################################################

import base64
import random
import tkinter as tk
from tkinter import messagebox, ttk

from Cryptodome.Cipher import AES


class AESCipher:
    def __init__(self, key: str):
        """
        Initializes the AES cipher.
        :param key: The encryption key.
        """
        self.key = key.encode('utf-8')

    def _pad(self, plaintext: bytes, mode: str = "ZeroPadding") -> bytes:
        """
        Applies padding to the plaintext based on the selected mode.
        :param plaintext: Plaintext to be padded.
        :param mode: Padding mode.
        :return: Padded plaintext.
        """
        if len(plaintext) % AES.block_size == 0:  # no padding
            return plaintext
        else:  # pad according to the block_size
            padding_length = AES.block_size - len(plaintext) % AES.block_size
            if mode == "ZeroPadding":
                return plaintext + b'\x00' * padding_length
            elif mode == "PKCS7":
                return plaintext + bytes([padding_length] * padding_length)
            elif mode == "AnsiX923":
                return plaintext + b'\x00' *(padding_length - 1) + bytes([padding_length])
            elif mode == "ISO10126":
                random.seed(114514)
                return plaintext + bytes(random.randint(0, 255) for _ in range(padding_length - 1)) + bytes([padding_length])
            elif mode == "ISO97971":
                return plaintext + b'\x80' + b'\x00' *(padding_length - 1)
            else:
                raise ValueError("Unsupported padding mode")

    def _unpad(self, plaintext: bytes, mode: str = "ZeroPadding") -> bytes:
        """
        Removes padding from the plaintext based on the selected mode.
        :param plaintext: Padded plaintext.
        :param mode: Padding mode.
        :return: Original plaintext without padding.
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
            raise ValueError("Unsupported padding mode")

    def encrypt(self, plaintext: str, mode: str = "ZeroPadding", output_format: str = "base64") -> str:
        """
        Encrypts the plaintext using AES in ECB mode.
        :param plaintext: The plaintext to encrypt.
        :param mode: Padding mode.
        :param output_format: Output format for ciphertext.
        :return: Encoded ciphertext.
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_plaintext = self._pad(plaintext.encode('utf-8'), mode)
        ciphertext = cipher.encrypt(padded_plaintext)
        if output_format == "base64":
            return base64.b64encode(ciphertext).decode('utf-8')
        elif output_format == "hex":
            return ciphertext.hex()
        else:
            raise NotImplementedError(f"Unsupported output format: {output_format}")

    def decrypt(self, ciphertext: str, mode: str = "ZeroPadding", input_format: str = "base64") -> str:
        """
        Decrypts the ciphertext using AES in ECB mode.
        :param ciphertext: Encoded ciphertext to decrypt.
        :param mode: Padding mode.
        :param input_format: Input format for ciphertext.
        :return: Original plaintext.
        """
        cipher = AES.new(self.key, AES.MODE_ECB)
        if input_format == "base64":
            decoded_ciphertext = base64.b64decode(ciphertext)
        elif input_format == "hex":
            decoded_ciphertext = bytes.fromhex(ciphertext)
        else:
            raise NotImplementedError(f"Unsupported input format: {input_format}")
        plaintext = cipher.decrypt(decoded_ciphertext)
        return self._unpad(plaintext, mode).decode('utf-8')


def main():
    def clear_results():
        encrypted_text.set("")
        decrypted_text.set("")

    def update_key_length(*args):
        selected_value = key_length_combobox.get()
        if selected_value == "128bit(16byte)":
            length = 16
        elif selected_value == "192bit(24byte)":
            length = 24
        elif selected_value == "256bit(32byte)":
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

        if selected_key_length == "128bit(16byte)":
            length = 16
        elif selected_key_length == "192bit(24byte)":
            length = 24
        elif selected_key_length == "256bit(32byte)":
            length = 32

        if len(key) != length:
            encrypted_text.set("[Encryption failed, please check the key length]")
            messagebox.showerror("Key Error", f"The key length must be {length} characters!")
        else:
            try:
                aes = AESCipher(key)
                encrypted = aes.encrypt(input_text, padding_mode, output_format)
                encrypted_text.set(encrypted)
            except ValueError as e:
                encrypted_text.set("[Encryption failed, please check the input text and key]")
                messagebox.showerror("Encryption Error", f"Input Error: {str(e)}")
            except Exception as e:
                encrypted_text.set("[Encryption failed, please check the input text and key]")
                messagebox.showerror("Unknown Error", f"Encryption failed: {str(e)}")

    def decrypt_action():
        input_text = input_entry.get()
        key = key_entry.get()
        padding_mode = padding_mode_combobox.get()
        input_format = format_combobox.get()
        selected_key_length = key_length_combobox.get()
        clear_results()

        if selected_key_length == "128bit(16byte)":
            length = 16
        elif selected_key_length == "192bit(24byte)":
            length = 24
        elif selected_key_length == "256bit(32byte)":
            length = 32

        if len(key) != length:
            decrypted_text.set("[Decryption failed, please check the key length]")
            messagebox.showerror("Key Error", f"The key length must be {length} characters!")
        elif not input_text:
            decrypted_text.set("[Decryption failed, please check the ciphertext]")
            messagebox.showerror("Ciphertext Error", "Please enter valid ciphertext!")
        else:
            try:
                aes = AESCipher(key)
                decrypted = aes.decrypt(input_text, padding_mode, input_format)
                decrypted_text.set(decrypted)
            except ValueError as e:
                decrypted_text.set("[Decryption failed, please check the ciphertext and key]")
                messagebox.showerror("Decryption Error", f"Input Error: {str(e)}")
            except Exception as e:
                decrypted_text.set("[Decryption failed, please check the ciphertext and key]")
                messagebox.showerror("Unknown Error", f"Decryption failed: {str(e)}")

    root = tk.Tk()
    root.title("AES Encryption Tool (Currently supports only ECB mode)")
    root.option_add("*Font", "Courier 16")

    tk.Label(root, text="Plain/Cipher Text").grid(row=0, column=0, padx=5, pady=10, sticky="w")
    input_entry = tk.Entry(root, width=54)
    input_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=10, sticky="w")

    tk.Label(root, text="Secret Key").grid(row=1, column=0, padx=5, pady=10, sticky="w")
    frame_key = tk.Frame(root)
    frame_key.grid(row=1, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    key_length_combobox = ttk.Combobox(frame_key, values=["128bit(16byte)", "192bit(24byte)", "256bit(32byte)"], state="readonly", width=14)
    key_length_combobox.pack(side="left", padx=(0, 10))
    key_length_combobox.set("256bit(32byte)")
    key_length_combobox.bind("<<ComboboxSelected>>", update_key_length)
    key_entry = tk.Entry(frame_key, validate="key", validatecommand=(root.register(limit_key_length), "%P", 32), width=32)
    key_entry.pack(side="left", padx=(0, 10))

    tk.Label(root, text="Padding Mode").grid(row=2, column=0, padx=5, pady=10, sticky="w")
    padding_mode_combobox = ttk.Combobox(root, values=["ZeroPadding", "PKCS7", "AnsiX923", "ISO10126", "ISO97971"], state="readonly", width=14)
    padding_mode_combobox.grid(row=2, column=1, padx=5, pady=10, sticky="w")
    padding_mode_combobox.set("ZeroPadding")

    tk.Label(root, text="Cipher Format").grid(row=3, column=0, padx=5, pady=10, sticky="w")
    format_combobox = ttk.Combobox(root, values=["base64", "hex"], state="readonly", width=14)
    format_combobox.grid(row=3, column=1, padx=5, pady=10, sticky="w")
    format_combobox.set("base64")

    tk.Label(root, text="Encrypted Output").grid(row=4, column=0, padx=5, pady=10, sticky="w")
    frame_encrypt = tk.Frame(root)
    frame_encrypt.grid(row=4, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_encrypt, text="Encrypt", command=encrypt_action).pack(side="left", padx=(0, 10))
    encrypted_text = tk.StringVar()
    tk.Entry(frame_encrypt, textvariable=encrypted_text, state="readonly", width=44).pack(side="left", padx=(0, 10))

    tk.Label(root, text="Decrypted Output").grid(row=5, column=0, padx=5, pady=10, sticky="w")
    frame_decrypt = tk.Frame(root)
    frame_decrypt.grid(row=5, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_decrypt, text="Decrypt", command=decrypt_action).pack(side="left", padx=(0, 10))
    decrypted_text = tk.StringVar()
    tk.Entry(frame_decrypt, textvariable=decrypted_text, state="readonly", width=44).pack(side="left", padx=(0, 10))

    root.mainloop()


if __name__ == "__main__":
    main()


# Example usage
def func_test():
    plaintext = "Hello world!"
    key_256 = "12345678909876543212345678909876"  # 32-character key for 256-bit encryption
    mode = "ZeroPadding"
    format = "base64"

    # Using 256-bit key
    aes_256 = AESCipher(key_256)
    encrypted_256 = aes_256.encrypt(plaintext, mode, format)
    decrypted_256 = aes_256.decrypt(encrypted_256, mode, format)
    print("\n256-bit Key")
    print("Encrypted:", encrypted_256)
    print("Decrypted:", decrypted_256)
