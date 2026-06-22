#####################################################################
# Copyright(c) 2024, SanJerry007
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

# ===== AES-GCM / KDF parameters =====
_GCM_SALT_LEN = 16   # scrypt salt length
_GCM_NONCE_LEN = 12  # recommended GCM nonce length
_GCM_TAG_LEN = 16    # GCM authentication tag length
_SCRYPT_N = 2 ** 14  # scrypt cost factor (larger = more brute-force resistant, but slower)
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_LEN = 32        # AES-256


class AESCipher:
    def __init__(self, key: str):
        """
        Initializes the AES cipher (used by ECB mode).
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
        remainder = len(plaintext) % AES.block_size
        if mode == "ZeroPadding":
            # ZeroPadding: no padding when already block-aligned
            # (note: a real trailing \x00 in the plaintext will be stripped on decrypt)
            if remainder == 0:
                return plaintext
            padding_length = AES.block_size - remainder
            return plaintext + b'\x00' * padding_length
        # Other modes: even when block-aligned, a full extra block MUST be added,
        # otherwise decryption cannot unambiguously recover the plaintext.
        padding_length = AES.block_size - remainder  # a full block when remainder == 0
        if mode == "PKCS7":
            return plaintext + bytes([padding_length] * padding_length)
        elif mode == "AnsiX923":
            return plaintext + b'\x00' * (padding_length - 1) + bytes([padding_length])
        elif mode == "ISO10126":
            # Pad with cryptographically secure random bytes (no fixed seed anymore)
            return plaintext + get_random_bytes(padding_length - 1) + bytes([padding_length])
        elif mode == "ISO97971":
            return plaintext + b'\x80' + b'\x00' * (padding_length - 1)
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
        NOTE: ECB is insecure (identical plaintext blocks -> identical ciphertext blocks,
        no integrity protection); keep it only for learning / legacy compatibility.
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


def gcm_encrypt(passphrase: str, plaintext: str, output_format: str = "base64") -> str:
    """
    Authenticated encryption with AES-256-GCM (recommended for storing passwords / secrets).
    - The passphrase is stretched into a 256-bit key via scrypt (a random salt per encryption).
    - A random nonce is used each time, so identical plaintexts yield different ciphertexts.
    - Built-in integrity: decryption fails if the ciphertext is tampered with or the passphrase is wrong.
    Output = encode( salt(16) | nonce(12) | tag(16) | ciphertext ).
    :param passphrase: Passphrase of any length.
    :param plaintext: The plaintext to encrypt.
    :param output_format: Output format for ciphertext (base64 / hex).
    :return: Encoded ciphertext.
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
        raise NotImplementedError(f"Unsupported output format: {output_format}")


def gcm_decrypt(passphrase: str, token_str: str, input_format: str = "base64") -> str:
    """
    Decrypts ciphertext produced by gcm_encrypt and verifies its integrity.
    Raises ValueError if the passphrase is wrong or the ciphertext was tampered with.
    :param passphrase: The passphrase used during encryption.
    :param token_str: Encoded ciphertext.
    :param input_format: Input format for ciphertext (base64 / hex).
    :return: Original plaintext.
    """
    if input_format == "base64":
        token = base64.b64decode(token_str)
    elif input_format == "hex":
        token = bytes.fromhex(token_str)
    else:
        raise NotImplementedError(f"Unsupported input format: {input_format}")
    header_len = _GCM_SALT_LEN + _GCM_NONCE_LEN + _GCM_TAG_LEN
    if len(token) < header_len:
        raise ValueError("Ciphertext too short or malformed")
    salt = token[:_GCM_SALT_LEN]
    nonce = token[_GCM_SALT_LEN:_GCM_SALT_LEN + _GCM_NONCE_LEN]
    tag = token[_GCM_SALT_LEN + _GCM_NONCE_LEN:header_len]
    ciphertext = token[header_len:]
    key = scrypt(passphrase.encode('utf-8'), salt, key_len=_KEY_LEN, N=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # raises ValueError on MAC failure
    return plaintext.decode('utf-8')


def main():
    KEY_LENGTHS = {"128bit(16byte)": 16, "192bit(24byte)": 24, "256bit(32byte)": 32}

    def clear_results():
        encrypted_text.set("")
        decrypted_text.set("")

    def copy_result(value):
        if not value:
            return
        root.clipboard_clear()
        root.clipboard_append(value)
        root.update()  # keep the copied text on the clipboard after the window closes

    def update_cipher_mode(*args):
        mode = cipher_mode_var.get()
        if mode == "GCM":
            # GCM: passphrase of any length, no key-length / padding selection needed
            key_length_combobox.config(state="disabled")
            padding_mode_combobox.config(state="disabled")
            key_entry.config(validate="none")
            key_label_var.set("Passphrase")
        else:  # ECB
            key_length_combobox.config(state="readonly")
            padding_mode_combobox.config(state="readonly")
            key_label_var.set("Secret Key")
            update_key_length()

    def update_key_length(*args):
        length = KEY_LENGTHS.get(key_length_combobox.get(), 32)
        key_entry.config(validate="key", validatecommand=(root.register(limit_key_length), "%P", length))
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
                encrypted_text.set("[Encryption failed, please enter a passphrase]")
                messagebox.showerror("Passphrase Error", "Please enter a passphrase!")
                return
            try:
                encrypted_text.set(gcm_encrypt(key, input_text, output_format))
            except Exception as e:
                encrypted_text.set("[Encryption failed, please check the input]")
                messagebox.showerror("Encryption Error", f"Encryption failed: {str(e)}")
            return

        # ECB mode
        padding_mode = padding_mode_combobox.get()
        length = KEY_LENGTHS.get(key_length_combobox.get(), 32)
        if len(key) != length:
            encrypted_text.set("[Encryption failed, please check the key length]")
            messagebox.showerror("Key Error", f"The key length must be {length} characters!")
        else:
            try:
                aes = AESCipher(key)
                encrypted_text.set(aes.encrypt(input_text, padding_mode, output_format))
            except ValueError as e:
                encrypted_text.set("[Encryption failed, please check the input text and key]")
                messagebox.showerror("Encryption Error", f"Input Error: {str(e)}")
            except Exception as e:
                encrypted_text.set("[Encryption failed, please check the input text and key]")
                messagebox.showerror("Unknown Error", f"Encryption failed: {str(e)}")

    def decrypt_action():
        input_text = input_entry.get()
        key = key_entry.get()
        input_format = format_combobox.get()
        cipher_mode = cipher_mode_var.get()
        clear_results()

        if cipher_mode == "GCM":
            if not key:
                decrypted_text.set("[Decryption failed, please enter a passphrase]")
                messagebox.showerror("Passphrase Error", "Please enter a passphrase!")
                return
            if not input_text:
                decrypted_text.set("[Decryption failed, please check the ciphertext]")
                messagebox.showerror("Ciphertext Error", "Please enter valid ciphertext!")
                return
            try:
                decrypted_text.set(gcm_decrypt(key, input_text, input_format))
            except ValueError as e:
                decrypted_text.set("[Decryption failed: wrong passphrase or tampered ciphertext]")
                messagebox.showerror("Decryption Error", f"Wrong passphrase or tampered ciphertext: {str(e)}")
            except Exception as e:
                decrypted_text.set("[Decryption failed, please check the ciphertext and passphrase]")
                messagebox.showerror("Unknown Error", f"Decryption failed: {str(e)}")
            return

        # ECB mode
        padding_mode = padding_mode_combobox.get()
        length = KEY_LENGTHS.get(key_length_combobox.get(), 32)
        if len(key) != length:
            decrypted_text.set("[Decryption failed, please check the key length]")
            messagebox.showerror("Key Error", f"The key length must be {length} characters!")
        elif not input_text:
            decrypted_text.set("[Decryption failed, please check the ciphertext]")
            messagebox.showerror("Ciphertext Error", "Please enter valid ciphertext!")
        else:
            try:
                aes = AESCipher(key)
                decrypted_text.set(aes.decrypt(input_text, padding_mode, input_format))
            except ValueError as e:
                decrypted_text.set("[Decryption failed, please check the ciphertext and key]")
                messagebox.showerror("Decryption Error", f"Input Error: {str(e)}")
            except Exception as e:
                decrypted_text.set("[Decryption failed, please check the ciphertext and key]")
                messagebox.showerror("Unknown Error", f"Decryption failed: {str(e)}")

    root = tk.Tk()
    root.title("AES Encryption Tool (supports ECB / GCM)")
    root.option_add("*Font", "Courier 16")

    tk.Label(root, text="Cipher Mode").grid(row=0, column=0, padx=5, pady=10, sticky="w")
    cipher_mode_var = tk.StringVar(value="ECB")
    frame_cipher_mode = tk.Frame(root)
    frame_cipher_mode.grid(row=0, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Radiobutton(frame_cipher_mode, text="ECB", variable=cipher_mode_var, value="ECB",
                   indicatoron=False, width=8, command=update_cipher_mode).pack(side="left", padx=(0, 10))
    tk.Radiobutton(frame_cipher_mode, text="GCM", variable=cipher_mode_var, value="GCM",
                   indicatoron=False, width=8, command=update_cipher_mode).pack(side="left", padx=(0, 10))

    tk.Label(root, text="Plain/Cipher Text").grid(row=1, column=0, padx=5, pady=10, sticky="w")
    input_entry = tk.Entry(root, width=54)
    input_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=10, sticky="w")

    key_label_var = tk.StringVar(value="Secret Key")
    tk.Label(root, textvariable=key_label_var).grid(row=2, column=0, padx=5, pady=10, sticky="w")
    frame_key = tk.Frame(root)
    frame_key.grid(row=2, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    key_length_combobox = ttk.Combobox(frame_key, values=list(KEY_LENGTHS.keys()), state="readonly", width=14)
    key_length_combobox.pack(side="left", padx=(0, 10))
    key_length_combobox.set("256bit(32byte)")
    key_length_combobox.bind("<<ComboboxSelected>>", update_key_length)
    key_entry = tk.Entry(frame_key, width=40)
    key_entry.pack(side="left", padx=(0, 10))

    tk.Label(root, text="Padding Mode").grid(row=3, column=0, padx=5, pady=10, sticky="w")
    padding_mode_combobox = ttk.Combobox(root, values=["ZeroPadding", "PKCS7", "AnsiX923", "ISO10126", "ISO97971"], state="readonly", width=14)
    padding_mode_combobox.grid(row=3, column=1, padx=5, pady=10, sticky="w")
    padding_mode_combobox.set("ZeroPadding")

    tk.Label(root, text="Cipher Format").grid(row=4, column=0, padx=5, pady=10, sticky="w")
    format_combobox = ttk.Combobox(root, values=["base64", "hex"], state="readonly", width=14)
    format_combobox.grid(row=4, column=1, padx=5, pady=10, sticky="w")
    format_combobox.set("base64")

    tk.Label(root, text="Encrypted Output").grid(row=5, column=0, padx=5, pady=10, sticky="w")
    frame_encrypt = tk.Frame(root)
    frame_encrypt.grid(row=5, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_encrypt, text="Encrypt", command=encrypt_action).pack(side="left", padx=(0, 10))
    encrypted_text = tk.StringVar()
    tk.Entry(frame_encrypt, textvariable=encrypted_text, state="readonly", width=44).pack(side="left", padx=(0, 10))
    tk.Button(frame_encrypt, text="Copy", command=lambda: copy_result(encrypted_text.get())).pack(side="left", padx=(0, 10))

    tk.Label(root, text="Decrypted Output").grid(row=6, column=0, padx=5, pady=10, sticky="w")
    frame_decrypt = tk.Frame(root)
    frame_decrypt.grid(row=6, column=1, columnspan=2, padx=5, pady=10, sticky="w")
    tk.Button(frame_decrypt, text="Decrypt", command=decrypt_action).pack(side="left", padx=(0, 10))
    decrypted_text = tk.StringVar()
    tk.Entry(frame_decrypt, textvariable=decrypted_text, state="readonly", width=44).pack(side="left", padx=(0, 10))
    tk.Button(frame_decrypt, text="Copy", command=lambda: copy_result(decrypted_text.get())).pack(side="left", padx=(0, 10))

    update_cipher_mode()  # initialize widget states for the default mode (ECB)
    root.mainloop()


if __name__ == "__main__":
    main()


# Example usage
def func_test():
    plaintext = "Hello world!"

    # AES-GCM (recommended): use a passphrase of any length
    passphrase = "my secret passphrase"
    encrypted_gcm = gcm_encrypt(passphrase, plaintext, "base64")
    decrypted_gcm = gcm_decrypt(passphrase, encrypted_gcm, "base64")
    print("\nAES-GCM")
    print("Encrypted:", encrypted_gcm)
    print("Decrypted:", decrypted_gcm)

    # AES-ECB (learning / legacy only): use a fixed-length key
    key_256 = "12345678909876543212345678909876"  # 32-character key for 256-bit encryption
    aes_256 = AESCipher(key_256)
    encrypted_256 = aes_256.encrypt(plaintext, "PKCS7", "base64")
    decrypted_256 = aes_256.decrypt(encrypted_256, "PKCS7", "base64")
    print("\nAES-ECB (256-bit Key)")
    print("Encrypted:", encrypted_256)
    print("Decrypted:", decrypted_256)
