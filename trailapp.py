import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import os
import base64
import hmac
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ============================================================
# SECURITY SETTINGS
# ============================================================

MAGIC = b"SECUREAPP1"

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

PBKDF2_ITERATIONS = 600_000

# Encryption method identifiers
AES_GCM = b"AG"
CHACHA20 = b"CH"
AES_CBC = b"AC"


# ============================================================
# PASSWORD -> KEY
# ============================================================

def derive_key(password, salt):
    if not password:
        raise ValueError("Password cannot be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )

    return kdf.derive(password.encode("utf-8"))


# ============================================================
# AES-256-GCM
# ============================================================

def aes_gcm_encrypt(data, password):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    aes = AESGCM(key)

    encrypted = aes.encrypt(
        nonce,
        data,
        None
    )

    return MAGIC + AES_GCM + salt + nonce + encrypted


def aes_gcm_decrypt(package, password):
    position = len(MAGIC) + 2

    salt = package[position:position + SALT_SIZE]
    position += SALT_SIZE

    nonce = package[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    encrypted = package[position:]

    key = derive_key(password, salt)

    try:
        return AESGCM(key).decrypt(
            nonce,
            encrypted,
            None
        )
    except Exception:
        raise ValueError(
            "Incorrect password or corrupted data."
        )


# ============================================================
# CHACHA20-POLY1305
# ============================================================

def chacha_encrypt(data, password):
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    key = derive_key(password, salt)

    cipher = ChaCha20Poly1305(key)

    encrypted = cipher.encrypt(
        nonce,
        data,
        None
    )

    return MAGIC + CHACHA20 + salt + nonce + encrypted


def chacha_decrypt(package, password):
    position = len(MAGIC) + 2

    salt = package[position:position + SALT_SIZE]
    position += SALT_SIZE

    nonce = package[position:position + NONCE_SIZE]
    position += NONCE_SIZE

    encrypted = package[position:]

    key = derive_key(password, salt)

    try:
        return ChaCha20Poly1305(key).decrypt(
            nonce,
            encrypted,
            None
        )
    except Exception:
        raise ValueError(
            "Incorrect password or corrupted data."
        )


# ============================================================
# AES-256-CBC + HMAC-SHA256
# ============================================================

def aes_cbc_encrypt(data, password):
    salt = os.urandom(SALT_SIZE)

    key = derive_key(password, salt)

    # AES CBC requires a 16-byte IV
    iv = os.urandom(16)

    # PKCS7-style padding
    padding_length = 16 - (len(data) % 16)

    padded = data + bytes([padding_length]) * padding_length

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )

    encryptor = cipher.encryptor()

    encrypted = (
        encryptor.update(padded)
        + encryptor.finalize()
    )

    # HMAC protects the encrypted data
    mac = hmac.new(
        key,
        iv + encrypted,
        hashlib.sha256
    ).digest()

    return (
        MAGIC
        + AES_CBC
        + salt
        + iv
        + mac
        + encrypted
    )


def aes_cbc_decrypt(package, password):
    position = len(MAGIC) + 2

    salt = package[position:position + SALT_SIZE]
    position += SALT_SIZE

    iv = package[position:position + 16]
    position += 16

    mac = package[position:position + 32]
    position += 32

    encrypted = package[position:]

    key = derive_key(password, salt)

    # Verify HMAC before decrypting
    expected_mac = hmac.new(
        key,
        iv + encrypted,
        hashlib.sha256
    ).digest()

    if not hmac.compare_digest(mac, expected_mac):
        raise ValueError(
            "Incorrect password or corrupted data."
        )

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv)
    )

    decryptor = cipher.decryptor()

    padded = (
        decryptor.update(encrypted)
        + decryptor.finalize()
    )

    if not padded:
        raise ValueError("Invalid encrypted data.")

    padding_length = padded[-1]

    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding.")

    if padded[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid encrypted data.")

    return padded[:-padding_length]


# ============================================================
# GENERAL ENCRYPTION
# ============================================================

def encrypt_data(data, password, method):

    if method == "AES-256-GCM":
        return aes_gcm_encrypt(data, password)

    elif method == "ChaCha20-Poly1305":
        return chacha_encrypt(data, password)

    elif method == "AES-256-CBC + HMAC":
        return aes_cbc_encrypt(data, password)

    else:
        raise ValueError("Unknown encryption method.")


# ============================================================
# GENERAL DECRYPTION
# ============================================================

def decrypt_data(package, password):

    if len(package) < len(MAGIC) + 2:
        raise ValueError(
            "Encrypted data is too short or corrupted."
        )

    if package[:len(MAGIC)] != MAGIC:
        raise ValueError(
            "This is not a valid Secure Encryption App file."
        )

    method = package[
        len(MAGIC):
        len(MAGIC) + 2
    ]

    if method == AES_GCM:
        return aes_gcm_decrypt(
            package,
            password
        )

    elif method == CHACHA20:
        return chacha_decrypt(
            package,
            password
        )

    elif method == AES_CBC:
        return aes_cbc_decrypt(
            package,
            password
        )

    else:
        raise ValueError(
            "Unknown encryption method."
        )


# ============================================================
# GUI APPLICATION
# ============================================================

class SecureEncryptionApp:

    def __init__(self, root):

        self.root = root

        self.root.title(
            "Secure Text & File Encryption"
        )

        self.root.geometry(
            "780x760"
        )

        self.root.minsize(
            720,
            680
        )

        # ----------------------------------------------------
        # TITLE
        # ----------------------------------------------------

        tk.Label(
            root,
            text="🔐 Secure Encryption App",
            font=("Segoe UI", 24, "bold")
        ).pack(
            pady=(20, 3)
        )

        tk.Label(
            root,
            text="Encrypt Text and Files with Your Preferred Method",
            font=("Segoe UI", 11)
        ).pack(
            pady=(0, 15)
        )

        # ----------------------------------------------------
        # TABS
        # ----------------------------------------------------

        notebook = ttk.Notebook(root)

        notebook.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=10
        )

        self.text_tab = tk.Frame(notebook)
        self.file_tab = tk.Frame(notebook)

        notebook.add(
            self.text_tab,
            text="📝 Text"
        )

        notebook.add(
            self.file_tab,
            text="📁 Files"
        )

        self.create_text_tab()
        self.create_file_tab()

        tk.Label(
            root,
            text=(
                "AES-256-GCM  •  ChaCha20-Poly1305  •  "
                "AES-256-CBC + HMAC"
            ),
            font=("Segoe UI", 9)
        ).pack(
            pady=10
        )

    # ========================================================
    # ENCRYPTION METHOD DROPDOWN
    # ========================================================

    def create_method_selector(self, parent):

        frame = tk.Frame(parent)

        frame.pack(
            fill="x",
            padx=15,
            pady=10
        )

        tk.Label(
            frame,
            text="Encryption Method:",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        variable = tk.StringVar(
            value="AES-256-GCM"
        )

        dropdown = ttk.Combobox(
            frame,
            textvariable=variable,
            state="readonly",
            width=30,
            values=[
                "AES-256-GCM",
                "ChaCha20-Poly1305",
                "AES-256-CBC + HMAC"
            ]
        )

        dropdown.pack(
            side="left",
            padx=10
        )

        return variable

    # ========================================================
    # TEXT TAB
    # ========================================================

    def create_text_tab(self):

        tk.Label(
            self.text_tab,
            text="Enter text:",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=15,
            pady=(15, 5)
        )

        self.text_input = ScrolledText(
            self.text_tab,
            height=9,
            font=("Consolas", 11),
            wrap="word"
        )

        self.text_input.pack(
            fill="both",
            expand=True,
            padx=15
        )

        # Method
        self.text_method = self.create_method_selector(
            self.text_tab
        )

        # Password
        password_frame = tk.Frame(
            self.text_tab
        )

        password_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        tk.Label(
            password_frame,
            text="Password:",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        self.text_password = tk.Entry(
            password_frame,
            show="•",
            font=("Segoe UI", 11)
        )

        self.text_password.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10
        )

        # Confirm
        confirm_frame = tk.Frame(
            self.text_tab
        )

        confirm_frame.pack(
            fill="x",
            padx=15,
            pady=5
        )

        tk.Label(
            confirm_frame,
            text="Confirm:",
            font=("Segoe UI", 10, "bold")
        ).pack(
            side="left"
        )

        self.text_confirm = tk.Entry(
            confirm_frame,
            show="•",
            font=("Segoe UI", 11)
        )

        self.text_confirm.pack(
            side="left",
            fill="x",
            expand=True,
            padx=10
        )

        # Buttons
        button_frame = tk.Frame(
            self.text_tab
        )

        button_frame.pack(
            pady=10
        )

        tk.Button(
            button_frame,
            text="🔒 Encrypt",
            width=16,
            height=2,
            font=("Segoe UI", 10, "bold"),
            command=self.encrypt_text_gui
        ).pack(
            side="left",
            padx=5
        )

        tk.Button(
            button_frame,
            text="🔓 Decrypt",
            width=16,
            height=2,
            font=("Segoe UI", 10, "bold"),
            command=self.decrypt_text_gui
        ).pack(
            side="left",
            padx=5
        )

        tk.Button(
            button_frame,
            text="📋 Copy",
            width=12,
            height=2,
            command=self.copy_result
        ).pack(
            side="left",
            padx=5
        )

        tk.Label(
            self.text_tab,
            text="Result:",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=15,
            pady=(5, 5)
        )

        self.text_result = ScrolledText(
            self.text_tab,
            height=9,
            font=("Consolas", 10),
            wrap="word"
        )

        self.text_result.pack(
            fill="both",
            expand=True,
            padx=15,
            pady=(0, 15)
        )

    # ========================================================
    # FILE TAB
    # ========================================================

    def create_file_tab(self):

        tk.Label(
            self.file_tab,
            text="Select a file:",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(25, 8)
        )

        file_frame = tk.Frame(
            self.file_tab
        )

        file_frame.pack(
            fill="x",
            padx=20
        )

        self.file_path = tk.StringVar()

        tk.Entry(
            file_frame,
            textvariable=self.file_path,
            state="readonly",
            font=("Segoe UI", 10)
        ).pack(
            side="left",
            fill="x",
            expand=True
        )

        tk.Button(
            file_frame,
            text="Browse",
            width=12,
            command=self.browse_file
        ).pack(
            side="left",
            padx=(10, 0)
        )

        # Method
        self.file_method = self.create_method_selector(
            self.file_tab
        )

        # Password
        tk.Label(
            self.file_tab,
            text="Password:",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 8)
        )

        self.file_password = tk.Entry(
            self.file_tab,
            show="•",
            font=("Segoe UI", 11)
        )

        self.file_password.pack(
            fill="x",
            padx=20
        )

        # Confirm
        tk.Label(
            self.file_tab,
            text="Confirm password:",
            font=("Segoe UI", 11, "bold")
        ).pack(
            anchor="w",
            padx=20,
            pady=(20, 8)
        )

        self.file_confirm = tk.Entry(
            self.file_tab,
            show="•",
            font=("Segoe UI", 11)
        )

        self.file_confirm.pack(
            fill="x",
            padx=20
        )

        # Buttons
        button_frame = tk.Frame(
            self.file_tab
        )

        button_frame.pack(
            pady=35
        )

        tk.Button(
            button_frame,
            text="🔒 Encrypt File",
            width=20,
            height=2,
            font=("Segoe UI", 11, "bold"),
            command=self.encrypt_file_gui
        ).pack(
            side="left",
            padx=10
        )

        tk.Button(
            button_frame,
            text="🔓 Decrypt File",
            width=20,
            height=2,
            font=("Segoe UI", 11, "bold"),
            command=self.decrypt_file_gui
        ).pack(
            side="left",
            padx=10
        )

        self.file_status = tk.StringVar(
            value="Ready"
        )

        tk.Label(
            self.file_tab,
            textvariable=self.file_status,
            font=("Segoe UI", 11)
        ).pack(
            pady=20
        )

    # ========================================================
    # TEXT ENCRYPT
    # ========================================================

    def encrypt_text_gui(self):

        text = self.text_input.get(
            "1.0",
            tk.END
        ).strip()

        password = self.text_password.get()
        confirm = self.text_confirm.get()
        method = self.text_method.get()

        if not text:
            messagebox.showwarning(
                "Missing Text",
                "Please enter text to encrypt."
            )
            return

        if not password:
            messagebox.showwarning(
                "Missing Password",
                "Please enter a password."
            )
            return

        if len(password) < 8:
            messagebox.showwarning(
                "Weak Password",
                "Password must contain at least 8 characters."
            )
            return

        if password != confirm:
            messagebox.showerror(
                "Password Error",
                "Passwords do not match."
            )
            return

        try:

            encrypted = encrypt_data(
                text.encode("utf-8"),
                password,
                method
            )

            encoded = base64.b64encode(
                encrypted
            ).decode("ascii")

            self.text_result.delete(
                "1.0",
                tk.END
            )

            self.text_result.insert(
                tk.END,
                encoded
            )

            messagebox.showinfo(
                "Success",
                f"Text encrypted using:\n{method}"
            )

        except Exception as e:

            messagebox.showerror(
                "Encryption Error",
                str(e)
            )

    # ========================================================
    # TEXT DECRYPT
    # ========================================================

    def decrypt_text_gui(self):

        encrypted_text = self.text_input.get(
            "1.0",
            tk.END
        ).strip()

        password = self.text_password.get()
        confirm = self.text_confirm.get()

        if not encrypted_text:
            messagebox.showwarning(
                "Missing Data",
                "Please enter encrypted text."
            )
            return

        if not password:
            messagebox.showwarning(
                "Missing Password",
                "Please enter the password."
            )
            return

        if password != confirm:
            messagebox.showerror(
                "Password Error",
                "Passwords do not match."
            )
            return

        try:

            package = base64.b64decode(
                encrypted_text,
                validate=True
            )

            decrypted = decrypt_data(
                package,
                password
            )

            self.text_result.delete(
                "1.0",
                tk.END
            )

            self.text_result.insert(
                tk.END,
                decrypted.decode("utf-8")
            )

            messagebox.showinfo(
                "Success",
                "Text decrypted successfully."
            )

        except Exception as e:

            messagebox.showerror(
                "Decryption Error",
                str(e)
            )

    # ========================================================
    # COPY
    # ========================================================

    def copy_result(self):

        result = self.text_result.get(
            "1.0",
            tk.END
        ).strip()

        if not result:
            messagebox.showwarning(
                "Nothing to Copy",
                "There is no result to copy."
            )
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(result)
        self.root.update()

        messagebox.showinfo(
            "Copied",
            "Result copied to clipboard."
        )

    # ========================================================
    # BROWSE FILE
    # ========================================================

    def browse_file(self):

        filename = filedialog.askopenfilename(
            title="Select File"
        )

        if filename:

            self.file_path.set(
                filename
            )

            self.file_status.set(
                "Selected: "
                + os.path.basename(filename)
            )

    # ========================================================
    # FILE ENCRYPT
    # ========================================================

    def encrypt_file_gui(self):

        input_file = self.file_path.get()
        password = self.file_password.get()
        confirm = self.file_confirm.get()
        method = self.file_method.get()

        if not input_file:

            messagebox.showwarning(
                "Missing File",
                "Please select a file."
            )

            return

        if not password:

            messagebox.showwarning(
                "Missing Password",
                "Please enter a password."
            )

            return

        if len(password) < 8:

            messagebox.showwarning(
                "Weak Password",
                "Password must contain at least 8 characters."
            )

            return

        if password != confirm:

            messagebox.showerror(
                "Password Error",
                "Passwords do not match."
            )

            return

        output_file = filedialog.asksaveasfilename(
            title="Save Encrypted File",
            defaultextension=".enc",
            initialfile=(
                os.path.basename(input_file)
                + ".enc"
            ),
            filetypes=[
                ("Encrypted files", "*.enc"),
                ("All files", "*.*")
            ]
        )

        if not output_file:
            return

        try:

            self.file_status.set(
                "Encrypting..."
            )

            self.root.update_idletasks()

            with open(input_file, "rb") as f:
                data = f.read()

            encrypted = encrypt_data(
                data,
                password,
                method
            )

            with open(output_file, "wb") as f:
                f.write(encrypted)

            self.file_status.set(
                "Encryption completed."
            )

            messagebox.showinfo(
                "Success",
                "File encrypted successfully!\n\n"
                f"Method: {method}\n\n"
                f"Saved to:\n{output_file}"
            )

        except Exception as e:

            self.file_status.set(
                "Encryption failed."
            )

            messagebox.showerror(
                "Encryption Error",
                str(e)
            )

    # ========================================================
    # FILE DECRYPT
    # ========================================================

    def decrypt_file_gui(self):

        input_file = self.file_path.get()
        password = self.file_password.get()
        confirm = self.file_confirm.get()

        if not input_file:

            messagebox.showwarning(
                "Missing File",
                "Please select an encrypted file."
            )

            return

        if not password:

            messagebox.showwarning(
                "Missing Password",
                "Please enter the password."
            )

            return

        if password != confirm:

            messagebox.showerror(
                "Password Error",
                "Passwords do not match."
            )

            return

        filename = os.path.basename(
            input_file
        )

        if filename.endswith(".enc"):
            default_name = filename[:-4]
        else:
            default_name = filename + ".decrypted"

        output_file = filedialog.asksaveasfilename(
            title="Save Decrypted File",
            initialfile=default_name,
            filetypes=[
                ("All files", "*.*")
            ]
        )

        if not output_file:
            return

        try:

            self.file_status.set(
                "Decrypting..."
            )

            self.root.update_idletasks()

            with open(input_file, "rb") as f:
                package = f.read()

            decrypted = decrypt_data(
                package,
                password
            )

            with open(output_file, "wb") as f:
                f.write(decrypted)

            self.file_status.set(
                "Decryption completed."
            )

            messagebox.showinfo(
                "Success",
                "File decrypted successfully!\n\n"
                f"Saved to:\n{output_file}"
            )

        except Exception as e:

            self.file_status.set(
                "Decryption failed."
            )

            if os.path.exists(output_file):

                try:
                    os.remove(output_file)
                except Exception:
                    pass

            messagebox.showerror(
                "Decryption Error",
                str(e)
            )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    root = tk.Tk()

    app = SecureEncryptionApp(root)

    root.mainloop()