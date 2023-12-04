"""
File Encryption App

Author: OT
Version: 1.0
Date: Dec 3rd, 2023

Description:
This module implements a simple GUI application for text file encryption and decryption using Python and the
cryptography library. The application utilizes Tkinter for the graphical interface and Fernet symmetric encryption
for secure file handling. Users can select a text file, choose between encryption and decryption options, and
perform operations with the provided encryption key. The application supports key generation, loading, and storage
for enhanced security.

Dependencies:
- Python 3.x
- Tkinter
- cryptography

Note: Ensure that the 'cryptography' library is installed using 'pip install cryptography'.

Usage:
- Run the script to launch the graphical user interface.
- Follow on-screen prompts to select a text file, choose an operation, and provide the necessary encryption key.

For additional functionality and best practices, refer to the docstrings within the code.

Disclaimer: This application is intended for educational purposes and should be used responsibly and ethically.
"""

# Imports
import os
import logging
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
from logging.handlers import RotatingFileHandler

# Local modules


class FileEncryptionApp(object):
    def __init__(self, master: tk.Tk):
        """
        Initialize the FileEncryptionApp.

        :param master: The main window.
        """
        self.master = master
        master.title(f"Text File Encryption/Decryption")

        # Load and set application icon
        icon_image = Image.open(f"encryption_icon.png")
        icon_image = ImageTk.PhotoImage(icon_image)
        master.tk.call("wm", "iconphoto", master._w, icon_image)

        # Logger configuration
        self.logger = self.setup_logger()

        # Check if key file exists, generate one if not
        self.key_file_path = f"encryption_key.key"
        if not self.key_exists():
            self.generate_key()

        # Load key from file
        self.key = self.load_key()

        # GUI components
        self.label_file_path = tk.Label(master, text="File Path:")
        self.entry_file_path = tk.Entry(master, width=50)
        self.button_browse = tk.Button(master, text="Browse", command=self.browse_file, bg='light gray')

        # self.label_key = tk.Label(master, text="Key:")
        # self.entry_key = tk.Entry(master, show="*")

        self.label_operation = tk.Label(master, text="Choose an option:")
        self.var = tk.StringVar()
        self.var.set("1")  # default value
        self.radio_encrypt = tk.Radiobutton(master, text="Encrypt", variable=self.var, value="1")
        self.radio_decrypt = tk.Radiobutton(master, text="Decrypt", variable=self.var, value="2")

        self.button_execute = tk.Button(master, text="Execute", command=self.execute_operation, fg="white", bg="green")
        self.result_label = tk.Label(master, text="")

        # Layout
        self.label_file_path.grid(row=0, column=0, sticky=tk.E, padx=5, pady=5)
        self.entry_file_path.grid(row=0, column=1, columnspan=2, pady=5)
        self.button_browse.grid(row=0, column=3, pady=5, padx=5)

        # self.label_key.grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
        # self.entry_key.grid(row=1, column=1, columnspan=2, pady=5)

        self.label_operation.grid(row=1, column=0, sticky=tk.E, padx=5, pady=5)
        self.radio_encrypt.grid(row=1, column=1, pady=5)
        self.radio_decrypt.grid(row=1, column=2, pady=5)

        self.button_execute.grid(row=2, column=0, columnspan=4, pady=10)
        self.result_label.grid(row=3, column=0, columnspan=4, pady=10)

    def __repr__(self):
        return f"FileEncryptionApp(master={self.master})"

    def setup_logger(self) -> logging:
        """
        Create and configure a logging instance for the application.

        :return: Configured logging instance.
        """
        try:
            # Logger configuration for console and file
            logger = logging.getLogger(f"file_encryption_app")
            logger.setLevel(logging.DEBUG)

            # Create a formatter
            formatter = logging.Formatter(f'%(asctime)s - %(levelname)s - %(message)s')

            # Configure the console controller
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)

            # Configure the file controller
            file_handler = RotatingFileHandler(f"file_encryption_app.log", maxBytes=100000, backupCount=1)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

            return logger
        except Exception as e:
            self.logger.error(f"Error configuring logger: {e}")

    def generate_key(self) -> None:
        """
        Generate a new encryption key and save it to a file.

        This method is called during the initial setup if no key file exists.
        """
        try:
            # Generate a new key
            key = Fernet.generate_key()

            # Save the key to a file
            with open(self.key_file_path, 'wb') as key_file:
                key_file.write(key)

            return
        except Exception as e:
            self.logger.error(f"Error generating key: {e}")

    def load_key(self) -> bytes:
        """
        Load the encryption key from the key file.

        :return: The encryption key.
        """
        try:
            # Load the key from the file
            with open(self.key_file_path, 'rb') as key_file:
                key = key_file.read()
            return key
        except Exception as e:
            self.logger.error(f"Error loading key: {e}")

    def key_exists(self) -> bool:
        """
        Check if the key file exists.

        :return: True if the key file exists, False otherwise.
        """
        try:
            with open(self.key_file_path, 'rb'):
                pass
            return True
        except FileNotFoundError:
            return False

    def browse_file(self) -> None:
        """
        Open a file dialog to allow the user to select a text file.

        Updates the entry field with the selected file path.
        """
        try:
            file_path = filedialog.askopenfilename(title="Select a text file")
            self.entry_file_path.delete(0, tk.END)
            self.entry_file_path.insert(0, file_path)
            return
        except Exception as e:
            self.logger.error(f"Error browsing file: {e}")

    def encrypt_file(self, file_path: str) -> bool:
        """
        Encrypt the specified file using the loaded encryption key.

        :param file_path: The path of the file to be encrypted.
        :return: True if the encryption is successful, False otherwise.
        """
        try:
            # Read original file
            with open(file_path, 'rb') as file:
                data = file.read()

            # Get key and encrypt data
            cipher = Fernet(self.key)
            encrypted_data = cipher.encrypt(data)

            # Write encrypted data to a new file
            with open(file_path + ".encrypted", 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)

            # Delete original file
            os.remove(file_path)

            return True
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            return False

    def decrypt_file(self, file_path: str) -> bool:
        """
        Decrypt the specified file using the loaded encryption key.

        :param file_path: The path of the file to be decrypted.
        :return: True if the decryption is successful, False otherwise.
        """
        try:
            # Read encrypted file
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            # Get key and decrypt data
            cipher = Fernet(self.key)
            decrypted_data = cipher.decrypt(encrypted_data)

            # Write decrypted data to a new file
            with open(file_path.replace(".encrypted", ""), 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            # Delete encrypted file
            os.remove(file_path)

            return True
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            return False

    def execute_operation(self) -> None:
        """
        Execute the selected encryption or decryption operation based on user input.

        Uses the selected option (encrypt or decrypt) and the specified file path.
        Updates the result label with the outcome of the operation.
        """
        try:
            file_path = self.entry_file_path.get()
            option = self.var.get()

            if file_path and option in ["1", "2"]:
                success = False

                if option == "1":
                    success = self.encrypt_file(file_path)
                elif option == "2":
                    success = self.decrypt_file(file_path)

                if success:
                    self.result_label.config(text="Operation completed successfully.", fg='green')
                else:
                    self.result_label.config(text="Error during operation.", fg='red')
            else:
                self.result_label.config(text="Invalid input. Please fill all fields.", fg='orange')

            return
        except Exception as e:
            self.logger.error(f"Error executing operation: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptionApp(root)
    print(app)
    root.mainloop()
