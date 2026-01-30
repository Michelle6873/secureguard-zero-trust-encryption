"""
SecureGuard
Zero-Trust Endpoint File Encryption Tool

Encrypts files in-place with tamper detection and audit logging.
"""

import os
import base64
import logging # for recording logs - industry standards
import datetime
import argparse
import getpass  # Takes password input, Does NOT show characters
from cryptography.fernet import Fernet #this is for the actual encryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

#this is just for a gui
try:
	from tkinter import Tk
	from tkinter.filedialog import askopenfilename
	GUI_AVAILABLE = True
except ImportError:
	GUI_AVAILABLE = False



logging.basicConfig(
    filename="vault_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_event(message):
    logging.info(message)
    print(message)


#checking if the file actually exists before trying to read it
def file_exists(filename):
    try:
        with open(filename, "rb"):
            return True
    except FileNotFoundError:
        return False



def make_key(password, salt):
#standard key setup
	kdf = PBKDF2HMAC(
	algorithm=hashes.SHA256(),
	length=32,
	salt=salt,
	iterations=100000,
	)

	return base64.urlsafe_b64encode(
		kdf.derive(password.encode())
		)
	


def encrypt_file(filename, password):
	salt = os.urandom(16)
	key = make_key(password, salt)
	fernet = Fernet(key)

	with open(filename, "rb") as f:
		data = f.read()

	encrypted = fernet.encrypt(data)

	with open(filename, "wb") as f:
		f.write(salt + encrypted)
	log_event(f"File encrypted {filename}")



def decrypt_file(filename, password):
	with open(filename, "rb") as f:
		data = f.read()
	salt = data[:16]
	encrypted = data[16:]
	key = make_key(password, salt)
	fernet = Fernet(key)

	try:
		decrypted = fernet.decrypt(encrypted)
	except Exception:
		log_event("ERROR: Tampering detected or wrong password")
		print("Decryption failed. File may be tampered with.")
		return


	with open(filename, "wb") as f:
		f.write(decrypted)


	log_event(f"File decrypted: {filename}")



def select_file_gui():
    if not GUI_AVAILABLE:
        print("GUI not available. Please type the file path.")
        return None
    Tk().withdraw()  
    filename = askopenfilename(title="Select a file")
    return filename



def main():
	log_event("starting...")

	# Choose CLI or GUI
	use_gui = input("Do you want to use GUI to select file? (yes/no): ").strip().lower()
	if use_gui == "yes" and GUI_AVAILABLE:
		filename = select_file_gui()
		if not filename:
			print("No file selected.")
			return
	else:
		filename = input("Enter full path to the file: ").strip()

	if not file_exists(filename):
		log_event(f"ERROR: File not found - {filename}")
		print("File does not exist.")
		return


	action = input("Do you want to 'encrypt' or 'decrypt'? ").strip().lower()

	password = getpass.getpass("enter your password")

	log_event(f"User chose to {action} the file {filename}")


	if action == "encrypt":
		encrypt_file(filename, password)

	elif action == "decrypt":
		decrypt_file(filename, password)

	else :
		print("Invalid Choice")


if __name__ == "__main__":
	main()











