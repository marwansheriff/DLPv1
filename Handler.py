import logging
import os
import re
import shutil
import time

from cryptography.fernet import Fernet
from watchdog.events import FileSystemEventHandler
from DLP import calculate_file_hash, SECURE_TEMP_DIR

class Handler(FileSystemEventHandler):
    visaregex = r'\d{4}(\s|-)\d{4}(\s|-)\d{4}(\s|-)\d{4}'
    Masterregex = r'\d{4}(\s|-)\d{6}(\s|-)\d{5}'
    known_files_hashes = {}
    encryption_key = Fernet.generate_key()
    cipher_suite = Fernet(encryption_key)
    processed_files =[]
    detection=0
    switch=False

    def on_created(self, event):
        print("ccccc")
        if self.switch:
            self.switch=False
        else:
            self.switch=True
        if not event.is_directory and (str(event.src_path) not in self.processed_files) and self.switch:
            self.processed_files.append(str(event.src_path))
            print("processdfiles ")
            print(self.processed_files)
            print("event.src_path "+ event.src_path)
            logging.info(f"File created: {event.src_path}")
            temp_path = os.path.join(SECURE_TEMP_DIR, os.path.basename(event.src_path))
            print(event.src_path)
            print(temp_path)
            self.move_file_with_retry(event.src_path, temp_path)

            if self.check_if_copied(temp_path):
                if self.check_sensitive(temp_path):
                    self.encrypt_file(temp_path)

                    self.move_file_with_retry(temp_path, event.src_path)
                else:
                    print("s re fals "+ event.src_path)

                    self.move_file_with_retry(temp_path, event.src_path)


    # def on_deleted(self, event):
    #
    #     if not event.is_directory:
    #         logging.info(f"File deleted: {event.src_path}")
    #         if event.src_path in self.processed_files:
    #             self.processed_files.remove(event.src_path)
    #             # Recreate the file to prevent deletion
    #         with open(event.src_path, 'w') as file:
    #             file.write("")
    #         logging.info(f"File recreated to prevent deletion: {event.src_path}")

    def check_sensitive(self, file_path):
        try:
            with open(file_path, 'r+') as file:
                for line in file:
                    print(line)
                    if re.findall(self.Masterregex, line) or re.findall(self.visaregex, line):
                        print("file sens")
                        # os.remove(file_path)
                        self.encrypt_file(file_path)
                        logging.warning(f"Sensitive information detected in {file_path}")

                        return True
                return False
        except OSError as e:
            logging.error(f"OS error reading file {file_path}: {e}")
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")

    def check_if_copied(self, file_path):
        file_hash = calculate_file_hash(file_path)
        if file_hash in self.known_files_hashes.values():
            logging.info(f"File copied from PC detected: {file_path}")
            return True
        else:
            return False

    def add_known_file(self, file_path):
        file_hash = calculate_file_hash(file_path)
        if file_hash:
            self.known_files_hashes[file_path] = file_hash

    def encrypt_file(self, file_path):
        try:
            with open(file_path, 'rb') as file:
                file_data = file.read()
            encrypted_data = self.cipher_suite.encrypt(file_data)
            with open(file_path, 'wb') as file:
                file.write(encrypted_data)
            logging.info(f"File encrypted: {file_path}")
        except Exception as e:
            logging.error(f"Error encrypting file {file_path}: {e}")

    def move_file_with_retry(self, src, dst, retries=5, delay=0.1):
        """Try to move the file with retries if it fails due to being used by another process."""
        for _ in range(retries):
            try:
                shutil.move(src, dst)
                logging.info(f"File moved from {src} to {dst}")
                return
            except PermissionError:
                logging.warning(f"PermissionError: File {src} is in use, retrying...")
                time.sleep(delay)
        logging.error(f"Failed to move file {src} to {dst} after {retries} retries")