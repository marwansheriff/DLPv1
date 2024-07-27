import ctypes
import os
import re
import time
import logging
import hashlib
import win32con
import win32file
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b''):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
        return None

class OnMyWatch:
    def __init__(self):
        self.observer = Observer()
        self.drive_paths = []

    def find_usb_drives(self):
        drives = win32file.GetLogicalDrives()
        for drive in range(1, 26):
            mask = 1 << drive
            if drives & mask:
                drive_name = f'{chr(65 + drive)}:\\'
                drive_type = win32file.GetDriveType(drive_name)
                if drive_type == win32con.DRIVE_REMOVABLE:
                    self.drive_paths.append(drive_name)
                    logging.info(f"USB found: {drive_name}")
        if not self.drive_paths:
            logging.info("No USB drives found")
        return self.drive_paths

    def run(self):
        if not self.find_usb_drives():
            return
        event_handler = Handler()
        for drive_path in self.drive_paths:
            self.observer.schedule(event_handler, drive_path, recursive=True)
        self.observer.start()
        logging.info(f"Started monitoring USB drives: {self.drive_paths}")
        try:
            while True:
                time.sleep(2000)
        except KeyboardInterrupt:
            self.observer.stop()
            logging.info("Observer Stopped")
        except Exception as e:
            self.observer.stop()
            logging.error(f"Observer Stopped due to: {e}")

        self.observer.join()


class Handler(FileSystemEventHandler):
    visaregex = r'\d{4}(\s|-)\d{4}(\s|-)\d{4}(\s|-)\d{4}'
    Masterregex = r'\d{4}(\s|-)\d{6}(\s|-)\d{5}'
    known_files_hashes = {}

    def on_created(self, event):
        if not event.is_directory:
            logging.info(f"File created: {event.src_path}")
            print("chek sens")
            self.check_sensitive(event.src_path)
            self.check_if_copied(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            logging.info(f"File modified: {event.src_path}")
            # self.check_sensitive(event.src_path)
            self.check_if_copied(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            logging.info(f"File deleted: {event.src_path}")

    def check_sensitive(self, file_path):
        try:
            print("0")
            file = open(file_path,'r')
            print("1")
            print(file.read())
            print("2")
            for line in file :
            # content = file.read()
                mastercard =bool(re.findall(self.Masterregex, line))
                print("mas " + mastercard)
                visacard = bool(re.findall(self.visaregex, line))
                print("vis " + visacard)


                if mastercard or visacard:
                    logging.warning(f"Sensitive information detected in {file_path}")
                    break
                # Optionally: take further action here (e.g., alerting, logging)
                else:
                    print("nono")
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")

    def check_if_copied(self, file_path):
        file_hash = calculate_file_hash(file_path)
        if file_hash in self.known_files_hashes.values():
            logging.info(f"File copied from PC detected: {file_path}")

    def add_known_file(self, file_path):
        file_hash = calculate_file_hash(file_path)
        if file_hash:
            self.known_files_hashes[file_path] = file_hash

if __name__ == '__main__':
    print(ctypes.windll.shell32.IsUserAnAdmin())
    watch = OnMyWatch()

    # Add known files from PC (Example paths)
    known_files = [r'D:\New folder (2)\testpathfile.txt']
    handler = Handler()
    for file_path in known_files:
        handler.add_known_file(file_path)

    watch.run()
