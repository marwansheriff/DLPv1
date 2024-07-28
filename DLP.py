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
from Handler import *  # Ensure your Handler class is in handler.py

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])

SECURE_TEMP_DIR = "D:\\secure"


def calculate_file_hash(file_path):
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
    def __init__(self, known_file):

        self.observer = Observer()
        self.known_files = known_file
        self.drive_paths = []
        self.event_handler = Handler()

        for file_path in self.known_files:
            self.event_handler.add_known_file(file_path)

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
        while not self.find_usb_drives():
            time.sleep(3)
        for drive_path in self.drive_paths:
            self.observer.schedule(self.event_handler, drive_path, recursive=False)
        self.observer.start()
        logging.info(f"Started monitoring USB drives: {self.drive_paths}")
        try:
            while True:
                time.sleep(4)
        except KeyboardInterrupt:
            self.observer.stop()
            logging.info("Observer Stopped")
        except Exception as e:
            self.observer.stop()
            logging.error(f"Observer Stopped due to: {e}")

        self.observer.join()


if __name__ == '__main__':
    if not os.path.exists(SECURE_TEMP_DIR):
        os.makedirs(SECURE_TEMP_DIR)

    if not ctypes.windll.shell32.IsUserAnAdmin():
        logging.error("You need to run this script as an administrator.")
        exit(1)


    def get_all_file_paths(folder_path):
        file_paths = []
        for root, directories, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                file_paths.append(file_path)
        return file_paths

    known_files=get_all_file_paths("D:\\New folder (2)")
    print(known_files)
    watch = OnMyWatch(known_files)
    watch.run()
