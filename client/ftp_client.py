"""
Secure FTP Client
-----------------
This script connects to an FTP server, uploads a randomly chosen file from
a designated local directory, and downloads a randomly chosen file from the server.
"""

import logging
from pathlib import Path
import random
import sys
import time
from typing import List, Optional
from ftplib import FTP, error_perm


class SecureFTPClient:
    """
        SecureFTPClient connects to an FTP server, performs file transfers,
        and handles connection management.

        Class Variables:
            port (int): The port number of the FTP server.
            username (str): Username for FTP authentication.
            password (str): Password for FTP authentication.
            client_dir (Path): Local directory containing files for upload.
            download_dir (Path): Local directory where downloaded files are saved.
        """

    def __init__(self, host: str, port: int, username: str, password: str, upload_directory: str = 'client_files', download_directory: str = 'downloads') -> None:

        # connection parameters
        self.HOST = host
        self.PORT = port
        self.USER = username
        self.PASSWORD = password

        # directory setup
        self.upload_directory = Path(upload_directory)
        self.download_directory = Path(download_directory)
        self.create_directories()
        self.logger = self.setup_logging()

        self.logger.info(f"FTP Client initialized for server {self.HOST}:{self.PORT}")

        # ftp client instance
        self.ftp: Optional[FTP] = None


    def create_directories(self) -> None:
        "Ensuring the upload and download directories exist for the client"
        self.upload_directory.mkdir(exist_ok=True)
        self.download_directory.mkdir(exist_ok=True)

    def setup_logging(self) -> logging.Logger:
        """
           Sets up logging to the console with a detailed formatter.

            Returns:
                A configured Logger instance.
        """

        logger = logging.getLogger("SecureFTPClient")
        logger.setLevel(logging.DEBUG)

        # creating a console logger with info level
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        logging_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

        console_handler.setFormatter(logging_formatter)
        logger.addHandler(console_handler)

        return logger

    def connect_to_server(self, max_retries: Optional[int] = 3) -> bool:
        f"""
            Establishes a connection to the FTP server using the provided credentials and {max_retries}
        """
        max_retries = 3

        for attempt in range(1, max_retries + 1):
            try:
                self.ftp = FTP()
                self.ftp.connect(self.HOST, self.PORT)
                self.ftp.login(self.USER, self.PASSWORD)
                self.logger.info(f"Connected to FTP server at {self.HOST}:{self.PORT}")
                return True
            except Exception as e:
                self.logger.error(f"Connection attempt {attempt} failed: {str(e)}")
                time.sleep(2 ** attempt)
        return False


    def disconnect_server(self) -> None:
        """
            Closes the FTP connection.
        """
        if self.ftp:
            self.ftp.quit()
            self.logger.info("Disconnected from FTP server.")

    def list_files_to_be_uploaded(self) -> List[Path]:
        """
        Lists all files in the local client directory that will be uploaded to the server.

        Returns:
            A list of Paths for each file that have been uploaded to the server.
        """
        if not self.upload_directory.exists():
            self.logger.error(f"Upload directory {self.upload_directory} does not exist.")
            return []
        return [file for file in self.upload_directory.iterdir() if file.is_file()] # return the list of files in the client's upload directory is the file is a file and not a folder

    def upload_a_file(self) -> None:
        """
            Randomly selects a file from the client directory and uploads it to the FTP server.
        """
        files = self.list_files_to_be_uploaded()
        if len(files) == 0:
            self.logger.warning("No files found for upload.")
            return

        file_to_upload = random.choice(files)
        self.logger.info(f"Uploading file: {file_to_upload}")

        try:
            with file_to_upload.open("rb") as file:
                self.ftp.storbinary(f"STOR {file_to_upload.name}", file)
            self.logger.info(f"Successfully uploaded: {file_to_upload.name}")
        except Exception as e:
            self.logger.error(f"Error uploading {file_to_upload.name}: {e}")

    def list_server_files(self) -> List[str]:
        """
            Retrieves the list of files available on the FTP server.

            Returns:
                A list of file names as strings.
        """
        try:
            server_files = self.ftp.nlst()
            self.logger.info(f"Files on server: {server_files}")
            return server_files
        except error_perm as e:
            self.logger.error(f"Permisssion error: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error retrieving list of files on the server: {e}")
            return []


    def download_file_from_sever(self) -> None:
        """
            Randomly selects a file from the FTP server and downloads it
            into the client's download directory.
        """
        server_files = self.list_server_files()
        if not server_files or len(server_files) == 0:
            self.logger.warning("No files available for download.")
            return

        file_to_download = random.choice(server_files)
        download_path = Path.joinpath(self.download_directory, file_to_download)

        try:
            with download_path.open("wb") as file:
                self.ftp.retrbinary(f"RETR {file_to_download}", file.write)
            self.logger.info(f"Successfully downloaded {file_to_download} to {download_path}")
        except Exception as e:
                self.logger.error(f"Error downloading {file_to_download}: {e}")


    def run_client(self) -> None:
        """
            Runs the client operations: connect, upload a file, download a file, then disconnect.
        """
        self.connect_to_server()
        self.upload_a_file()
        self.download_file_from_sever()
        self.upload_a_file()

if __name__ == '__main__':
    try:
        client = SecureFTPClient(host="192.168.56.101", port=2121, username="ftp-user", password="S3cur3P@ss!")
        client.run_client()
    except KeyboardInterrupt as e:
        client.disconnect_server()
        sys.exit(0)
