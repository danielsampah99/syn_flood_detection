"""
FTP SERVER
Sets up an FTP Server that allows upload and download of files
"""

import logging
from pathlib import Path
from typing import ClassVar

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


class SecureFTPServer:
    """
    Class Variables:
        FTP_ROOT: Absolute root path to the server's location
        FTP_PORT: Port number on which the server will run
        USER_CREDENTIALS: A mapping of username and password
    """

    # Server configuration
    FTP_ROOT: ClassVar[Path] = Path("ftp_files").resolve()  # making the path absolute
    FTP_PORT: ClassVar[int] = 2121  # choosing this port because it is non privileged
    USER_CREDENTIALS: ClassVar[dict[str, str]] = {"ftp-user": "Secure-password@1234"}

    def __init__(self) -> None:
        """
        Initializes the SecureFTPServer instance.
        Sets up logging, configures the user authorizer, the FTP handler, and creates the server.
        """

        self.logger = self.setup_logging()
        self.logger.info("Initializing the secure FTP Server")
        self.authorizer = self.create_authorizer()
        self.handler = self.create_handler()
        self.server = FTPServer(("0.0.0.0", self.FTP_PORT), self.handler)

    def setup_logging(self) -> logging.Logger:
        """
        Sets up a robust logging system that logs both to the console and a file.
        Returns:
            A configured logger instance.
        """

        logger: logging.Logger = logging.getLogger("FTP Server")
        logger.setLevel(logging.DEBUG)

        # console handler for general information
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)

        # file handler to log detailed general information
        file_handler = logging.FileHandler("ftp_server.log")
        file_handler.setLevel(logging.DEBUG)

        #  Formatter for logging messages
        logging_format = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        console_handler.setFormatter(logging_format)
        file_handler.setLevel(logging.DEBUG)

        # Adding the handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)

        return logger

    def create_authorizer(self) -> DummyAuthorizer:
        """
        Creates and configures an authorizer for the FTP server.
        This includes ensuring that the FTP root exists and adding user credentials.

        Returns:
            A DummyAuthorizer instance with the configured users.
        """

        authorizer = DummyAuthorizer()

        # Ensuring the ftp root directory exists and creating it if it doesn't
        if not self.FTP_ROOT.exists():
            self.FTP_ROOT.mkdir(exist_ok=True, parents=True)
            self.logger.info(f"FTP root directory created at {self.FTP_ROOT}")

        # add users in the credentials directory
        for user, password in self.USER_CREDENTIALS.items():
            try:
                # Grant full permissions to the user ("elradfmwMT")
                authorizer.add_user(
                    username=user, password=password, homedir=str(self.FTP_ROOT), perm="elradfmwMT", msg_login='Login was successful', msg_quit="Goodbye"
                )

                self.logger.info(f"Added user: {user}, with home directory: {self.FTP_ROOT}")
            except Exception as e:
                self.logger.error(f"Error: {e}\t. Failed to add user: {user}, with home directory: {self.FTP_ROOT}")

        return authorizer

    def create_handler(self) -> FTPHandler:
        """
        Configures the FTPHandler with the authorizer and additional settings.

        Returns:
            A customized FTPHandler class.
        """

        # assign the handler to the authorizer
        handler = FTPHandler
        handler.authorizer = self.authorizer

        # set passive ports for easy traversal
        handler.passive_ports = range(60000, 65535)

        # setting a custom banner to display a message when a user connects
        handler.banner = "Welcome to the Secure FTP Server. Authorized access only."

        return handler

    def start_server(self) -> None:
        """
        Starts the FTP server and logs runtime events.
        The server will run indefinitely until an error occurs or it is stopped.
        """

        try:
            self.logger.info("Starting FTP Server\n\t Ready to accept connections")
            self.server.serve_forever()
        except KeyboardInterrupt as error:
            self.logger.error(f"Server shutting down: {error}")
            self.server.close_all()


def main() -> None:
    """
    Entry point for the FTP server application.
    Instantiates the SecureFTPServer and starts it.
    """

    ftp_server = SecureFTPServer()
    ftp_server.start_server()


if __name__ == "__main__":
    main()
