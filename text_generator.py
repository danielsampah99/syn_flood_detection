"""
SECURE FILE GENERATOR
Create random text files with cryptographically secure content
"""

import secrets
from pathlib import Path
from typing import Optional, Union


def generate_secure_files(
    number_of_files: int, base_directory: Union[str, Path] = "ftp_files", min_file_size: int = 512, max_file_size: int = 4096
) -> Optional[list[Path]]:
    """
    Returns: List of created file Path objects or None on failure
    """

    created_files: list[Path] = []

    try:
        # determine the output path
        output_path = Path(base_directory) if isinstance(base_directory, str) else base_directory

        # create the output path now that it's figured
        output_path.mkdir(exist_ok=True, parents=True)

        for _ in range(number_of_files):
            # generate cryptographically secure content
            file_size: int = secrets.randbelow(max_file_size - min_file_size) + min_file_size
            file_content: bytes = secrets.token_bytes(file_size)

            # generate a unique file name for each file
            file_name: str = f"file_{secrets.token_hex(4)}.txt"
            file_path: Path = output_path / file_name

            # write the file to the disk with atomic replace
            with open(file_path, "wb") as file:
                file.write(file_content)

            created_files.append(file_path)
            print(f"Created: {file_path}")

        return created_files

    except (IOError, PermissionError) as e:
        print(f"File creation failed: {e}")
        return None


if __name__ == "__main__":
    result: Optional[list[Path]] = generate_secure_files(15)
    if result:
        print(f"Generated {len(result)} files")
