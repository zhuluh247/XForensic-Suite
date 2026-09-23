import os
from pathlib import Path
import tempfile

# Use current working directory with an automatic system temp fallback 
# to completely prevent Windows multiprocessing WinError 2 spawn crashes.
try:
    BASE_DIR = Path(os.getcwd())
    UPLOAD_DIR = BASE_DIR / "uploads"
    os.makedirs(str(UPLOAD_DIR), exist_ok=True)
except Exception:
    # Guaranteed fallback if Windows blocks local directory spawning
    UPLOAD_DIR = Path(tempfile.gettempdir()) / "xforensics_uploads"
    os.makedirs(str(UPLOAD_DIR), exist_ok=True)

def get_file_path(filename: str) -> Path:
    os.makedirs(str(UPLOAD_DIR), exist_ok=True)
    return UPLOAD_DIR / filename