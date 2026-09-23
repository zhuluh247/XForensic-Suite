import os
from pathlib import Path
from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from PIL import Image
import numpy as np
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from core.utils import UPLOAD_DIR

router = APIRouter(prefix="/api/stego", tags=["XStegoCover"])

# Helper to derive a stable encryption key from a user password
def _get_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@router.post("/hide")
async def hide_data(
    file: UploadFile = File(...),
    secret_text: str = Form(...),
    password: str = Form(None)
):
    """
    Encrypts user text (AES with optional password) and embeds ciphertext into image LSB pixel color channels[cite: 1].
    """
    temp_input_path = None
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        safe_filename = os.path.basename(file.filename)
        temp_input_path = UPLOAD_DIR / f"temp_{safe_filename}"
        
        image_bytes = await file.read()
        with open(temp_input_path, "wb") as f:
            f.write(image_bytes)

        img = Image.open(temp_input_path).convert("RGB")
        width, height = img.size
        img_arr = np.array(img)

        # Handle Encryption & Payload packaging
        if password and password.strip() != "":
            salt = os.urandom(16)
            key = _get_key_from_password(password, salt)
            f_cipher = Fernet(key)
            token = f_cipher.encrypt(secret_text.encode())
            payload = salt + token  # Prefix with salt for password-based derivation
        else:
            key = Fernet.generate_key()  # 44 bytes b64 encoded key
            f_cipher = Fernet(key)
            token = f_cipher.encrypt(secret_text.encode())
            payload = key + token        # Prefix with raw key for passwordless auto-decrypt

        # Convert payload length + payload bytes to binary string
        binary_payload = ''.join(format(byte, '08b') for byte in payload)
        binary_payload += '00000000000000000000000000000000' # 32-bit termination marker

        total_pixels = width * height * 3
        if len(binary_payload) > total_pixels:
            if os.path.exists(temp_input_path):
                os.remove(temp_input_path)
            raise HTTPException(status_code=400, detail="Image is too small to hold this secret text payload.")

        flat_img = img_arr.flatten()
        for i in range(len(binary_payload)):
            flat_img[i] = (flat_img[i] & ~1) | int(binary_payload[i])

        modified_img_arr = flat_img.reshape((height, width, 3))
        output_img = Image.fromarray(modified_img_arr.astype('uint8'), 'RGB')
        
        output_filename = f"stego_{safe_filename.split('.')[0]}.png"
        output_path = UPLOAD_DIR / output_filename
        output_img.save(output_path, "PNG")
        
        if os.path.exists(temp_input_path):
            os.remove(temp_input_path)

        return {
            "status": "success",
            "message": "Payload embedded successfully via LSB steganography.",
            "download_url": f"/api/stego/download/{output_filename}"
        }
    except Exception as e:
        if temp_input_path and os.path.exists(temp_input_path):
            os.remove(temp_input_path)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{filename}")
async def download_stego_image(filename: str):
    file_path = UPLOAD_DIR / filename
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="image/png", filename=filename)
    raise HTTPException(status_code=404, detail="File not found.")

@router.post("/reveal")
async def reveal_data(
    file: UploadFile = File(...),
    password: str = Form(None)
):
    """
    Scans carrier image to extract LSB payloads and decrypt/reveal secret text[cite: 1].
    """
    temp_path = None
    try:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        
        image_bytes = await file.read()
        safe_filename = os.path.basename(file.filename)
        temp_path = UPLOAD_DIR / f"scan_{safe_filename}"
        
        with open(temp_path, "wb") as f:
            f.write(image_bytes)

        img = Image.open(temp_path).convert("RGB")
        flat_img = np.array(img).flatten()
        if os.path.exists(temp_path):
            os.remove(temp_path)

        # Extract bits
        extracted_bits = []
        for val in flat_img:
            extracted_bits.append(str(val & 1))
        
        binary_str = ''.join(extracted_bits)
        bytes_list = []
        
        for i in range(0, len(binary_str), 8):
            byte_str = binary_str[i:i+8]
            if len(byte_str) < 8:
                break
            byte_val = int(byte_str, 2)
            bytes_list.append(byte_val)
            if len(bytes_list) >= 4 and bytes_list[-4:] == [0, 0, 0, 0]:
                bytes_list = bytes_list[:-4]
                break

        if not bytes_list:
            return {"verdict": "Standard Clean Image. No steganographic signatures detected."}

        full_payload = bytes(bytes_list)
        
        try:
            if password and password.strip() != "":
                salt = full_payload[:16]
                token = full_payload[16:]
                key = _get_key_from_password(password, salt)
            else:
                # Extract the auto-bundled 44-byte Fernet key prefix
                key = full_payload[:44]
                token = full_payload[44:]

            f_cipher = Fernet(key)
            decrypted_text = f_cipher.decrypt(token).decode()

            return {
                "verdict": "Payload Recovered Successfully",
                "secret_text": decrypted_text
            }
        except Exception:
            return {
                "verdict": "Data detected, but decryption failed. Incorrect password or invalid key format."
            }

    except Exception as e:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=500, detail=str(e))