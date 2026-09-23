import os
import math
import hashlib
import json
import re
import zipfile
import io
from datetime import datetime, timezone
from fastapi import APIRouter, UploadFile, File, HTTPException
from pydantic import BaseModel
import requests

router = APIRouter(prefix="/api/malware", tags=["XMalInspect"])

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    "url": r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\.-]*",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "btc_wallet": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|^(bc1)[0-9a-z]{39,59}$",
    "eth_wallet": r"\b0x[a-fA-F0-9]{40}\b"
}

SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualProtect", "CreateRemoteThread", "WriteProcessMemory", 
    "InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "WinExec", 
    "ShellExecuteA", "RegSetValueExA", "CreateProcessA", "WNetOpenEnumA",
    "android/content/Intent", "Ljava/lang/Runtime;", "DexClassLoader"
]

SUSPICIOUS_KEYWORDS = [
    "eval", "exec", "powershell", "cmd.exe", "wscript", "rundll32", 
    "regsvr32", "base64", "AutoOpen", "Workbook_Open", "Document_Open", 
    "JS/", "ActiveXObject", "ADODB.Stream", "Shell.Application", "hta", "MSHTA",
    "AndroidManifest.xml", "classes.dex", "su", "supersu", "payload"
]

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    data_len = len(data)
    frequencies = {}
    for byte in data:
        frequencies[byte] = frequencies.get(byte, 0) + 1
    for count in frequencies.values():
        p_x = count / data_len
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)

def extract_strings(data: bytes, min_len: int = 4) -> str:
    """Extracts printable ASCII and UTF-8 strings from arbitrary binary streams."""
    pattern = b"[\x20-\x7e]{" + str(min_len).encode() + b",}"
    matches = re.findall(pattern, data)
    return "\n".join([m.decode('latin1', errors='ignore') for m in matches])

def detect_universal_file_type(header: bytes, filename: str) -> tuple:
    ext = filename.split('.')[-1].lower() if '.' in filename else ""
    
    if ext == 'apk' or (header.startswith(b"PK\x03\x04") and "AndroidManifest.xml" in filename.lower()):
        return "Android Application Package (.APK)", "apk"
    elif ext == 'hta' or b"<hta:application" in header.lower() or b"application/hta" in header.lower():
        return "HTML Application / Script Dropper (.HTA)", "hta"
    elif header.startswith(b"MZ"):
        return "PE Executable (Windows Binary)", "exe"
    elif header.startswith(b"%PDF"):
        return "PDF Document", "pdf"
    elif header.startswith(b"PK\x03\x04"):
        if "word/" in filename.lower() or "xl/" in filename.lower() or filename.endswith(('.docx', '.xlsx', '.pptx')):
            return "Microsoft Office OpenXML Container", "office_xml"
        return "ZIP Archive / Compressed Container", "zip"
    elif header.startswith(b"\xD0\xCF\x11\xE0"):
        return "Legacy Microsoft Office (OLE Compound Document)", "ole"
    elif header.startswith(b"\x7fELF"):
        return "ELF Executable (Linux Binary)", "elf"
    
    if ext in ['py', 'js', 'ps1', 'sh', 'bat', 'vbs', 'wsf', 'rb', 'json', 'xml', 'txt', 'html']:
        return f"Script / Text Source File ({ext.upper()})", ext
    
    return "Generic Binary / Unknown Stream", "bin"

@router.post("/inspect")
async def inspect_file(file: UploadFile = File(...)):
    file_bytes = await file.read()
    filename = file.filename or "unknown_sample"
    file_size = len(file_bytes)

    md5_hash = hashlib.md5(file_bytes).hexdigest()
    sha1_hash = hashlib.sha1(file_bytes).hexdigest()
    sha256_hash = hashlib.sha256(file_bytes).hexdigest()

    header_bytes = file_bytes[:64]
    file_type_desc, format_category = detect_universal_file_type(header_bytes, filename)

    entropy = calculate_entropy(file_bytes)
    
    packing_status = "Normal / Low Entropy"
    if format_category == "pdf":
        if entropy > 7.5:
            packing_status = "Normal PDF Compression (Streams / Fonts)"
    else:
        if entropy > 7.2:
            packing_status = "CRITICAL: Highly Packed, Compressed, or Encrypted (Potential Ransomware/Packer)"
        elif entropy > 6.5:
            packing_status = "SUSPICIOUS: Moderate-High Entropy (Possible Obfuscation)"

    # Universal Content Ingestion (Text decoding + Binary String Mining + Archive Extraction)
    file_text = ""
    try:
        file_text = file_bytes.decode('utf-8', errors='ignore')
    except Exception:
        pass

    # If text is too short or binary, extract raw strings
    extracted_strings_blob = ""
    if len(file_text.strip()) < 50 or format_category in ["exe", "elf", "bin", "apk"]:
        extracted_strings_blob = extract_strings(file_bytes)
        file_text += "\n\n--- Extracted Binary Strings ---\n" + extracted_strings_blob

    archive_contents = []
    structural_notes = []

    # Universal Recursive Container Unpacking (ZIP, APK, Office XML)
    if format_category in ["zip", "office_xml", "apk"]:
        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                archive_contents = zf.namelist()
                extracted_inner_texts = []
                for inner_filename in archive_contents:
                    try:
                        with zf.open(inner_filename) as inner_file:
                            inner_bytes = inner_file.read()
                            inner_text = inner_bytes.decode('utf-8', errors='ignore')
                            if len(inner_text.strip()) < 20:
                                inner_text = extract_strings(inner_bytes)
                            extracted_inner_texts.append(f"--- Container Asset [{inner_filename}] ---\n{inner_text}")
                    except Exception:
                        pass
                if extracted_inner_texts:
                    file_text += "\n\n" + "\n".join(extracted_inner_texts)
                    structural_notes.append(f"Successfully unpacked and analyzed {len(archive_contents)} assets from container.")
        except Exception as e:
            structural_notes.append(f"Container unpacking warning: {str(e)}")

    extracted_iocs = {
        "ipv4": [],
        "urls": [],
        "emails": [],
        "btc_wallets": [],
        "eth_wallets": []
    }
    
    found_apis = []
    found_keywords = []

    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(re.findall(pattern, file_text)))
        if matches:
            if ioc_type == "ipv4": extracted_iocs["ipv4"] = matches[:15]
            elif ioc_type == "url": extracted_iocs["urls"] = matches[:15]
            elif ioc_type == "email": extracted_iocs["emails"] = matches[:10]
            elif ioc_type == "btc_wallet": extracted_iocs["btc_wallets"] = matches[:5]
            elif ioc_type == "eth_wallet": extracted_iocs["eth_wallets"] = matches[:5]

    for api in SUSPICIOUS_APIS:
        if api.lower() in file_text.lower():
            found_apis.append(api)

    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in file_text.lower():
            found_keywords.append(kw)

    if format_category == "hta":
        structural_notes.append("HTML Application (.HTA) container identified. Executes with full system privileges.")
    elif format_category == "apk":
        structural_notes.append("Android Package (.APK) identified. Evaluated for permissions, manifest components, and DEX bytecode.")
    elif format_category == "exe":
        structural_notes.append("Windows PE Executable identified. Evaluated via imported APIs and binary strings.")
    elif format_category == "elf":
        structural_notes.append("Linux ELF Executable identified. Evaluated via binary structure and symbol strings.")

    ai_verdict = None
    ai_risk_score = None
    ai_briefing = []

    telemetry_payload = {
        "filename": filename,
        "file_size_bytes": file_size,
        "sha256": sha256_hash,
        "detected_format": file_type_desc,
        "shannon_entropy": entropy,
        "packing_analysis": packing_status,
        "suspicious_apis": found_apis,
        "suspicious_keywords": found_keywords,
        "extracted_iocs": extracted_iocs,
        "archive_contents": archive_contents[:50],
        "structural_notes": structural_notes,
        "full_content_dump": file_text[:15000] # Full extracted text, strings, and container contents fed to AI
    }

    if OPENROUTER_API_KEY and OPENROUTER_API_KEY.strip() != "":
        try:
            headers = {
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "XForensic Suite",
                "Content-Type": "application/json"
            }
            prompt = f"""
            You are an elite Senior Malware Reverse Engineer and Principal SOC Threat Intelligence Analyst. 
            Examine the following universal file telemetry, extracted strings, container contents, and source code. Determine the true nature of this file (whether it is an APK, PE executable, ELF binary, archive, script, or benign document) and provide a professional behavioral assessment.

            File Telemetry & Contents:
            {json.dumps(telemetry_payload, indent=2)}

            Instructions for your behavioral briefing:
            1. Identify the file category and evaluate whether it is malicious, suspicious, or clean based entirely on its internal contents and extracted strings.
            2. Detail the execution mechanics, permissions, API calls, or script commands found within.
            3. Analyze extracted IOCs and assess risk with clear mitigation steps.

            Return ONLY valid JSON in this exact structure:
            {{
              "verdict": "MALICIOUS" | "SUSPICIOUS" | "CLEAN",
              "risk_score_percentage": "XX%",
              "behavioral_briefing": [
                "Detailed paragraph 1 covering format identification and structural analysis...",
                "Detailed paragraph 2 covering execution behavior, internal assets, or API/script logic...",
                "Detailed paragraph 3 covering risk assessment, network IOCs, and final verdict conclusion..."
              ]
            }}
            """
            body = {
                "model": "openrouter/free",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1
            }
            res = requests.post("https://openrouter.ai/api/v1/chat/completions", headers=headers, json=body, timeout=25)
            
            if res.status_code == 200:
                res_data = res.json()
                content = res_data["choices"][0]["message"]["content"].strip()
                if content.startswith("```json"):
                    content = content[7:-3].strip()
                elif content.startswith("```"):
                    content = content[3:-3].strip()
                
                ai_data = json.loads(content)
                ai_verdict = ai_data.get("verdict")
                ai_risk_score = ai_data.get("risk_score_percentage")
                ai_briefing = ai_data.get("behavioral_briefing", [])
            else:
                print(f"OpenRouter API Error in XMalInspect [{res.status_code}]: {res.text}")
        except Exception as e:
            print(f"OpenRouter API Exception in XMalInspect: {str(e)}")
            structural_notes.append(f"AI OpenRouter exception: {str(e)}")

    if not ai_verdict:
        calc_score = 10 if format_category == "pdf" else 30
        if format_category in ["hta", "exe", "elf", "apk"]: calc_score += 40
        if extracted_iocs["urls"]: calc_score += 20
        if found_keywords: calc_score += 20
        calc_score = min(calc_score, 100)
        
        ai_risk_score = f"{calc_score}%"
        if calc_score >= 50:
            ai_verdict = "MALICIOUS"
        elif calc_score >= 25:
            ai_verdict = "SUSPICIOUS"
        else:
            ai_verdict = "CLEAN"
        ai_briefing = structural_notes

    return {
        "filename": filename,
        "file_size_bytes": file_size,
        "hashes": {
            "md5": md5_hash,
            "sha1": sha1_hash,
            "sha256": sha256_hash
        },
        "detected_file_type": file_type_desc,
        "shannon_entropy": entropy,
        "entropy_analysis": packing_status,
        "risk_score_percentage": ai_risk_score,
        "verdict": ai_verdict,
        "suspicious_apis_detected": found_apis if found_apis else ["No critical system APIs flagged"],
        "suspicious_keywords_detected": found_keywords if found_keywords else ["No malicious keywords flagged"],
        "extracted_iocs": extracted_iocs,
        "archive_contents": archive_contents[:50] if archive_contents else ["N/A (Not an archive container)"],
        "structural_forensic_notes": structural_notes,
        "ai_behavioral_briefing": ai_briefing
    }