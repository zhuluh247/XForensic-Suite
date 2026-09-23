import socket
import ssl
import urllib.parse
import os
import json
import idna
import requests
from datetime import datetime, timezone
from pathlib import Path
from bs4 import BeautifulSoup
from PIL import Image, ImageDraw
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from core.utils import UPLOAD_DIR

router = APIRouter(prefix="/api/phish", tags=["XPhishCheck"])

class URLScanRequest(BaseModel):
    url: str

OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl", "buff.ly", "adf.ly", "is.gd"]

TRUSTED_WHITELIST = {
    "google.com": "Google LLC",
    "microsoft.com": "Microsoft Corporation",
    "apple.com": "Apple Inc.",
    "github.com": "GitHub, Inc.",
    "groq.com": "Groq, Inc.",
    "instagram.com": "Meta Platforms, Inc.",
    "facebook.com": "Meta Platforms, Inc.",
    "whatsapp.com": "Meta Platforms, Inc.",
    "linkedin.com": "Microsoft Corporation",
    "netflix.com": "Netflix, Inc.",
    "amazon.com": "Amazon.com, Inc.",
    "paypal.com": "PayPal Holdings, Inc."
}

def unroll_url(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        if any(short in parsed.netloc.lower() for short in SHORTENERS):
            resp = requests.head(url, allow_redirects=True, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            return resp.url
    except Exception:
        pass
    return url

def get_root_domain(domain: str) -> str:
    parts = domain.lower().split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return domain

def generate_typosquat_permutations(domain: str) -> list:
    parts = domain.split('.')
    if len(parts) < 2:
        return []
    sld = parts[0]
    tld = '.'.join(parts[1:])
    
    permutations = set()
    for i in range(len(sld)):
        perm = sld[:i] + sld[i+1:]
        if len(perm) > 2:
            permutations.add(f"{perm}.{tld}")
    for i in range(len(sld)):
        perm = sld[:i] + sld[i] + sld[i] + sld[i+1:]
        permutations.add(f"{perm}.{tld}")
    return list(permutations)[:5]

def create_fallback_preview(domain: str, target_url: str, save_path: Path):
    img = Image.new("RGB", (1280, 720), color=(15, 23, 42))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 1280, 80], fill=(30, 41, 59))
    draw.text((30, 28), f"XFORENSIC SUITE — OPENROUTER VIEWPORT: {domain}", fill=(56, 189, 248))
    draw.rectangle([60, 120, 1220, 660], fill=(30, 41, 59), outline=(51, 65, 85), width=2)
    draw.text((100, 160), f"Target URL: {target_url}", fill=(255, 255, 255))
    draw.text((100, 220), f"Resolved Domain: {domain}", fill=(148, 163, 184))
    draw.text((100, 300), "[+] Deep Forensics: OpenRouter Auto-Routing active.", fill=(74, 222, 128))
    img.save(save_path, "PNG")

def extract_structural_dom(soup: BeautifulSoup) -> dict:
    forms = []
    for form in soup.find_all('form'):
        inputs = []
        for inp in form.find_all(['input', 'button', 'select', 'textarea']):
            inputs.append({
                "tag": inp.name,
                "name": inp.get('name', ''),
                "type": inp.get('type', ''),
                "id": inp.get('id', ''),
                "value": inp.get('value', ''),
                "placeholder": inp.get('placeholder', '')
            })
        forms.append({
            "action": form.get('action', ''),
            "method": form.get('method', 'GET'),
            "inputs": inputs
        })
    
    scripts = []
    for script in soup.find_all('script'):
        src = script.get('src')
        content = script.string
        if src:
            scripts.append({"type": "external", "src": src})
        elif content and content.strip():
            scripts.append({"type": "inline", "code": content.strip()})
            
    iframes = [iframe.get('src') for iframe in soup.find_all('iframe') if iframe.get('src')]
    meta_redirects = [meta.get('content') for meta in soup.find_all('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'})]
    
    return {
        "forms": forms,
        "scripts": scripts,
        "iframes": iframes,
        "meta_redirects": meta_redirects
    }

@router.post("/scan")
async def scan_url(data: URLScanRequest):
    raw_url = data.url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "http://" + raw_url

    target_url = unroll_url(raw_url)
    parsed_url = urllib.parse.urlparse(target_url)
    domain = parsed_url.netloc or parsed_url.path.split('/')[0]
    if ":" in domain:
        domain = domain.split(":")[0]

    root_domain = get_root_domain(domain)
    if domain.lower() in TRUSTED_WHITELIST or root_domain in TRUSTED_WHITELIST:
        matched_brand = TRUSTED_WHITELIST.get(domain.lower(), TRUSTED_WHITELIST.get(root_domain, "Trusted Entity"))
        return {
            "target_url": target_url,
            "resolved_domain": domain,
            "root_domain": root_domain,
            "server_ip": "Whitelisted Infrastructure",
            "hosting_provider": matched_brand,
            "rdap_registrar": "Verified Official Registrar",
            "rdap_creation_date": "Trusted Historical Entity",
            "domain_age_days": "Trusted Entity",
            "registrant_name": "Protected / Enterprise Entity",
            "registrant_email": "Protected",
            "registrant_phone": "Protected",
            "registrant_address": "Protected",
            "abuse_contact": "official-abuse@enterprise.com",
            "nameservers": ["Official Enterprise Nameservers"],
            "risk_score_percentage": "0%",
            "verdict": "LEGITIMATE",
            "desktop_screenshot_url": "N/A (Whitelisted Official Domain)",
            "brand_impersonation_targets": ["None detected"],
            "exfiltration_hooks": ["No unauthorized webhooks found"],
            "typosquat_permutations": [],
            "detailed_verdict_reasons": [f"Official whitelisted enterprise infrastructure recognized for {root_domain}."],
            "raw_technical_indicators": [f"Whitelisted domain match: {domain}"]
        }

    indicators = []
    exfiltration_endpoints = []
    brand_matches = []
    structural_dom = {}
    
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    safe_dom_name = domain.replace('.', '_').replace(':', '_')
    screenshot_filename = f"phish_snap_{safe_dom_name}.png"
    screenshot_path = UPLOAD_DIR / screenshot_filename

    if target_url != raw_url:
        indicators.append(f"URL Shortener Unrolled: Redirected from [{raw_url}] to [{target_url}]")

    registrar_info = "Unknown Registrar"
    creation_date = "Unknown"
    age_days = -1
    nameservers_list = []
    registrant_name = "Redacted / Not Disclosed"
    registrant_email = "Not Disclosed"
    registrant_phone = "Not Disclosed"
    registrant_address = "Not Disclosed"
    abuse_contact = "Not Disclosed"

    try:
        rdap_resp = requests.get(f"https://rdap.org/domain/{root_domain}", timeout=6)
        if rdap_resp.status_code == 200:
            rdap_data = rdap_resp.json()
            
            for event in rdap_data.get("events", []):
                if event.get("eventAction") == "registration":
                    creation_date = event.get("eventDate", "Unknown")
                    break
            
            for ns in rdap_data.get("nameservers", []):
                if "ldhName" in ns:
                    nameservers_list.append(ns["ldhName"])

            for entity in rdap_data.get("entities", []):
                roles = entity.get("roles", [])
                vcard = entity.get("vcardArray", [])
                
                if "registrar" in roles:
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                registrar_info = item[3]
                                break

                if len(vcard) > 1:
                    vcard_items = vcard[1]
                    c_name, c_email, c_phone, c_addr = None, None, None, None
                    
                    for item in vcard_items:
                        prop = item[0]
                        val = item[3]
                        if prop == 'fn': c_name = val
                        elif prop == 'email': c_email = val
                        elif prop == 'tel': c_phone = val
                        elif prop == 'adr':
                            if isinstance(val, list):
                                c_addr = ", ".join([str(x) for x in val if x])
                            else:
                                c_addr = str(val)

                    if 'registrant' in roles:
                        if c_name: registrant_name = c_name
                        if c_email: registrant_email = c_email
                        if c_phone: registrant_phone = c_phone
                        if c_addr: registrant_address = c_addr
                    
                    if 'abuse' in roles:
                        if c_email: abuse_contact = c_email

            if creation_date != "Unknown":
                try:
                    clean_date_str = creation_date.replace("Z", "+00:00")
                    c_dt = datetime.fromisoformat(clean_date_str)
                    age_days = (datetime.now(timezone.utc) - c_dt).days
                    indicators.append(f"RDAP Registry Verified for [{root_domain}]: Registrar [{registrar_info}], Created {age_days} days ago [{creation_date}].")
                except Exception:
                    indicators.append(f"RDAP Registry Verified for [{root_domain}]: Registrar [{registrar_info}], Created [{creation_date}]")
    except Exception as e:
        indicators.append(f"RDAP lookup warning: {str(e)}")

    server_ip = "Unknown"
    hosting_provider = "Unknown Hosting Provider"
    asn_info = "Unknown"
    try:
        server_ip = socket.gethostbyname(domain)
        ip_resp = requests.get(f"http://ip-api.com/json/{server_ip}", timeout=4).json()
        if ip_resp.get("status") == "success":
            isp = ip_resp.get("isp", "")
            org = ip_resp.get("org", "")
            hosting_provider = f"{org} ({isp})" if org else isp
            asn_info = ip_resp.get('as', 'N/A')
            indicators.append(f"Hosting Infrastructure: {hosting_provider} [ASN: {asn_info}]")
    except Exception:
        indicators.append("DNS resolution or ASN IP geolocation failed.")

    global_brands = ["microsoft", "office365", "teams", "paypal", "apple", "netflix", "google", "amazon", "bank", "chase", "binance", "coinbase", "groq", "instagram", "facebook"]
    official_domains = {
        "microsoft": "microsoft.com", "office365": "microsoft.com", "teams": "microsoft.com",
        "paypal": "paypal.com", "apple": "apple.com", "netflix": "netflix.com", "google": "google.com", 
        "groq": "groq.com", "instagram": "instagram.com", "facebook": "facebook.com"
    }

    for brand in global_brands:
        if brand in domain.lower():
            official = official_domains.get(brand, f"{brand}.com")
            if official not in domain.lower():
                brand_matches.append(brand.capitalize())
                indicators.append(f"Brand Spoofing Flag: Domain contains brand '{brand.capitalize()}' but does not resolve to official authority ('{official}').")

    try:
        page_resp = requests.get(target_url, timeout=7, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})
        soup = BeautifulSoup(page_resp.text, 'html.parser')
        structural_dom = extract_structural_dom(soup)
        
        for form in structural_dom.get("forms", []):
            action = form.get("action", "")
            if any(term in action for term in ['telegram.org', 'discord.com', 'webhook', 'php', 'submit', 'collect', 'login', 'auth', 'bot']):
                exfiltration_endpoints.append(action)
                indicators.append(f"Credential Collection Vector: DOM form action points to external endpoint [{action}]")
    except Exception as e:
        indicators.append(f"DOM parsing warning: {str(e)}")

    screenshot_success = False
    try:
        microlink_url = (
            f"https://api.microlink.io/?url={urllib.parse.quote(target_url)}"
            f"&screenshot=true&viewport.width=1920&viewport.height=1080"
            f"&isMobile=false&deviceScaleFactor=1"
            f"&user-agent=Mozilla%2F5.0%20(Windows%20NT%2010.0%3B%20Win64%3B%20x64)%20AppleWebKit%2F537.36%20(KHTML,%20like%20Gecko)%20Chrome%2F122.0.0.0%20Safari%2F537.36"
        )
        ml_resp = requests.get(microlink_url, timeout=25)
        if ml_resp.status_code == 200:
            ml_data = ml_resp.json()
            real_screenshot_url = ml_data.get("data", {}).get("screenshot", {}).get("url")
            if real_screenshot_url:
                img_data = requests.get(real_screenshot_url, timeout=15)
                if img_data.status_code == 200:
                    with open(screenshot_path, "wb") as f:
                        f.write(img_data.content)
                    screenshot_success = True
                    indicators.append("Cloud-rendered desktop browser screenshot successfully captured via Microlink API.")
    except Exception as e:
        indicators.append(f"Cloud screenshot warning: {str(e)}")

    if not screenshot_success or not os.path.exists(screenshot_path):
        create_fallback_preview(domain, target_url, screenshot_path)

    typosquat_candidates = generate_typosquat_permutations(domain)

    ai_verdict = None
    ai_risk_score = None
    ai_reasoning = []

    telemetry_payload = {
        "target_url": target_url,
        "resolved_domain": domain,
        "root_domain": root_domain,
        "registrar": registrar_info,
        "domain_age_days": age_days,
        "registrant_name": registrant_name,
        "registrant_email": registrant_email,
        "registrant_phone": registrant_phone,
        "registrant_address": registrant_address,
        "abuse_contact": abuse_contact,
        "hosting_provider": hosting_provider,
        "asn": asn_info,
        "brand_matches": brand_matches,
        "exfiltration_hooks": exfiltration_endpoints,
        "nameservers": nameservers_list,
        "technical_indicators": indicators,
        "structural_dom_code": structural_dom
    }

    if OPENROUTER_API_KEY and OPENROUTER_API_KEY.strip() != "":
        try:
            headers = {
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "https://xforensic-suite-backend.onrender.com",
                "X-Title": "XForensic Suite",
                "Content-Type": "application/json"
            }
            prompt = f"""
            You are an elite SOC Principal Threat Intelligence Analyst and Phishing Investigator. 
            Examine the following structural DOM code (forms, inputs, scripts) and cyber forensics telemetry for the scanned URL. Write a comprehensive, professional multi-paragraph forensic briefing.
            
            Telemetry & Structural DOM Code:
            {json.dumps(telemetry_payload, indent=2)}

            Instructions for your detailed report:
            1. Provide an executive verdict summary ("CONFIRMED PHISHING", "SUSPICIOUS/HIGH RISK", or "LEGITIMATE") based on domain age, brand spoofing, registrar records, and analysis of the extracted DOM code and login forms.
            2. Analyze the structural forms, input fields (e.g., password, username), and inline/external scripts to uncover hidden credential harvesting mechanisms, cloaking, or redirection tactics.
            3. Detail the threat mechanics, exfiltration channels, and potential risks to users visiting this URL.

            Return ONLY valid JSON in this exact structure:
            {{
              "verdict": "CONFIRMED PHISHING" | "SUSPICIOUS/HIGH RISK" | "LEGITIMATE",
              "risk_score_percentage": "XX%",
              "detailed_reasons": [
                "Detailed paragraph 1 covering infrastructure analysis, domain age, registrar telemetry, and hosting anomaly...",
                "Detailed paragraph 2 covering structural DOM code analysis, login form inspection, credential harvesting hooks, and script logic...",
                "Detailed paragraph 3 covering tactical assessment, user risk, exfiltration vectors, and final threat conclusion..."
              ]
            }}
            """
            body = {
                "model": "openrouter/free",  # Automatically routes to open free models with zero bottleneck
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
                ai_reasoning = ai_data.get("detailed_reasons", [])
            else:
                print(f"OpenRouter API Error in XPhishCheck [{res.status_code}]: {res.text}")
        except Exception as e:
            print(f"OpenRouter API Exception in XPhishCheck: {str(e)}")
            indicators.append(f"AI OpenRouter warning: {str(e)}")

    if not ai_verdict:
        calc_score = 10
        if age_days >= 0 and age_days <= 30:
            calc_score += 40
        if brand_matches:
            calc_score += 45
        if exfiltration_endpoints:
            calc_score += 30
        calc_score = min(calc_score, 100)
        
        ai_risk_score = f"{calc_score}%"
        if calc_score >= 45:
            ai_verdict = "CONFIRMED PHISHING"
        elif calc_score >= 20:
            ai_verdict = "SUSPICIOUS/HIGH RISK"
        else:
            ai_verdict = "LEGITIMATE"
        ai_reasoning = indicators

    return {
        "target_url": target_url,
        "resolved_domain": domain,
        "root_domain": root_domain,
        "server_ip": server_ip,
        "hosting_provider": hosting_provider,
        "rdap_registrar": registrar_info,
        "rdap_creation_date": creation_date,
        "domain_age_days": f"{age_days} days" if age_days >= 0 else "Unknown",
        "registrant_name": registrant_name,
        "registrant_email": registrant_email,
        "registrant_phone": registrant_phone,
        "registrant_address": registrant_address,
        "abuse_contact": abuse_contact,
        "nameservers": nameservers_list if nameservers_list else ["No nameservers returned"],
        "risk_score_percentage": ai_risk_score,
        "verdict": ai_verdict,
        "desktop_screenshot_url": f"/api/phish/screenshot/{screenshot_filename}",
        "brand_impersonation_targets": brand_matches if brand_matches else ["None detected"],
        "exfiltration_hooks": exfiltration_endpoints if exfiltration_endpoints else ["No unauthorized webhooks found"],
        "typosquat_permutations": typosquat_candidates,
        "detailed_verdict_reasons": ai_reasoning,
        "raw_technical_indicators": indicators
    }

@router.get("/screenshot/{filename}")
async def get_phish_screenshot(filename: str):
    file_path = UPLOAD_DIR / filename
    if os.path.exists(file_path):
        return FileResponse(file_path, media_type="image/png", filename=filename)
    raise HTTPException(status_code=404, detail="Screenshot not found.")