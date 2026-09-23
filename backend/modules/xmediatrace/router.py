import os
import io
import json
import base64
import numpy as np
import av
import cv2
from fastapi import APIRouter, UploadFile, File, HTTPException
import requests
import certifi

router = APIRouter(prefix="/api/media", tags=["XMediaTrace"])

OPENROUTER_API_KEY = "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"

@router.post("/trace")
async def trace_media(file: UploadFile = File(...)):
    media_bytes = await file.read()
    filename = file.filename or "unknown_media.bin"
    file_size = len(media_bytes)

    # 1. Universal Video Container & Platform Fingerprinting via PyAV
    container_metadata = {}
    codec_name = "unknown"
    width = 0
    height = 0
    fps = 0.0
    duration_sec = 0.0
    extracted_keyframes_b64 = []

    try:
        container = av.open(io.BytesIO(media_bytes))
        video_stream = next((s for s in container.streams if s.type == 'video'), None)
        
        if not video_stream:
            raise HTTPException(status_code=400, detail="Invalid media file: No video stream detected for OSINT tracing.")

        codec_name = video_stream.codec.name
        width = video_stream.width
        height = video_stream.height
        fps = float(video_stream.average_rate) if video_stream.average_rate else 30.0
        
        if container.duration:
            duration_sec = float(container.duration / av.time_base)

        if container.metadata:
            container_metadata = {str(k): str(v) for k, v in container.metadata.items()}

        # 2. Intelligent Single-Frame Target Extraction (Optimized for zero-error transmission)
        frames = []
        frame_count = 0
        total_frames_estimate = (fps * duration_sec) if duration_sec > 0 else 30
        target_frame_index = int(total_frames_estimate / 2)

        for frame in container.decode(video_stream):
            frame_count += 1
            if frame_count >= max(5, target_frame_index // 2):
                img = frame.to_ndarray(format='bgr24')
                frames.append(img)
                break

        if not frames:
            container.seek(0)
            for frame in container.decode(video_stream):
                frames.append(frame.to_ndarray(format='bgr24'))
                break

        # Resize keyframe to max width of 480px for a lightweight payload
        for img_frame in frames:
            h, w = img_frame.shape[:2]
            if w > 480:
                new_w = 480
                new_h = int(h * (480 / w))
                img_frame = cv2.resize(img_frame, (new_w, new_h), interpolation=cv2.INTER_AREA)

            success, encoded_img = cv2.imencode('.jpg', img_frame, [int(cv2.IMWRITE_JPEG_QUALITY), 75])
            if success:
                b64_str = base64.b64encode(encoded_img.tobytes()).decode('utf-8')
                extracted_keyframes_b64.append(b64_str)

    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Media Forensic Decode Error: Unable to parse video container structure. Details: {str(e)}"
        )

    # 3. Platform & Publishing Fingerprinting Heuristics
    detected_platform = "UNKNOWN / DIRECT CAPTURE"
    filename_lower = filename.lower()
    meta_str = json.dumps(container_metadata).lower()

    if "tiktok" in meta_str or "musical.ly" in meta_str or width == height or (width == 1080 and height == 1920):
        detected_platform = "TIKTOK RE-ENCODING PIPELINE"
    elif "instagram" in meta_str or "ig" in filename_lower:
        detected_platform = "INSTAGRAM REELS / STORIES PIPELINE"
    elif "whatsapp" in filename_lower or "wa" in filename_lower:
        detected_platform = "WHATSAPP MOBILE COMPRESSION PIPELINE"
    elif "youtube" in meta_str or "yt" in filename_lower:
        detected_platform = "YOUTUBE SHORTS / EXPORT PIPELINE"
    elif filename_lower.startswith("document_") or "telegram" in meta_str:
        detected_platform = "TELEGRAM DESKTOP / MOBILE EXPORT"

    osint_analysis = {
        "environment_type": "UNKNOWN",
        "geographic_region_estimate": "UNVERIFIED",
        "country_match": "UNVERIFIED",
        "coordinates_bounding_box": "N/A",
        "architectural_and_cultural_markers": [],
        "electrical_and_infrastructure_cues": [],
        "flora_and_topography": [],
        "lighting_and_chronolocation": "N/A",
        "platform_attribution_confidence": detected_platform
    }
    
    forensic_dossier = [
        f"Media container successfully ingested: {codec_name} codec, {width}x{height} resolution at {round(fps, 1)} fps, duration {round(duration_sec, 2)}s.",
        f"Extracted keyframe target for visual OSINT vector analysis.",
        f"Platform fingerprint analysis indicates origin: {detected_platform}."
    ]

    api_debug_error = None

    # 4. Multimodal OSINT Vision Intelligence via OpenRouter (Using certifi bundle)
    if OPENROUTER_API_KEY and OPENROUTER_API_KEY.strip() != "" and extracted_keyframes_b64:
        try:
            headers = {
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "HTTP-Referer": "http://localhost:8000",
                "X-Title": "XForensic Suite",
                "Content-Type": "application/json"
            }

            content_payload = [
                {
                    "type": "text",
                    "text": """
                    You are an elite Senior OSINT and Multimedia Geospatial Intelligence Analyst. 
                    Examine the provided video keyframe and container metadata. Describe what is physically happening in the video scene, and perform deep geographic, environmental, and source attribution.

                    Evaluate the following criteria thoroughly:
                    1. Scene Breakdown: What activity, objects, people, or events are taking place in this frame?
                    2. Environment Context: Is this recorded INDOORS or OUTDOORS? 
                    3. If INDOORS: Analyze wall sockets/electrical standards, window framing, tiles, furniture, and any visible text or cultural packaging.
                    4. If OUTDOORS: Analyze road markings, signage fonts, architectural styles, vehicle license plates, electrical utility poles, and commercial storefronts.
                    5. Flora & Topography: Identify plant species, soil types, or climate indicators (e.g., Sahel savanna, tropical rainforest, urban sprawl).
                    6. Geospatial Triangulation: Provide your best estimate of the Country, Region/State, and estimated geographic coordinate bounding box or landmark references.

                    Return ONLY valid JSON in this exact structure:
                    {
                      "environment_type": "INDOOR / HOUSE" or "OUTDOOR / STREET / RURAL",
                      "geographic_region_estimate": "Specific city, state, or region name",
                      "country_match": "Country name",
                      "coordinates_bounding_box": "Estimated lat/long coordinates or geographic bounding box description",
                      "architectural_and_cultural_markers": ["marker 1", "marker 2"],
                      "electrical_and_infrastructure_cues": ["cue 1", "cue 2"],
                      "flora_and_topography": ["flora 1", "topography 2"],
                      "lighting_and_chronolocation": "Description of lighting and shadow vectors",
                      "forensic_summary_paragraphs": [
                        "Paragraph 1 detailing what is visibly happening in the video scene, activity, and environment...",
                        "Paragraph 2 covering cultural markers, architecture, flora, and geospatial estimation...",
                        "Paragraph 3 concluding with coordinate tracking and platform attribution confidence..."
                      ]
                    }
                    """
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": f"data:image/jpeg;base64,{extracted_keyframes_b64[0]}"
                    }
                }
            ]

            body = {
                "model": "google/gemini-2.5-flash",
                "messages": [{"role": "user", "content": content_payload}],
                "max_tokens": 2000,
                "temperature": 0.2
            }

            res = requests.post(
                "https://openrouter.ai/api/v1/chat/completions", 
                headers=headers, 
                json=body, 
                timeout=45,
                verify=certifi.where()
            )
            
            if res.status_code == 200:
                res_data = res.json()
                content = res_data["choices"][0]["message"]["content"].strip()
                if content.startswith("```json"):
                    content = content[7:-3].strip()
                elif content.startswith("```"):
                    content = content[3:-3].strip()
                
                ai_data = json.loads(content)
                osint_analysis.update({
                    "environment_type": ai_data.get("environment_type", "UNKNOWN"),
                    "geographic_region_estimate": ai_data.get("geographic_region_estimate", "UNVERIFIED"),
                    "country_match": ai_data.get("country_match", "UNVERIFIED"),
                    "coordinates_bounding_box": ai_data.get("coordinates_bounding_box", "N/A"),
                    "architectural_and_cultural_markers": ai_data.get("architectural_and_cultural_markers", []),
                    "electrical_and_infrastructure_cues": ai_data.get("electrical_and_infrastructure_cues", []),
                    "flora_and_topography": ai_data.get("flora_and_topography", []),
                    "lighting_and_chronolocation": ai_data.get("lighting_and_chronolocation", "N/A")
                })
                if "forensic_summary_paragraphs" in ai_data:
                    forensic_dossier = ai_data["forensic_summary_paragraphs"]
            else:
                api_debug_error = f"OpenRouter API Error [{res.status_code}]: {res.text}"
                print(api_debug_error)
        except Exception as e:
            api_debug_error = f"OpenRouter Vision Exception: {str(e)}"
            print(api_debug_error)

    response_payload = {
        "filename": filename,
        "file_size_bytes": file_size,
        "codec": codec_name,
        "resolution": f"{width}x{height}",
        "duration_seconds": round(duration_sec, 2),
        "platform_fingerprint": detected_platform,
        "osint_geospatial_intelligence": osint_analysis,
        "forensic_dossier": forensic_dossier
    }

    if api_debug_error:
        response_payload["api_debug_error"] = api_debug_error

    return response_payload