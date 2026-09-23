import sys
import asyncio

# Force Windows Proactor Event Loop Policy to support Playwright subprocesses
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from modules.xstegocover.router import router as stego_router
from modules.xphishcheck.router import router as phish_router
from modules.xmalinspect.router import router as mal_router
from modules.xvoiceverify.router import router as voice_router
from modules.xmediatrace.router import router as media_router  # Added XMediaTrace router


app = FastAPI(
    title="XForensic Suite API",
    version="2.0",
    description="Enterprise-grade cyber-investigation and digital forensics platform backend."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(stego_router)
app.include_router(phish_router)
app.include_router(mal_router)
app.include_router(voice_router)
app.include_router(media_router)  # Registered XMediaTrace endpoint

@app.get("/")
def read_root():
    return {
        "status": "online",
        "platform": "XForensic Suite API",
        "version": "2.0",
        "modules": [
            "XMediaTrace",
            "XPhishCheck",
            "XMalInspect",
            "XVoiceVerify",
            "XStegoCover"
        ]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)