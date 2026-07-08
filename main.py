from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import shutil, os
from validator import validate_pdf_async

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/validate")
async def validate(file: UploadFile = File(...)):
    temp_path = f"temp_{file.filename}"
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        result = await validate_pdf_async(temp_path)
    finally:
        os.remove(temp_path)

    return result

@app.post("/debug")
async def debug(file: UploadFile = File(...)):
    content = await file.read()
    has_byterange = b'/ByteRange' in content
    has_sig_type = b'/Type/Sig' in content or b'/Type /Sig' in content
    has_acroform = b'/AcroForm' in content
    count_byterange = content.count(b'/ByteRange')

    return {
        "file_size_bytes": len(content),
        "has_byterange_marker": has_byterange,
        "byterange_count": count_byterange,
        "has_sig_type_marker": has_sig_type,
        "has_acroform": has_acroform
    }

@app.get("/")
def health():
    return {"status": "SignVerify backend is running"}
