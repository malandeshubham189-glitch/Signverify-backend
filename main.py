from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import shutil, os
from validator import validate_pdf_async, load_root_certs, load_intermediate_certs

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
    roots = load_root_certs()
    intermediates = load_intermediate_certs()

    root_info = [str(r.subject.human_friendly) for r in roots]
    intermediate_info = [str(i.subject.human_friendly) for i in intermediates]

    return {
        "roots_loaded": len(roots),
        "root_subjects": root_info,
        "intermediates_loaded": len(intermediates),
        "intermediate_subjects": intermediate_info
    }

@app.get("/")
def health():
    return {"status": "SignVerify backend is running"}
