from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader

async def validate_pdf_async(file_path: str):
    results = []
    try:
        with open(file_path, 'rb') as doc:
            reader = PdfFileReader(doc)
            sig_fields = reader.embedded_signatures

            if not sig_fields:
                return {"error": "No digital signatures found in this PDF"}

            for sig in sig_fields:
                try:
                    status = await async_validate_pdf_signature(sig)
                    results.append({
                        "signer": str(status.signing_cert.subject.human_friendly) if status.signing_cert else "Unknown",
                        "valid": bool(status.intact and status.valid),
                        "trusted": bool(status.trusted),
                        "signing_time": str(status.signer_reported_dt) if status.signer_reported_dt else None,
                        "coverage": str(status.coverage),
                    })
                except Exception as e:
                    results.append({"signature_error": str(e)})

        return {"signatures": results}
    except Exception as e:
        return {"error": f"Could not process PDF: {str(e)}"}
        
