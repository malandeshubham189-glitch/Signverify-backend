from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509

def load_root_certs():
    roots = []
    cert_files = [
        "CCAIndia2022.cer",
        "CCAIndia2022SPL.cer"
    ]
    for fname in cert_files:
        with open(fname, "rb") as f:
            data = f.read()
            cert = x509.Certificate.load(data)
            roots.append(cert)
    return roots

async def validate_pdf_async(file_path: str):
    results = []
    try:
        trust_roots = load_root_certs()
        vc = ValidationContext(trust_roots=trust_roots, allow_fetching=True)

        with open(file_path, 'rb') as doc:
            reader = PdfFileReader(doc)
            sig_fields = reader.embedded_signatures

            if not sig_fields:
                return {"error": "No digital signatures found in this PDF"}

            for sig in sig_fields:
                try:
                    status = await async_validate_pdf_signature(sig, vc)
                    trust_problem = None
                    try:
                        trust_problem = str(status.trust_problem_indic)
                    except Exception:
                        pass
                    results.append({
                        "signer": str(status.signing_cert.subject.human_friendly) if status.signing_cert else "Unknown",
                        "issuer": str(status.signing_cert.issuer.human_friendly) if status.signing_cert else "Unknown",
                        "valid": bool(status.intact and status.valid),
                        "trusted": bool(status.trusted),
                        "trust_problem": trust_problem,
                        "signing_time": str(status.signer_reported_dt) if status.signer_reported_dt else None,
                        "coverage": str(status.coverage),
                    })
                except Exception as e:
                    results.append({"signature_error": str(e)})

        return {"signatures": results}
    except Exception as e:
        return {"error": f"Could not process PDF: {str(e)}"}
