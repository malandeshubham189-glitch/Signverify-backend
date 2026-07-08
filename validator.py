from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko_certvalidator import ValidationContext
from asn1crypto import x509, pem

def load_single_cert(data):
    if pem.detect(data):
        _, _, der_bytes = pem.unarmor(data)
    else:
        der_bytes = data
    return x509.Certificate.load(der_bytes)

def load_certs(file_list):
    certs = []
    for fname in file_list:
        try:
            with open(fname, "rb") as f:
                data = f.read()
                cert = load_single_cert(data)
                certs.append(cert)
        except Exception as e:
            print(f"Failed to load {fname}: {e}")
    return certs

def load_root_certs():
    return load_certs(["CCAIndia2022.cer", "CCAIndia2022SPL.cer"])

def load_intermediate_certs():
    return load_certs(["eMudhraSubCA_eSignOTP2014.cer", "eMudhraCA2014.cer"])

async def validate_pdf_async(file_path: str):
    results = []
    try:
        trust_roots = load_root_certs()
        intermediate_certs = load_intermediate_certs()

        with open(file_path, 'rb') as doc:
            reader = PdfFileReader(doc)
            sig_fields = reader.embedded_signatures

            if not sig_fields:
                return {"error": "No digital signatures found in this PDF"}

            for sig in sig_fields:
                try:
                    embedded_certs = list(sig.other_embedded_certs)
                    all_other_certs = embedded_certs + intermediate_certs

                    vc = ValidationContext(
                        trust_roots=trust_roots,
                        other_certs=all_other_certs,
                        allow_fetching=True
                    )
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
