import os
import io
import hashlib
import mimetypes
import logging
from datetime import datetime, timezone

import requests
from google.cloud import storage, firestore
from PIL import Image, ExifTags
import functions_framework

# Global GCP clients reused across invocations
storage_client = storage.Client()
db = firestore.Client()

# Environment variables for the Volatility engine and VirusTotal
VOL_ENGINE_URL = os.environ.get("VOL_ENGINE_URL")
VT_API_KEY = os.environ.get("VT_API_KEY")


def _run_volatility(gcs_path: str):
    """
    Helper to call the Volatility Engine (Cloud Run) with the GCS path
    of a memory dump. Returns parsed JSON or a small error dict.
    """
    if not VOL_ENGINE_URL:
        logging.warning("VOL_ENGINE_URL not set, skipping volatility")
        return None

    try:
        # POST to the Cloud Run volatility engine
        resp = requests.post(
            f"{VOL_ENGINE_URL}/analyze",
            json={"gcs_path": gcs_path},
            timeout=600,
        )
        if resp.status_code != 200:
            logging.warning(
                "Volatility HTTP error %s: %s",
                resp.status_code,
                resp.text[:500],
            )
            return {"status": "http_error", "code": resp.status_code}
        # Successful call: return JSON body
        return resp.json()
    except Exception as e:
        logging.warning("Volatility call failed: %s", e)
        return {"status": "exception", "error": str(e)}


def vt_lookup(hash_value: str):
    """
    Perform a VirusTotal lookup for the given hash (MD5 or SHA256).
    Returns a small dict with stats or None on error.
    """
    if not VT_API_KEY:
        logging.warning("VT_API_KEY is not set, skipping VirusTotal lookup")
        return None

    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except Exception as e:
        logging.warning("VT lookup failed for %s: %s", hash_value, e)
        return None

    if resp.status_code != 200:
        logging.warning("VT lookup returned %s for %s", resp.status_code, hash_value)
        return None

    data = resp.json().get("data", {})
    attrs = data.get("attributes", {}) or {}
    stats = attrs.get("last_analysis_stats", {}) or {}

    # Extract VirusTotal summary stats
    return {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "vt_link": f"https://www.virustotal.com/gui/file/{data.get('id', '')}",
    }


def _read_exif_if_image(content: bytes):
    """
    Try to parse EXIF metadata from a bytes object (image data).
    Returns a small dict with EXIF fields or None if parsing fails
    or if the file is not an image / has no EXIF.
    """
    try:
        img = Image.open(io.BytesIO(content))
        exif = img.getexif()
        if not exif:
            return None

        exif_data = {}
        for k, v in exif.items():
            tag = ExifTags.TAGS.get(k, str(k))
            exif_data[tag] = v

        # Core EXIF fields we care about
        result = {
            "width": img.width,
            "height": img.height,
            "make": str(exif_data.get("Make")) if "Make" in exif_data else None,
            "model": str(exif_data.get("Model")) if "Model" in exif_data else None,
            "datetime": str(exif_data.get("DateTime")) if "DateTime" in exif_data else None,
            "orientation": exif_data.get("Orientation"),
            "fnumber": str(exif_data.get("FNumber")) if "FNumber" in exif_data else None,
            "exposure_time": str(exif_data.get("ExposureTime")) if "ExposureTime" in exif_data else None,
            "iso_speed": exif_data.get("ISOSpeedRatings")
                         or exif_data.get("PhotographicSensitivity"),
        }

        # GPS info (if present)
        gps_info = exif_data.get("GPSInfo")
        if gps_info:
            # Store raw GPS info – enough for this project
            result["gps_raw"] = {str(k): str(v) for k, v in gps_info.items()}

        return result

    except Exception as e:
        logging.warning("EXIF parse failed: %s", e)
        return None


def classify_evidence(vt_result, vol_result):
    """
    Simple heuristic that returns (verdict, reason_string).

    verdict ∈ {"threat","suspicious","probably_benign","unknown"}.
    Uses VirusTotal stats and a tiny example of Volatility-based signal.
    """
    score = 0
    reasons = []

    vt = vt_result or {}
    m = int(vt.get("malicious", 0) or 0)
    s = int(vt.get("suspicious", 0) or 0)

    # ---- VirusTotal signals ----
    if m >= 5:
        score += 4
        reasons.append(f"VirusTotal: {m} engines flag as malicious")
    elif m > 0:
        score += 3
        reasons.append(f"VirusTotal: {m} engine(s) flag as malicious")
    elif s > 0:
        score += 1
        reasons.append(f"VirusTotal: {s} engine(s) mark as suspicious")

    # ---- Simple Volatility example (netscan) ----
    vol = vol_result or {}
    netscan_out = vol.get("netscan_stdout") or ""
    # If we see ESTABLISHED connections, we add a little suspicion score
    if "ESTABLISHED" in netscan_out:
        score += 1
        reasons.append("ESTABLISHED network connections present in netscan output")

    # ---- Map numeric score to a text verdict ----
    if score >= 4:
        verdict = "threat"
    elif score >= 2:
        verdict = "suspicious"
    elif score == 0 and vt_result:
        verdict = "probably_benign"
    else:
        verdict = "unknown"

    return verdict, "; ".join(reasons) if reasons else None


def _is_memory_dump(object_name: str, mime_type: str) -> bool:
    """
    Simple helper to determine whether a given GCS object looks like
    a memory dump based on its name and extension.
    """
    name = object_name.lower()
    if name.startswith("dumps/"):
        return True
    if name.endswith((".raw", ".mem", ".dmp", ".bin", ".vmem")):
        return True
    return False


def _sha256_and_md5(content: bytes):
    """
    Compute SHA256 and MD5 for a bytes object fully in memory.
    Only used for small/normal files.
    """
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()
    return sha256, md5


def _hash_gcs_blob_streaming(blob, chunk_size=8 * 1024 * 1024):
    """Compute (sha256, md5) without loading the entire object into RAM.
    This uses a temporary local file and reads it in chunks.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()

    import tempfile
    with tempfile.NamedTemporaryFile() as tmp:
        # Download to disk (/tmp) instead of RAM
        blob.download_to_file(tmp)
        tmp.flush()
        tmp.seek(0)

        # Stream in chunks and update the hash objects
        while True:
            chunk = tmp.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)

    return sha256.hexdigest(), md5.hexdigest()


def compute_verdict(vt_result, vol):
    """
    Compute a more detailed verdict dict {label, score, reasons[]} based
    on VirusTotal results and multiple Volatility plugin outputs.
    """
    score = 0
    reasons = []

    # 1) VirusTotal contribution
    if vt_result:
        m = vt_result.get("malicious", 0) or 0
        s = vt_result.get("suspicious", 0) or 0
        h = vt_result.get("harmless", 0) or 0

        if m >= 3 or (m >= 1 and s >= 2):
            score += 3
            reasons.append(f"{m} engines flagged the file as malicious on VirusTotal.")
        elif m == 0 and s == 0 and h > 5:
            reasons.append("No engine flagged the file; several flagged it as harmless on VirusTotal.")

    # 2) malfind signals: suspicious executable / RWX memory regions
    malfind_out = (vol or {}).get("malfind_stdout", "") or ""
    if "PAGE_EXECUTE_READWRITE" in malfind_out or "VadTag" in malfind_out:
        score += 2
        reasons.append("Suspicious executable memory regions detected by malfind.")

    # 3) cmdline signals: suspicious command lines / tools
    cmdline_out = (vol or {}).get("cmdline_stdout", "") or ""
    suspicious_cmd_markers = ["mimikatz", "powershell -enc", "nc.exe", "meterpreter"]
    if any(marker.lower() in cmdline_out.lower() for marker in suspicious_cmd_markers):
        score += 2
        reasons.append("Suspicious process command line (e.g. mimikatz, encoded PowerShell, netcat).")

    # 4) dlllist signals: suspicious DLLs
    dlllist_out = (vol or {}).get("dlllist_stdout", "") or ""
    if "mimikatz" in dlllist_out.lower() or "winscard.dll" in dlllist_out.lower():
        score += 1
        reasons.append("Suspicious DLL loaded in a process (dlllist).")

    # === Final decision ===
    if score >= 4:
        label = "malicious"
    elif score == 0 and vt_result and vt_result.get("malicious", 0) == 0 and vt_result.get("suspicious", 0) == 0:
        label = "benign"
    else:
        label = "needs-manual-review"

    return {
        "label": label,
        "score": score,
        "reasons": reasons,
    }


# Threshold used to decide whether to skip hashing for big dumps
BIG_DUMP_THRESHOLD = 200 * 1024 * 1024  # 200 MB


@functions_framework.cloud_event
def dfir_ingest(cloud_event):
    """
    Main Cloud Function entrypoint.

    Triggered by a GCS finalize event.
    - Identifies the file type (memory dump / image / generic file)
    - Computes hashes (or skips for huge dumps)
    - Optionally parses EXIF
    - Calls VirusTotal / Volatility
    - Stores all results in Firestore ('evidence' collection)
    """
    data = cloud_event.data or {}
    bucket_name = data.get("bucket")
    name = data.get("name")
    print(name)

    if not bucket_name or not name or name.endswith("/"):
        logging.info("Skipping object: %s", name)
        return

    logging.info("Finalize event for: gs://%s/%s", bucket_name, name)
    logging.info("VOL_ENGINE_URL=%s", VOL_ENGINE_URL)

    # First, get the blob from the bucket
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(name)
    # Reload metadata (size, content_type, etc.)
    blob.reload()

    size_bytes = blob.size or 0
    mime_type = (
        blob.content_type
        or mimetypes.guess_type(name)[0]
        or "application/octet-stream"
    )
    created_at = blob.time_created
    gcs_path = f"gs://{bucket_name}/{name}"

    # --- Hash / EXIF placeholders ---
    exif = None
    sha256 = None
    md5 = None

    if _is_memory_dump(name, mime_type):
        # ========== MEMORY DUMP CASE ==========
        if size_bytes > BIG_DUMP_THRESHOLD:
            # Huge dump (e.g. 256 MB) → do not hash at all to save time/resources
            logging.info(
                "Huge memory dump (%d bytes) for %s – skipping hashing & VT",
                size_bytes,
                name,
            )
            # sha256/md5 remain None → VirusTotal will not be called
        else:
            logging.info(
                "Memory dump under threshold (%d bytes) – streaming hash",
                size_bytes,
            )
            sha256, md5 = _hash_gcs_blob_streaming(blob)
    else:
        # ========== NORMAL FILES ==========
        # Small/normal files are read in memory
        content = blob.download_as_bytes()
        sha256, md5 = _sha256_and_md5(content)

        # If it looks like a small image, try to extract EXIF
        if mime_type.startswith("image/") and size_bytes < 10 * 1024 * 1024:
            exif = _read_exif_if_image(content)

    # --- VirusTotal: only if we have a hash ---
    vt_result = None
    if sha256 or md5:
        # Try SHA256 first, then MD5 (or vice versa)
        vt_result = vt_lookup(sha256 or md5) or vt_lookup(md5 or sha256)

    # --- Volatility only for memory dumps ---
    volatility = None
    if _is_memory_dump(name, mime_type):
        logging.info("Running Volatility for %s", gcs_path)
        volatility = _run_volatility(gcs_path)
        logging.info("Volatility result (truncated): %s", str(volatility)[:400])

    # Determine a high-level "kind" for the evidence
    if _is_memory_dump(name, mime_type):
        kind = "memory_dump"
    elif mime_type.startswith("image/"):
        kind = "image"
    else:
        kind = "file"

    size_mb = round(size_bytes / (1024 * 1024), 2) if size_bytes else 0

    # Simple heuristic classification (currently not stored separately)
    verdict_reason = classify_evidence(vt_result, volatility)

    # More detailed verdict object that will be stored
    verdict = compute_verdict(vt_result, volatility) if (vt_result or volatility) else None

    # Build Firestore document for this evidence
    doc = {
        "bucket": bucket_name,
        "object_name": blob.name,
        "gcs_path": gcs_path,
        "filename": os.path.basename(name),
        "extension": os.path.splitext(name)[1].lower(),
        "kind": kind,
        "mime_type": mime_type,
        "size_bytes": size_bytes,
        "size_mb": size_mb,
        "md5": md5,
        "sha256": sha256,
        "created_at": created_at,
        "processed_at": datetime.now(timezone.utc),
        "exif": exif,
        "vt": vt_result,
        "volatility": volatility,
        "verdict": verdict,
    }

    # Persist to Firestore
    db.collection("evidence").add(doc)
    logging.info("Stored metadata for %s (sha256=%s…)", name, (sha256 or "")[:12])