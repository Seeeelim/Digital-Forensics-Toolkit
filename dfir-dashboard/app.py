import os
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, abort, jsonify
from google.cloud import firestore, storage
import requests
from types import SimpleNamespace
import subprocess

from werkzeug.utils import secure_filename

app = Flask(__name__)

# ---- GCP clients ----
db = firestore.Client()
storage_client = storage.Client()

# Change this if your bucket name is different
EVIDENCE_BUCKET = "dfir-evidence-digital-forensic-toolkit"

# Optional: VirusTotal API key (set as Cloud Run env var VT_API_KEY)
VT_API_KEY = os.environ.get("VT_API_KEY")


# ---------- Helpers ----------

def parse_ps_table(stdout: str, header_prefix: str):
    """
    Parse une table texte classique Volatility (pslist/psscan)
    en list[dict]. header_prefix = 'PID' pour pslist/psscan.
    """
    if not stdout:
        return []

    lines = stdout.splitlines()
    rows = []
    header_idx = None

    # trouver la ligne d'en-tête
    for i, line in enumerate(lines):
        if line.strip().startswith(header_prefix):
            header_idx = i
            break

    if header_idx is None:
        return []

    headers = lines[header_idx].split()
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        parts = line.split()
        # sécurité : ignorer les lignes bizarres
        if len(parts) < len(headers):
            continue
        row = dict(zip(headers, parts))
        rows.append(row)

    return rows


def parse_netscan(stdout: str):
    """
    Parse netscan en list[dict].
    """
    if not stdout:
        return []

    lines = stdout.splitlines()
    rows = []
    header_idx = None

    for i, line in enumerate(lines):
        if line.strip().startswith("Offset"):
            header_idx = i
            break

    if header_idx is None:
        return []

    headers = lines[header_idx].split()
    for line in lines[header_idx + 1:]:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) < len(headers):
            continue
        row = dict(zip(headers, parts))
        rows.append(row)

    return rows

def parse_malfind(text):
    """
    Parse le output de Volatility 3 malfind (table PID / Process / Start / End / Tag / Protection...)
    et retourne une liste de dicts avec:
      - process
      - pid
      - vad  (range mémoire + tag)
      - hex_dump (on ne la remplit pas pour l’instant)
    """
    if not text:
        return []

    lines = text.splitlines()
    header_idx = None

    # Chercher la ligne qui commence par 'PID'
    for i, line in enumerate(lines):
        if line.strip().startswith("PID"):
            header_idx = i
            break

    if header_idx is None:
        return []

    rows = []
    for line in lines[header_idx + 1:]:
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        # On garde seulement les vraies lignes de table (qui commencent par un PID numérique)
        if not parts[0].isdigit():
            continue
        if len(parts) < 6:
            continue

        pid = parts[0]
        process = parts[1]
        start = parts[2]
        end = parts[3]
        tag = parts[4]
        protection = parts[5]

        vad_str = f"{start} → {end} ({tag}, {protection})"

        rows.append({
            "process": process,
            "pid": pid,
            "vad": vad_str,
            "hex_dump": "",  # tu pourras l'améliorer plus tard
        })

    return rows

def parse_cmdline(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if line.startswith("PID"):
            continue
        rows.append(line.strip())
    return rows

def parse_dlllist(text):
    """
    Parse le output de Volatility 3 dlllist (table PID / Process / Base / Size / Name / Path...)
    et retourne une liste de dicts:
      - pid
      - process
      - name
      - path
    """
    if not text:
        return []

    lines = text.splitlines()
    header_idx = None

    for i, line in enumerate(lines):
        if line.strip().startswith("PID"):
            header_idx = i
            break

    if header_idx is None:
        return []

    rows = []
    for line in lines[header_idx + 1:]:
        line = line.strip()
        if not line:
            continue

        parts = line.split()
        if not parts[0].isdigit():
            continue
        if len(parts) < 6:
            continue

        pid = parts[0]
        process = parts[1]
        # parts[2] = Base, parts[3] = Size, parts[4] = Name, parts[5] = Path
        name = parts[4]
        path = parts[5]

        rows.append({
            "pid": pid,
            "process": process,
            "name": name,
            "path": path,
        })

    return rows

def get_download_url(object_name: str, minutes: int = 60) -> str | None:
    """Generate a signed URL for an object (or None on error)."""
    try:
        bucket = storage_client.bucket(EVIDENCE_BUCKET)
        blob = bucket.blob(object_name)
        url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=minutes),
            method="GET",
        )
        return url
    except Exception as e:
        print(f"[WARN] Failed to create signed URL for {object_name}: {e}")
        return None


def vt_lookup(sha256: str) -> dict:
    """Query VirusTotal for a file hash."""
    if not VT_API_KEY:
        return {"error": "VT_API_KEY not configured on the service."}

    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            summary = {
                "harmless": stats.get("harmless", 0),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
            }
            return summary
        else:
            return {"error": f"{resp.status_code} {resp.text}"}
    except Exception as e:
        return {"error": str(e)}


# ---------- Routes ----------

from types import SimpleNamespace

def _clean(value):
    """Convertit récursivement les SimpleNamespace et objets non-JSON."""
    if isinstance(value, SimpleNamespace):
        return {k: _clean(v) for k, v in value.__dict__.items()}
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, tuple):
        return tuple(_clean(v) for v in value)
    try:
        json.dumps(value)
        return value
    except:
        return str(value)

def _doc_to_item(doc):
    data = doc.to_dict() or {}
    data["id"] = doc.id
    return _clean(data)


@app.route("/")
def index():
    # Timeline: latest first
    docs = (
        db.collection("evidence")
        .order_by("processed_at", direction=firestore.Query.DESCENDING)
        .limit(100)
        .stream()
    )
    items = [_doc_to_item(d) for d in docs]
    return render_template("index.html", items=items)


@app.route("/evidence/<doc_id>")
def evidence_detail(doc_id):
    doc_ref = db.collection("evidence").document(doc_id)
    snap = doc_ref.get()
    evidence = snap.to_dict()
    evidence["id"] = doc_id

    vol = evidence.get("volatility") or {}

    pslist_rows = parse_ps_table(vol.get("pslist_stdout", ""), "PID")
    psscan_rows = parse_ps_table(vol.get("psscan_stdout", ""), "PID")
    netscan_rows = parse_netscan(vol.get("netscan_stdout", ""))

    malfind_rows = parse_malfind(vol.get("malfind_stdout", ""))
    cmdline_rows = parse_cmdline(vol.get("cmdline_stdout", ""))
    dlllist_rows = parse_dlllist(vol.get("dlllist_stdout", ""))

    return render_template(
        "detail.html",
        evidence=evidence,
        pslist_rows=pslist_rows,
        psscan_rows=psscan_rows,
        netscan_rows=netscan_rows,
        malfind_rows=malfind_rows,
        cmdline_rows=cmdline_rows,
        dlllist_rows=dlllist_rows,
    )


@app.route("/search")
def search():
    """
    Search by MD5 or SHA256 hash.
    This endpoint name is 'search' so it matches url_for('search') in layout.html
    """
    query = (request.args.get("q") or "").strip()
    field = None

    if len(query) == 32:
        field = "md5"
    elif len(query) == 64:
        field = "sha256"

    results = []
    if field:
        docs = db.collection("evidence").where(field, "==", query).stream()
        results = [_doc_to_item(d) for d in docs]

    return render_template("search.html", query=query, field=field, results=results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)

@app.route("/evidence/<doc_id>/add_comment", methods=["POST"])
def add_comment(doc_id):
    """Add investigator comment to an evidence item."""
    author = request.form.get("author", "").strip() or "anonymous"
    text = request.form.get("text", "").strip()
    if not text:
        return redirect(url_for("evidence_detail", doc_id=doc_id))

    ref = db.collection("evidence").document(doc_id)
    ref.collection("comments").add(
        {
            "author": author,
            "text": text,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
    )
    return redirect(url_for("evidence_detail", doc_id=doc_id))


@app.route("/evidence/<doc_id>/vt_check", methods=["POST"])
def vt_check(doc_id):
    """
    Call VirusTotal for this evidence's sha256 and store the result in Firestore.
    """
    ref = db.collection("evidence").document(doc_id)
    snap = ref.get()
    if not snap.exists:
        abort(404)

    data = snap.to_dict()
    sha256 = data.get("sha256")
    if not sha256:
        # Nothing to do
        return redirect(url_for("evidence_detail", doc_id=doc_id))

    vt_result = vt_lookup(sha256)
    # Store under 'vt' field
    ref.update({"vt": vt_result, "vt_checked_at": datetime.utcnow().isoformat() + "Z"})

    return redirect(url_for("evidence_detail", doc_id=doc_id))

@app.post("/upload")
def upload_evidence():
    """
    Upload a file from the dashboard to the evidence bucket.
    Trigger dfir_ingest via the GCS finalize event.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    filename = secure_filename(file.filename)

    try:
        bucket = storage_client.bucket(EVIDENCE_BUCKET)
        blob = bucket.blob(f"uploads/{filename}")
        # le file object est déjà un stream, on peut l’envoyer direct
        blob.upload_from_file(file)

        gcs_path = f"gs://{EVIDENCE_BUCKET}/uploads/{filename}"
        return jsonify({
            "status": "uploaded",
            "bucket": EVIDENCE_BUCKET,
            "object_name": blob.name,
            "gcs_path": gcs_path,
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.json
    bucket = data["bucket"]
    filename = data["filename"]

    # Download memory file
    client = storage.Client()
    bucket = client.bucket(bucket)
    blob = bucket.blob(filename)
    blob.download_to_filename("/tmp/memory.raw")

    results = {}
    for plugin in ["pslist", "netscan", "psscan"]:
        cmd = [
            "python3", "-m", "volatility3",
            "-f", "/tmp/memory.raw",
            plugin
        ]
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
            results[plugin] = out
        except Exception as e:
            results[plugin] = str(e)

    return jsonify(results)


# Cloud Run entrypoint
if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)), debug=True)