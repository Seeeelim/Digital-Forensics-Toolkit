from flask import Flask, request, jsonify
import subprocess
import tempfile
from google.cloud import storage
import uuid

app = Flask(__name__)
storage_client = storage.Client()

# Bucket that stores evidence (same as used by main pipeline)
BUCKET_NAME = "dfir-evidence-digital-forensic-toolkit"


@app.get("/")
def health():
    """
    Simple health check endpoint to verify that the Volatility
    engine service is running.
    """
    return "Volatility Engine Running", 200


@app.post("/analyze")
def analyze():
    """
    Main Volatility Engine endpoint.

    Expected JSON body:
    { "gcs_path": "gs://bucket/path/to/memdump.raw" }

    Steps:
    - Download the file from GCS to a temporary local file
    - Run multiple Volatility plugins on it
    - Truncate outputs and return them as JSON
    """
    data = request.get_json(silent=True) or {}
    gcs_path = data.get("gcs_path")

    if not gcs_path or not gcs_path.startswith("gs://"):
        return jsonify({"error": "gcs_path missing or invalid"}), 400

    # ---- Parse gs://bucket/object ----
    _, path = gcs_path.split("gs://", 1)
    bucket_name, blob_name = path.split("/", 1)

    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    # ---- Save locally ----
    # Use a temporary file to store the dump locally for Volatility
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tmp:
        local_path = tmp.name
        blob.download_to_filename(local_path)

    # ---- RUN VOLATILITY ----
    analysis = {}

    try:
        # Helper closure to avoid repeating subprocess boilerplate
        def run_volatility(plugin):
            return subprocess.run(
                ["vol", "-f", local_path, plugin],
                capture_output=True,
                text=True,
                timeout=600
            )

        # 1) pslist
        pslist = run_volatility("windows.pslist")
        analysis["pslist_exit"] = pslist.returncode
        analysis["pslist_stdout"] = pslist.stdout[:4000]
        analysis["pslist_stderr"] = pslist.stderr[:1000]

        # 2) psscan
        psscan = run_volatility("windows.psscan")
        analysis["psscan_exit"] = psscan.returncode
        analysis["psscan_stdout"] = psscan.stdout[:4000]
        analysis["psscan_stderr"] = psscan.stderr[:1000]

        # 3) netscan
        netscan = run_volatility("windows.netscan")
        analysis["netscan_exit"] = netscan.returncode
        analysis["netscan_stdout"] = netscan.stdout[:4000]
        analysis["netscan_stderr"] = netscan.stderr[:1000]

        # 4) malfind
        malfind = run_volatility("windows.malfind")
        analysis["malfind_exit"] = malfind.returncode
        analysis["malfind_stdout"] = malfind.stdout[:4000]
        analysis["malfind_stderr"] = malfind.stderr[:1000]

        # 5) cmdline
        cmdline = run_volatility("windows.cmdline")
        analysis["cmdline_exit"] = cmdline.returncode
        analysis["cmdline_stdout"] = cmdline.stdout[:4000]
        analysis["cmdline_stderr"] = cmdline.stderr[:1000]

        # 6) dlllist
        dlllist = run_volatility("windows.dlllist")
        analysis["dlllist_exit"] = dlllist.returncode
        analysis["dlllist_stdout"] = dlllist.stdout[:4000]
        analysis["dlllist_stderr"] = dlllist.stderr[:1000]

        analysis["status"] = "ok"

    except Exception as e:
        # If any plugin or subprocess fails, return a structured error
        analysis = {
            "status": "exception",
            "error": str(e),
        }

    return jsonify(analysis), 200


@app.post("/upload")
def upload():
    """
    Simple helper endpoint to upload a file directly to the evidence bucket
    via the Volatility Engine service (mainly for testing).
    """
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    filename = file.filename

    # Upload to GCS under uploads/
    bucket = storage_client.bucket(BUCKET_NAME)
    blob = bucket.blob(f"uploads/{filename}")
    blob.upload_from_file(file)

    gcs_path = f"gs://{BUCKET_NAME}/uploads/{filename}"

    return jsonify({
        "status": "uploaded",
        "gcs_path": gcs_path
    })


if __name__ == "__main__":
    # Local development server for the Volatility engine
    app.run(host="0.0.0.0", port=8080)