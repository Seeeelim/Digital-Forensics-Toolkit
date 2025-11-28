_**🕵️‍♂️ Digital Forensics Cloud Toolkit
Automated Memory Forensics, Evidence Ingestion & Volatility 3 Analysis on Google Cloud**_

This project is a full cloud-native DFIR (Digital Forensics & Incident Response) pipeline, designed to ingest forensic evidence, process it automatically using serverless functions, and run Volatility 3 analysis on memory dumps through a containerized engine.

It integrates four major Google Cloud services, interacting end-to-end:

**⚡️ 1. Architecture Overview**
**✔ Google Cloud Storage (GCS) — Evidence Storage**

Users upload forensic files (memory dumps, RAM captures, images, documents, etc.) into a dedicated bucket:

gs://dfir-evidence-digital-forensic-toolkit/uploads/


This upload automatically triggers the next component.

**✔ Google Cloud Functions (Gen2) — Evidence Processing & Orchestration**

Function name: dfir_ingest

Triggered when a new file is uploaded to GCS.

The function performs:

📄 Metadata extraction (size, mime, timestamps)

🔐 SHA256 / MD5 hashing (unless file > 200MB)

🧪 VT (VirusTotal) lookup (optional)

🧠 Volatility 3 analysis for memory dumps (pslist, psscan, netscan, dlllist, cmdline, malfind)

📝 Storing results inside Firestore

The function calls the Volatility Engine using:

VOL_ENGINE_URL=https://volatility-engine-1003013388283.us-central1.run.app

**✔ Cloud Run — Volatility Engine (Containerized)**

A container running:

Python

Volatility 3 framework

Parsers + custom JSON formatting

It receives files from Cloud Functions and returns plugin outputs:

windows.pslist
windows.psscan
windows.netscan
windows.cmdline
windows.dlllist
windows.malfind
Raw JSON output

**✔ Cloud Run — DFIR Dashboard (Flask Web UI)**

A separate Cloud Run service providing a modern web interface:

Upload evidence through the UI

Browse all ingested files

View metadata, hashes, EXIF

Explore Volatility 3 results (pslist, psscan, netscan, etc.)

View raw JSON for DFIR reporting

URL example: https://dfir-dashboard-1003013388283.us-central1.run.app/

**🔧 Installation & Deployment
1️⃣ Clone the repository**
git clone https://github.com/Seeeelim/Digital-Forensics-Toolkit.git
cd Digital-Forensics-Toolkit

**2️⃣ Deploy the GCS-triggered Cloud Function**
gcloud functions deploy dfir_ingest \
  --gen2 \
  --region=us-central1 \
  --runtime=python311 \
  --source="." \
  --entry-point=dfir_ingest \
  --trigger-bucket=dfir-evidence-digital-forensic-toolkit \
  --service-account=cf-dfir@digital-forensic-toolkit.iam.gserviceaccount.com \
  --memory=1Gi \
  --timeout=540s \
  --set-env-vars=VOL_ENGINE_URL="https://volatility-engine-1003013388283.us-central1.run.app",VT_API_KEY="$VT_API_KEY"

**3️⃣ Deploy the Volatility Engine (Cloud Run)**
cd volatility_engine
gcloud run deploy volatility-engine \
  --source . \
  --region us-central1 \
  --allow-unauthenticated

URL given → assign to VOL_ENGINE_URL.

**4️⃣ Deploy the DFIR Web Dashboard (Cloud Run)**
cd dashboard
gcloud run deploy dfir-dashboard \
  --source . \
  --region us-central1 \
  --allow-unauthenticated


**5️⃣ Upload Evidence for Testing**
gsutil cp dump.raw gs://dfir-evidence-digital-forensic-toolkit/uploads/dump.raw

**🔍 Volatility 3 Reports Shown in the Dashboard**

_▶ pslist_ --> Lists all active processes extracted from the EPROCESS list.

_▶ psscan_ --> Recovers terminated or hidden processes by scanning memory for EPROCESS signatures.

_▶ netscan_ --> Extracts active/closed TCP & UDP connections with:

  LocalAddr

  RemoteAddr

  PID

  State

_▶ malfind_ --> Detects hidden or injected code pages.

_▶ cmdline_ --> Shows the original process command-line strings.

_▶ dlllist_ --> Lists DLLs loaded for each process.

All results stored in Firestore and rendered in the dashboard.

**🧬 Why This Project Matters**

This project demonstrates:

- Cloud-native DFIR architecture

- Serverless automation

- Memory forensics at scale

- Zero-trust / least-privilege IAM design

- Multi-service integration (4 GCP services)

- Real-world Volatility 3 forensics pipeline

This is ideal for cybersecurity portfolios, cloud security architecture, or DFIR automation demonstration.

**👨‍💻 Project Authors**

Selim Harzallah
