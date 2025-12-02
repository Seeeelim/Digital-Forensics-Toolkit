**🕵️‍♂️ Digital Forensics Cloud Toolkit**
**Automated Memory Forensics, Evidence Ingestion & Volatility 3 Analysis on Google Cloud**

  A full cloud-native DFIR (Digital Forensics & Incident Response) pipeline that automatically ingests forensic evidence, analyzes memory dumps using Volatility 3, integrates VirusTotal, and displays everything in a modern Cloud Run dashboard.

  Built entirely with Google Cloud serverless architecture.

**🚀 1. Project Architecture**

The platform uses four fully managed GCP services, forming an automated end-to-end analysis chain:

    ┌──────────────────────────────┐
    │   User uploads evidence      │
    └───────────────┬──────────────┘
                    ▼
            Google Cloud Storage
     (gs://dfir-evidence-digital-forensic-toolkit/uploads/)
                    │ Event
                    ▼
         Cloud Function (dfir_ingest)
      • Metadata extraction
      • Hashing
      • EXIF extraction
      • VirusTotal lookup
      • Volatility 3 remote execution
      • Store structured results → Firestore
                    │
                    ▼
       Cloud Run (volatility-engine)
          • Runs Volatility 3 plugins
          • Returns structured JSON
                    │
                    ▼
       Firestore Database (NoSQL)
                    │
                    ▼
       Cloud Run Dashboard (Flask UI)
      → View metadata, EXIF, hashes, VT results
      → Upload evidence from UI

  **⚡️ 2. Components Overview**

  _**✔ Google Cloud Storage — Evidence Bucket**_

    All forensic files are uploaded to: gs://dfir-evidence-digital-forensic-toolkit/uploads/

    Supported formats : 
    
      - .raw, .mem, .dmp, .vmem (memory dumps)
      - Images (jpg, png)
      - Documents (pdf, txt)
      - Misc binary files    
      Uploading automatically triggers the Cloud Function.

  _**✔ Cloud Functions (Gen2) — Evidence Processing**_

    Function name: dfir_ingest
    
    🔍 Responsibilities:
    
    Task	Description :
      Metadata extraction	==> Size, MIME, timestamps
      Hashing	==> SHA256 & MD5 (streaming for big files)
      EXIF parsing	==> Extract GPS, camera info, timestamps
      VirusTotal lookup	==> Uses secure API key stored in Secret Manager
      Volatility 3 analysis	==> Only for memory dump formats
      Evidence classification	==> benign / suspicious / malicious / unknown
      Storage	==> Writes all results in Firestore
    
    🔧 Cloud Function Environment Variables:
    
      VOL_ENGINE_URL=https://volatility-engine-1003013388283.us-central1.run.app
      VT_API_KEY=XXXXX

  _**✔ Cloud Run — Volatility 3 Engine**_

    A containerized microservice running:
    
      Python
      Volatility 3 Framework
      Custom plugin wrappers
      JSON output formatting
    
    Runs these plugins:
    
      windows.pslist
      windows.psscan
      windows.netscan
      windows.cmdline
      windows.dlllist
      windows.malfind
      windows.psxview
      windows.svcsan
    
    Accessible by Cloud Function only.

  _**✔ Cloud Run — DFIR Dashboard (Flask UI)**_
  
    A clean, modern web interface to explore evidence.
    
    Features:
    
      Upload evidence from browser
      View file metadata (size, MIME, timestamps)
      Hashes (MD5, SHA256)
      EXIF metadata for images
      VirusTotal results
      Volatility 3 results (with tab navigation)
      Raw JSON dump for exporting reports
      Verdict automatic scoring system

  **🔐 3. Security Model — IAM & Zero Trust**

    This project follows strict least privilege design:
    
    Service Accounts & Permissions
    
      DFIR Cloud Functions SA : cf-dfir@digital-forensic-toolkit.iam.gserviceaccount.com
    
        Required roles:
          Storage Object Viewer
          Eventarc Event Receiver
          Secret Manager Accessor
          Datastore User
      
        Purpose: process evidence & write structured results.
    
      Volatility Engine (Cloud Run)
      
        Uses Cloud Run default SA with no access to GCS or Firestore.
        It only receives requests from Cloud Function.
        
      Dashboard Service Account (Cloud Run)
        digital-forensic-toolkit@appspot.gserviceaccount.com
        
        Roles:
          Firestore Viewer
        Purpose: read-only dashboard.
        Cannot modify evidence or run analysis.
    
    🧿 Key Security Guarantees:
    
      - Evidence cannot be deleted or modified by dashboard
      - VirusTotal API key stored in Secret Manager
      - Memory dumps never handled by frontend
      - Each service only accesses its own resources
      → Browse Volatility reports
  
**🔬 4. Volatility 3 Analysis**

  The engine runs multiple deep-memory forensics modules:
  
    ▶ pslist : Active processes (EPROCESS list)
    
    ▶ psscan : Terminated or hidden processes via raw pool scanning
    
    ▶ netscan : Open & closed TCP/UDP sockets
    Shows: LocalAddr, RemoteAddr, PID, State
    
    ▶ malfind : Detects injected or hidden executable VAD regions
    
    ▶ cmdline : Shows command lines of every process
    
    ▶ dlllist : Lists DLLs loaded inside each process
    
    ▶ psxview : Cross-view consistency check → detects hidden rootkits
    
    ▶ svcsan : Enumerates Windows services found in memory
  
  Results stored as clean JSON and displayed in dashboard.

**🤖 5. Automatic Verdict System**

  Each evidence receives a score → classification:
  
  ▶ Threat (malicious)
      HIGH VirusTotal detections
      Suspicious malfind regions
      Inconsistent psxview results
      Suspicious DLLs or command lines
    
  ▶ Suspicious
      Some strange processes
      Partial VT detections
      Hidden connections/ports
  
  ▶ Benign
      Clean VirusTotal
      No anomalies across all plugins
  
  ▶ Unknown
      Dump too large to hash
      No VT available

**🛠 6. Installation & Deployment**

  Full reproduction commands:
  
    1️⃣ Clone the repository
    git clone https://github.com/Seeeelim/Digital-Forensics-Toolkit.git
    cd Digital-Forensics-Toolkit
    
    2️⃣ Deploy Cloud Function
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
    
    3️⃣ Deploy Volatility Engine (Cloud Run)
    cd volatility_engine
    gcloud run deploy volatility-engine \
      --source . \
      --region us-central1 \
      --allow-unauthenticated
    
    4️⃣ Deploy Dashboard (Cloud Run)
    cd dashboard
    gcloud run deploy dfir-dashboard \
      --source . \
      --region us-central1 \
      --allow-unauthenticated
    
    5️⃣ Upload Evidence Programmatically
    gsutil cp dump.raw gs://dfir-evidence-digital-forensic-toolkit/uploads/dump.raw

**📉 7. Project Limitations**

  Even though it’s powerful, limits include:
  
    - No full event reconstruction / timeline graph
    - Cannot extract browser history or registry
    - Extremely large dumps skip hashing
    - VirusTotal API key rate-limited
    - Cannot identify which user performed actions
    - Cloud Run timeout limits complex plugin execution

**🎯 8. Why This Project Matters**

  This project demonstrates:
  
    - Digital forensics automation at cloud scale
    - Integration of Volatility 3 into serverless cloud
    - Real DFIR workflows (hashing, VT lookup, memory analysis)
    - Secure pipeline using IAM, Eventarc, Secret Manager
    - Professional dashboard for investigators
    - Production-ready architecture
  
  Ideal for:
  
    - Cybersecurity portfolios
    - Cloud engineering demonstration
    - DFIR research
    - Memory forensics training

**👨‍💻 Author**

  Selim Harzallah
