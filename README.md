# Cowrie Honeypot Log Classifier & Splunk Integration

This project uses Hugging Face's `distilbert-base-uncased` to fine-tune a model capable of classifying SSH honey-pot logs (Cowrie) into three tiers of threats:
- 0: Recon Bots 
- 1: Malware Droppers
- 2: Human Interactive sessions

It features a continuous integration script that reads logs dynamically from Splunk (via its REST API) and streams the generated AI confidence insights directly back into Splunk Event logs using HTTP Event Collector (HEC).

## Requirements
- Python 3.9+
- Splunk with HEC enabled and REST API (default port 8089) accessible.

## Setup Instructions

**1. Clone the repository**
```bash
git clone <your-repository-url>
cd <repository-folder>
```

**2. Create and Activate a Virtual Environment**
- Windows:
  ```bash
  python -m venv .venv
  .venv\Scripts\activate
  ```
- Linux/Mac:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  ```

**3. Install Dependencies**
```bash
pip install -r requirements.txt
```

**4. Set up Environment Variables**
Copy `.env.example` to `.env` and fill in your Splunk deployment details:
```bash
cp .env.example .env
```
Ensure you have generated an HEC Token from Splunk (`Settings` > `Data Inputs` > `HTTP Event Collector`).

## Usage

**1. Generate Synthetic Data (Optional)**
If you do not have enough Cowrie logs yet, you can generate a synthetic dataset mapping the 3-tiered behavior system.
```bash
python generate_fake_logs.py
```

**2. Fine-Tune the DistilBERT Model**
This script parses the `.json` log files (both synthetic and real), fine-tunes the base uncased model to identify commands, evaluates it, and saves the trained weights into a local directory (`saved_distilbert_cowrie/`).
```bash
python cowrie_splunk_finetune.py
```

**3. Start the Splunk Continuous Reader Inference Daemon**
Will connect to Splunk's REST API, ingest real-time Cowrie logs, run them against your custom local AI, and post predictions to your Splunk Dashboard metrics via HEC automatically.
```bash
python splunk_continuous_reader.py
```