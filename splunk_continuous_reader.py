import json
import time
import requests
import urllib3
import torch
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification

# Import HEC functionality from our fine-tuning script
from cowrie_splunk_finetune import send_to_splunk, SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, SPLUNK_INDEX

# Suppress insecure request warnings if using self-signed Splunk certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import os
from dotenv import load_dotenv

# Load configuration from .env file
load_dotenv()

# --- Splunk REST API Configuration ---
SPLUNK_REST_URL = os.getenv("SPLUNK_REST_URL")
SPLUNK_USERNAME = os.getenv("SPLUNK_USERNAME")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD")
SEARCH_QUERY = os.getenv("SPLUNK_SEARCH_QUERY")

def stream_new_logs_from_splunk(model, tokenizer, device):
    """
    Connects to the Splunk REST API export endpoint using a real-time search.
    This will continuously stream new events as they arrive in Splunk.
    """
    export_url = f"{SPLUNK_REST_URL}/services/search/jobs/export"
    
    # URL encoded parameters for the real-time search
    search_params = {
        "search": SEARCH_QUERY,
        "output_mode": "json",
        "earliest_time": "rt",  # Real-time starting now
        "latest_time": "rt",    # Continuous
        "search_mode": "realtime"
    }

    print(f"Connecting to Splunk REST API at {export_url}...")
    print(f"Running Real-Time Search: {SEARCH_QUERY}")
    
    try:
        # stream=True keeps the connection open to continuously receive chunks
        response = requests.post(
            export_url,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data=search_params,
            verify=False, # Set to True if you have valid SSL certs
            stream=True
        )
        
        response.raise_for_status()
        
        print("Connected! Listening for new Cowrie logs...\n")
        
        # Iterate over the streaming lines coming from Splunk
        for line in response.iter_lines():
            if line:
                try:
                    # Splunk returns lines of JSON. The actual event data is in the "result" dictionary.
                    event_data = json.loads(line)
                    if "result" in event_data:
                        raw_event = event_data["result"].get("_raw", "")
                        
                        # Assuming the raw event is the JSON log from Cowrie
                        print("--- New Event Received ---")
                        print(raw_event)
                        
                        try:
                            # Try parsing the raw event string back to dict
                            cowrie_event = json.loads(raw_event)
                            
                            # Only score command inputs
                            if cowrie_event.get("eventid") == "cowrie.command.input":
                                command_text = cowrie_event.get("input", "")
                                
                                if command_text:
                                    # 1. Tokenize and prepare for model
                                    inputs = tokenizer(command_text, return_tensors="pt", truncation=True, padding=True)
                                    inputs = {k: v.to(device) for k, v in inputs.items()}
                                    
                                    # 2. Run Inference
                                    with torch.no_grad():
                                        outputs = model(**inputs)
                                        logits = outputs.logits
                                        predicted_class_idx = torch.argmax(logits, dim=1).item()
                                        confidence = torch.softmax(logits, dim=1).max().item()
                                    
                                    # Translate the math back to English for Splunk
                                    label_map = {
                                        0: "recon_bot",
                                        1: "malware_dropper",
                                        2: "human_interactive"
                                    }
                                    predicted_label_str = label_map.get(predicted_class_idx, "unknown")
                                    
                                    print(f"[AI] Command: {command_text}")
                                    print(f"[AI] Evaluated -> Label: {predicted_label_str} | Confidence: {confidence*100:.2f}%")
                                    
                                    # 3. Create the Splunk Event Metadata payload
                                    ai_insight = {
                                        "source_event": cowrie_event,
                                        "model": "distilbert-base-uncased-finetuned",
                                        "predicted_threat_label": predicted_label_str, # Now sends the string!
                                        "confidence": round(confidence * 100, 2),
                                        "analyzed_command": command_text,
                                        "timestamp": cowrie_event.get("timestamp")
                                    }
                                    
                                    # 4. Send AI Insight strictly back to Splunk
                                    send_to_splunk(ai_insight, SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, SPLUNK_INDEX)
                                    
                        except json.JSONDecodeError:
                            print("Raw event is not valid JSON, skipping AI analysis.")
                        
                except json.JSONDecodeError:
                    pass

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to Splunk: {e}")
        print("Retrying in 10 seconds...")
        time.sleep(10)
        stream_new_logs_from_splunk(model, tokenizer, device)

if __name__ == "__main__":
    # --- Load Fine-Tuned Model ---
    # Make sure to point this to the actual checkpoint directory
    MODEL_PATH = "./saved_distilbert_cowrie" 
    
    print(f"Loading tokenizer & model from: {MODEL_PATH} ...")
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Load model + tokenizer into memory
    tokenizer = DistilBertTokenizer.from_pretrained(MODEL_PATH)
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH, num_labels=3)
    model.to(device)
    model.eval()  # Set to evaluation mode
    print("Model initialized.")

    try:
        stream_new_logs_from_splunk(model, tokenizer, device)
    except KeyboardInterrupt:
        print("\nStopping Splunk continuous reader.")