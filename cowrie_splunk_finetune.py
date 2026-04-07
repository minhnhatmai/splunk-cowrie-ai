import json
import os
import requests
import torch
import numpy as np
from datasets import Dataset
from dotenv import load_dotenv
from transformers import (
    DistilBertTokenizer,
    DistilBertForSequenceClassification,
    Trainer,
    TrainingArguments
)

# Load configuration from .env file
load_dotenv()

# Configuration for Splunk HEC
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
SPLUNK_INDEX = os.getenv("SPLUNK_INDEX")

def load_cowrie_logs(file_paths):
    """
    Extracts sessions and their corresponding commands from Cowrie logs.
    """
    sessions = {}
    for path in file_paths:
        if not os.path.exists(path):
            continue
        with open(path, 'r') as f:
            for line in f:
                event = json.loads(line.strip())
                session_id = event.get('session')
                if session_id not in sessions:
                    sessions[session_id] = []
                
                # We focus on extracting commands for the model
                if event.get('eventid') == 'cowrie.command.input':
                    sessions[session_id].append(event.get('input', ''))
    
    # Combine commands per session to form a feature document
    texts = []
    labels = []
    
    for idx, (sid, commands) in enumerate(sessions.items()):
       if commands:
            text = " ".join(commands)
            texts.append(text)
            
            # The 3-Tier Label Logic
            # 1: Malware Dropper (Looking for payload downloads/execution)
            if any(indicator in text for indicator in ["wget", "curl", "chmod +x", "./"]):
                labels.append(1) 
            # 2: Human Interactive (Looking for manual exploration of sensitive files)
            elif any(indicator in text for indicator in ["cd /etc", "cat passwd", ".ssh", "id_rsa", "ls -la"]):
                labels.append(2)
            # 0: Recon Bot (Defaulting everything else, like 'uname' or 'whoami', to basic automated bots)
            else:
                labels.append(0)
            
    return texts, labels

def fine_tune_distilbert(texts, labels):
    """
    Fine-tunes the distilbert-base-uncased model on the extracted logs.
    """
    model_name = "distilbert-base-uncased"
    tokenizer = DistilBertTokenizer.from_pretrained(model_name)
    model = DistilBertForSequenceClassification.from_pretrained(model_name, num_labels=3)
    # Create huggingface dataset
    data = {"text": texts, "label": labels}
    dataset = Dataset.from_dict(data)
    
    # Split dataset into train (80%) and test (20%)
    split_dataset = dataset.train_test_split(test_size=0.2, seed=42)
    train_dataset = split_dataset["train"]
    eval_dataset = split_dataset["test"]
    
    def tokenize_func(examples):
        return tokenizer(examples["text"], padding="max_length", truncation=True, max_length=128)
        
    tokenized_train = train_dataset.map(tokenize_func, batched=True)
    tokenized_eval = eval_dataset.map(tokenize_func, batched=True)
    
    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        return {"accuracy": float(np.mean(predictions == labels))}
    
    # Simple training arguments for demonstration
    training_args = TrainingArguments(
        output_dir="./results",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        logging_steps=10,
        eval_strategy="epoch",  # Evaluate every epoch
        save_strategy="epoch",
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_eval,
        compute_metrics=compute_metrics,
    )
    
    print("Starting Fine-tuning...")
    trainer.train()
    
    print("Evaluating the model on test data...")
    eval_results = trainer.evaluate()
    print(f"\nEvaluation Results: {eval_results}\n")
    
    # Save the fine-tuned model and tokenizer
    save_path = "./saved_distilbert_cowrie"
    print(f"Saving fine-tuned model and tokenizer to {save_path}...")
    trainer.save_model(save_path)
    tokenizer.save_pretrained(save_path)
    
    return model, tokenizer, eval_dataset

def send_to_splunk(data, hec_url, token, index):
    """
    Sends JSON data to Splunk via the HTTP Event Collector (HEC).
    """
    headers = {
        "Authorization": f"Splunk {token}"
    }
    
    # Splunk HEC payload format
    payload = {
        "event": data,
        "index": index,
        "sourcetype": "_json"
    }
    
    try:
        response = requests.post(
            hec_url, 
            json=payload, 
            headers=headers, 
            verify=False  # Set to True in production to ensure SSL validity
        )
        response.raise_for_status()
        print(f"Successfully sent event to Splunk: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send to Splunk: {e}")

if __name__ == "__main__":
    # 1. Load data
    log_files = ["logs1.json", "logs2.json", "logs3.json", "fake_logs.json"]
    texts, labels = load_cowrie_logs(log_files)
    
    if not texts:
        print("No command data found in logs.")
        exit()
        
    print(f"Extracted {len(texts)} sessions with commands.")
    
    # 2. Fine-tune the model
    # Warning: this requires a lot of memory, in real environments you should use a mapped dataset and a GPU
    model, tokenizer, test_data = fine_tune_distilbert(texts, labels)
    
    # 3. Test the model locally before Splunk integration
    print("\n--- Local Testing on Evaluation Set ---")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    
    for i in range(len(test_data)):
        text = test_data[i]["text"]
        true_label = test_data[i]["label"]
        
        inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
        inputs = {k: v.to(device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            predicted_class = torch.argmax(logits, dim=1).item()
            confidence = torch.softmax(logits, dim=1).max().item()
        
        print(f"Session Commands: {text}")
        print(f"   => True Label: {true_label} | Predicted: {predicted_class} | Confidence: {confidence*100:.2f}%\n")
        
        # Prepare the result metadata format for when you connect to Splunk
        ai_insight = {
            "model": "distilbert-base-uncased-finetuned",
            "session_index": i,
            "session_commands": text,
            "true_label": true_label,
            "predicted_label": predicted_class,
            "confidence": round(confidence * 100, 2)
        }
        
        # Uncomment the following line when ready to send to Splunk!
        send_to_splunk(ai_insight, SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, SPLUNK_INDEX)
        
    print("Testing completed safely without sending strictly to Splunk yet.")
