# Under construction, there will be lots of options afterwards.

import psutil
import pandas as pd
import time
from datetime import datetime
from sklearn.ensemble import IsolationForest
import joblib
import os

MODEL_FILE = "network_ai_model.pkl"
REPORT_FILE = "network_ai_report.csv"

def extract_features(conn):
    """
    Extracts numerical features from a connection dictionary for AI analysis.
    """
    try:
        r_ip, r_port = conn['raddr'].split(':')
        l_ip, l_port = conn['laddr'].split(':')
        features = [
            int(l_port),
            int(r_port),
            conn['pid'] if conn['pid'] else -1,
            1 if conn['status'] == "ESTABLISHED" else 0
        ]
        return features
    except:
        return [0, 0, -1, 0]

def get_connections():
    """
    Collects current network connections with relevant info.
    """
    conns = []
    for c in psutil.net_connections(kind='inet'):
        if c.raddr:
            try:
                proc = psutil.Process(c.pid)
                pname = proc.name()
            except Exception:
                pname = "N/A"
            conns.append({
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'laddr': f"{c.laddr.ip}:{c.laddr.port}",
                'raddr': f"{c.raddr.ip}:{c.raddr.port}",
                'status': c.status,
                'pid': c.pid,
                'process': pname
            })
    return conns

def train_model(data):
    """
    Trains an IsolationForest model on the provided data and saves it.
    """
    model = IsolationForest(contamination=0.02, random_state=42)
    model.fit(data)
    joblib.dump(model, MODEL_FILE)
    print("AI model trained and saved.")

def load_or_train_model():
    """
    Loads the AI model if it exists, otherwise trains a new one.
    """
    if os.path.exists(MODEL_FILE):
        model = joblib.load(MODEL_FILE)
    else:
        print("Training AI model on initial traffic... Please wait 1 minute.")
        # Collect 1 minute of baseline data
        baseline = []
        start = time.time()
        while time.time() - start < 60:
            conns = get_connections()
            for conn in conns:
                baseline.append(extract_features(conn))
            time.sleep(2)
        train_model(baseline)
        model = joblib.load(MODEL_FILE)
    return model

def main():
    report = []
    model = load_or_train_model()
    print("AI-based network monitoring started. Press Ctrl+C to stop.")
    try:
        while True:
            conns = get_connections()
            features = [extract_features(conn) for conn in conns]
            if features:
                preds = model.predict(features)
                for conn, pred in zip(conns, preds):
                    if pred == -1:
                        print(f"AI ALERT: Anomalous connection detected: {conn}")
                        conn['AI_ALERT'] = 'YES'
                    else:
                        conn['AI_ALERT'] = ''
                    report.append(conn)
                # Save report every minute
                if len(report) > 0:
                    df = pd.DataFrame(report)
                    df.to_csv(REPORT_FILE, index=False)
                    report.clear()
            time.sleep(60)
    except KeyboardInterrupt:
        print("\nMonitoring stopped. Saving report...")
        if len(report) > 0:
            df = pd.DataFrame(report)
            df.to_csv(REPORT_FILE, index=False)
        print(f"Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    # Add params...
    main()
