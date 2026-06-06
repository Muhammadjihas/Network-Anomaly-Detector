import time
import pandas as pd
from sklearn.ensemble import IsolationForest
import database as db

DETECTION_INTERVAL = 15  # Run ML check every 15 seconds


def run_anomaly_detector():
    print("[*] Machine Learning Anomaly Detection Service Started...")

    # Initialize the unsupervised model (contamination set to roughly 5% expected anomalies)
    model = IsolationForest(contamination=0.05, random_state=42)

    while True:
        time.sleep(DETECTION_INTERVAL)

        # Pull data from the database
        df = db.get_recent_flows(limit=200)

        # Isolation Forest requires a baseline mass of records to understand "normal" context
        if len(df) < 10:
            print(f"[*] Waiting for more data to train baseline model ({len(df)}/10 profiles)...")
            continue

        # Select our numerical features for ML training
        features = ['protocol', 'pkt_count', 'byte_count', 'avg_pkt_size']
        X = df[features]

        # Fit model and predict (-1 indicates an anomaly, 1 indicates normal behavior)
        model.fit(X)
        df['anomaly'] = model.predict(X)
        df['score'] = model.decision_function(X)  # Lower scores mean more anomalous

        # Isolate anomalies
        anomalies = df[df['anomaly'] == -1]

        if not anomalies.empty:
            print(f"[ALERT] Detected {len(anomalies)} network anomalies!")

            # Write detected anomalies to the alert dashboard database table
            for _, row in anomalies.iterrows():
                try:
                    db.log_alert(
                        row['timestamp'], row['src_ip'], row['dst_ip'],
                        int(row['protocol']), int(row['pkt_count']),
                        int(row['byte_count']), float(row['avg_pkt_size']),
                        float(row['score'])
                    )
                except Exception:
                    pass


if __name__ == "__main__":
    try:
        run_anomaly_detector()
    except KeyboardInterrupt:
        print("\n[*] Anomaly detection service stopped.")