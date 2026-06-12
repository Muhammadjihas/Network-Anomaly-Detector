# simulate.py
import time
import random
import database as db

PRIVATE_IPS = ["192.168.1.129", "192.168.1.1", "10.0.0.5", "172.16.0.2"]
PUBLIC_IPS  = ["13.107.136.10", "20.50.73.9", "142.251.157.2",
               "34.128.9.67", "150.171.27.11", "13.235.138.240"]

def run_simulation():
    db.init_db()
    print("[*] Simulation engine active — generating live traffic...")
    while True:
        ts = time.strftime('%Y-%m-%d %H:%M:%S')

        # Generate 3-8 normal flow records per tick
        for _ in range(random.randint(3, 8)):
            src   = random.choice(PRIVATE_IPS + PUBLIC_IPS)
            dst   = random.choice(PRIVATE_IPS)
            proto = random.choice([6, 17, 1])
            pkts  = random.randint(1, 20)
            bts   = pkts * random.randint(60, 1500)
            avg   = round(bts / pkts, 2)
            db.log_flow(ts, src, dst, proto, pkts, bts, avg)

        # Occasionally inject an anomaly alert (30% chance per tick)
        if random.random() < 0.3:
            src   = random.choice(PUBLIC_IPS)
            dst   = random.choice(PRIVATE_IPS)
            proto = random.choice([6, 17, 1])
            pkts  = random.randint(50, 500)   # anomalously high packet count
            bts   = pkts * random.randint(800, 1500)
            avg   = round(bts / pkts, 2)
            score = round(random.uniform(-0.35, -0.05), 4)  # negative = anomalous
            db.log_alert(ts, src, dst, proto, pkts, bts, avg, score)

        time.sleep(15)

if __name__ == "__main__":
    run_simulation()