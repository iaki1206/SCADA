from flask import Flask, render_template
from flask_socketio import SocketIO
import sqlite3
import time
import numpy as np
from scapy.all import sniff, IP, TCP

app = Flask(__name__)
socketio = SocketIO(app)

# Database setup
conn = sqlite3.connect('scada_events.db', check_same_thread=False)
cursor = conn.cursor()

# Create events table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        source_ip TEXT,
        target_ip TEXT,
        protocol TEXT,
        severity TEXT
    )
''')
conn.commit()

# Track connections per source IP
connection_counts = {}

def calculate_z_score(source_ip):
    counts = list(connection_counts.get(source_ip, [0]))
    mean = np.mean(counts)
    std = np.std(counts) if len(counts) > 1 else 1.0
    return (counts[-1] - mean) / std if std != 0 else 0

def log_event(source_ip, target_ip, protocol, severity):
    cursor.execute('''
        INSERT INTO events (timestamp, source_ip, target_ip, protocol, severity)
        VALUES (?, ?, ?, ?, ?)
    ''', (time.time(), source_ip, target_ip, protocol, severity))
    conn.commit()

def packet_handler(packet):
    if IP in packet and TCP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        port = packet[TCP].dport

        # Update connection counts
        if src not in connection_counts:
            connection_counts[src] = []
        connection_counts[src].append(1)

        # Calculate Z-score
        z_score = calculate_z_score(src)

        # Detect lateral movement
        if z_score > 3:
            log_event(src, dst, "TCP/{}".format(port), "High")
            alert = f"[!] Lateral movement detected: {src} → {dst} (Z-score: {z_score:.2f})"
            socketio.emit('alert', {'message': alert})

        # Detect multiple unique targets
        cursor.execute('''
            SELECT COUNT(DISTINCT target_ip) FROM events
            WHERE source_ip = ? AND timestamp >= ? 
        ''', (src, time.time() - 300))
        unique_targets = cursor.fetchone()[0]
        if unique_targets >= 3:
            alert = f"[!] Lateral movement: {src} connected to {unique_targets} unique devices"
            socketio.emit('alert', {'message': alert})

@app.route('/')
def index():
    return render_template('index.html')

def start_sniffing():
    sniff(prn=packet_handler, filter="tcp", store=0)

if __name__ == '__main__':
    # Start packet sniffing in a separate thread
    import threading
    threading.Thread(target=start_sniffing, daemon=True).start()

    # Run the Flask app
    socketio.run(app, host='0.0.0.0', port=5000)