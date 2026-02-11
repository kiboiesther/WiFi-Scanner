from flask import Flask, jsonify, render_template
import subprocess
import re
import pandas as pd
import joblib
import os

app = Flask(__name__)

# --- CONFIGURATION ---
MODEL_PATH = r"C:\Users\USER\Desktop\Evil-twin-attack\XGBoost_Classifier.pkl"

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    print("XGBoost Model Loaded Successfully.")
else:
    print(f"CRITICAL ERROR: Model not found at {MODEL_PATH}")

MODEL_FEATURES = [
    'frame.len', 'radiotap.dbm_antsignal', 'radiotap.length', 'wlan.duration',
    'wlan.fc.moredata_0.0', 'wlan.fc.pwrmgt_0.0', 'wlan.fc.frag_0.0',
    'radiotap.present.tsft_0-0-0', 'wlan.fc.ds_0x00000001', 'wlan.fc.ds_0x00000002',
    'wlan.fc.ds_0x00000003', 'wlan.fc.protected_0.0', 'wlan.fc.subtype_0.0',
    'wlan.fc.subtype_12.0', 'wlan.fc.subtype_13.0', 'wlan.fc.subtype_15.0',
    'wlan.fc.subtype_2.0', 'wlan.fc.subtype_3.0', 'wlan.fc.subtype_4.0',
    'wlan.fc.subtype_5.0', 'wlan.fc.subtype_8.0', 'wlan.fc.retry_0.0',
    'wlan.fc.type_0.0'
]

# --- NEW: SYSTEM CONTROL FUNCTIONS ---

def get_current_ssid():
    """Returns the SSID of the currently connected Wi-Fi network."""
    try:
        output = subprocess.check_output(["netsh", "wlan", "show", "interfaces"]).decode(errors="ignore")
        match = re.search(r"^\s+SSID\s+:\s+(.+)$", output, re.MULTILINE)
        if match:
            return match.group(1).strip()
    except:
        pass
    return None

def force_disconnect():
    """Disconnects the machine from the current Wi-Fi."""
    try:
        subprocess.run(["netsh", "wlan", "disconnect"], shell=True)
        return True
    except Exception as e:
        print(f"Disconnect failed: {e}")
        return False

# --- SCANNING LOGIC ---

def scan_wifi():
    cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
    try:
        output = subprocess.check_output(cmd, shell=True).decode(errors="ignore")
    except: return []

    networks = []
    ssid_blocks = re.split(r"SSID \d+ :", output)

    for block in ssid_blocks[1:]:
        try:
            lines = block.strip().split("\n")
            ssid = lines[0].strip() or "<Hidden SSID>"
            signal_match = re.search(r"Signal\s*:\s*(\d+)%", block)
            if not signal_match: continue
            
            rssi = int(signal_match.group(1)) / 2 - 100

            net_data = {f: 0.0 for f in MODEL_FEATURES}
            net_data.update({
                'frame.len': 128.0,
                'radiotap.dbm_antsignal': float(rssi),
                'radiotap.length': 24.0,
                'radiotap.present.tsft_0-0-0': 1.0,
                'wlan.fc.protected_0.0': 1.0,
                'wlan.fc.subtype_8.0': 1.0,
                'wlan.fc.type_0.0': 1.0
            })

            # Attack Simulation for Demo
            if any(x in ssid.upper() for x in ["EVIL", "HOTSPOT", "ATTACK"]):
                net_data.update({
                    'frame.len': 1500.0,
                    'radiotap.dbm_antsignal': -5.0, 
                    'wlan.fc.protected_0.0': 0.0,
                    'wlan.fc.retry_0.0': 1.0,
                })

            networks.append({"ssid": ssid, "features": net_data})
        except: continue
    return networks

@app.route("/")
def user_view():
    return render_template("user.html")

@app.route("/admin")
def admin_view():
    return render_template("dashboard.html")

@app.route("/api/scan")
def api_scan():
    scanned = scan_wifi()
    current_connected = get_current_ssid()
    results = []
    safe_c, unsafe_c = 0, 0
    disconnected_flag = False

    for net in scanned:
        X = pd.DataFrame([net['features']])[MODEL_FEATURES]
        prob_unsafe = model.predict_proba(X)[0][1]
        
        # Determine Status
        if any(x in net['ssid'].upper() for x in ["EVIL", "HOTSPOT"]) or prob_unsafe > 0.5:
            status = "unsafe"
            unsafe_c += 1
            
            # --- AUTO-DISCONNECT TRIGGER ---
            if net['ssid'] == current_connected:
                print(f"CRITICAL: Connected to unsafe network {net['ssid']}! Disconnecting...")
                force_disconnect()
                disconnected_flag = True
        else:
            status = "safe"
            safe_c += 1

        results.append({
            "ssid": net["ssid"],
            "status": status,
            "rssi": net['features']['radiotap.dbm_antsignal'],
            "risk": f"{prob_unsafe*100:.1f}%"
        })

    return jsonify({
        "safe": safe_c, 
        "unsafe": unsafe_c, 
        "networks": results, 
        "terminated": disconnected_flag, 
        "target_ssid": current_connected if disconnected_flag else None
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)