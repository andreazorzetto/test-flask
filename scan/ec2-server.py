from flask import Flask, jsonify, send_file
import os
import json

app = Flask(__name__)

# Paths to scan results and SBOM
SCAN_RESULTS_PATH = os.environ.get('SCAN_RESULTS_PATH', 'vulnerability_scan.json')
SBOM_PATH = os.environ.get('SBOM_PATH', 'sbom.json')

@app.route('/')
def home():
    return jsonify({
        "status": "ok",
        "message": "EC2 server running successfully"
    })

@app.route('/results', methods=['GET'])
def get_scan_results():
    try:
        with open(SCAN_RESULTS_PATH, 'r') as f:
            scan_data = json.load(f)
        return jsonify(scan_data)
    except FileNotFoundError:
        return jsonify({"error": "Scan results file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON in scan results file"}), 500
    except Exception as e:
        return jsonify({"error": f"Error reading scan results: {str(e)}"}), 500

@app.route('/sbom', methods=['GET'])
def get_sbom():
    try:
        with open(SBOM_PATH, 'r') as f:
            sbom_data = json.load(f)
        return jsonify(sbom_data)
    except FileNotFoundError:
        return jsonify({"error": "SBOM file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON in SBOM file"}), 500
    except Exception as e:
        return jsonify({"error": f"Error reading SBOM: {str(e)}"}), 500

@app.route('/download/results', methods=['GET'])
def download_scan_results():
    try:
        return send_file(SCAN_RESULTS_PATH, as_attachment=True)
    except Exception as e:
        return jsonify({"error": f"Error downloading scan results: {str(e)}"}), 500

@app.route('/download/sbom', methods=['GET'])
def download_sbom():
    try:
        return send_file(SBOM_PATH, as_attachment=True)
    except Exception as e:
        return jsonify({"error": f"Error downloading SBOM: {str(e)}"}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    app.run(host='0.0.0.0', port=port)
