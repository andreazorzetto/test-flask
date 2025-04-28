from flask import Flask, jsonify, request, Response
import os
import json
import requests
from functools import wraps

app = Flask(__name__)

# Configuration
EC2_INSTANCE_IP = os.environ.get('EC2_INSTANCE_IP', 'localhost')
EC2_PORT = os.environ.get('EC2_PORT', '8000')
AUTH_USERNAME = os.environ.get('AUTH_USERNAME', 'admin')
AUTH_PASSWORD = os.environ.get('AUTH_PASSWORD', 'secure_password')

# Basic authentication decorator
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not (auth.username == AUTH_USERNAME and auth.password == AUTH_PASSWORD):
            return Response(
                'Authentication required',
                401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return jsonify({
        "status": "ok",
        "message": "Flask application running successfully"
    })

@app.route('/scan', methods=['GET'])
@require_auth
def get_scan_results():
    try:
        # Get scan results from EC2 instance
        response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/results")
        
        if response.status_code == 200:
            scan_data = response.json()
            return jsonify(scan_data)
        else:
            return jsonify({"error": f"Failed to fetch scan results: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error fetching scan results: {str(e)}"}), 500

@app.route('/sbom', methods=['GET'])
@require_auth
def get_sbom():
    try:
        # Get SBOM from EC2 instance
        response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/sbom")
        
        if response.status_code == 200:
            sbom_data = response.json()
            return jsonify(sbom_data)
        else:
            return jsonify({"error": f"Failed to fetch SBOM: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error fetching SBOM: {str(e)}"}), 500

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
