from flask import Flask, jsonify, send_file, request
import os
import json

app = Flask(__name__)

# Load configuration
CONFIG_PATH = os.environ.get('CONFIG_PATH', 'config.json')

try:
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)

    # Paths to scan results and SBOM
    SCAN_RESULTS_PATH = config.get('scan_results_path', 'vulnerability_scan.json')
    SBOM_PATH = config.get('sbom_path', 'sbom.json')
    CRITICAL_HIGH_VULNS_PATH = config.get('critical_high_vulns_path', 'critical_high_vulns.json')

    # Set port
    PORT = config.get('port', 8000)

    # Set allowed origins
    ALLOWED_ORIGINS = config.get('allowed_origins', ['*'])
except Exception as e:
    print(f"Error loading config: {str(e)}")
    # Default values
    SCAN_RESULTS_PATH = os.environ.get('SCAN_RESULTS_PATH', 'vulnerability_scan.json')
    SBOM_PATH = os.environ.get('SBOM_PATH', 'sbom.json')
    CRITICAL_HIGH_VULNS_PATH = os.environ.get('CRITICAL_HIGH_VULNS_PATH', 'critical_high_vulns.json')
    PORT = int(os.environ.get('PORT', 8000))
    ALLOWED_ORIGINS = ['*']


# CORS headers
@app.after_request
def add_cors_headers(response):
    origin = '*'  # Allow all origins by default
    if ALLOWED_ORIGINS != ['*']:
        # Check if the origin is in the allowed list
        request_origin = request.headers.get('Origin')
        if request_origin in ALLOWED_ORIGINS:
            origin = request_origin

    response.headers.add('Access-Control-Allow-Origin', origin)
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response


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


@app.route('/stats', methods=['GET'])
def get_vulnerability_stats():
    try:
        with open(SCAN_RESULTS_PATH, 'r') as f:
            scan_data = json.load(f)

        # Count vulnerabilities by severity
        severity_counts = {}
        package_counts = {}

        for match in scan_data.get('matches', []):
            # Count by severity
            severity = match.get('vulnerability', {}).get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            # Count by package
            package = match.get('artifact', {}).get('name', 'unknown')
            if package not in package_counts:
                package_counts[package] = 1
            else:
                package_counts[package] += 1

        # Get top 5 vulnerable packages
        top_packages = sorted(package_counts.items(), key=lambda x: x[1], reverse=True)[:5]

        # Check if there are any fixable vulnerabilities
        fixable_count = 0
        for match in scan_data.get('matches', []):
            if match.get('vulnerability', {}).get('fix', {}).get('state') == 'fixed':
                fixable_count += 1

        return jsonify({
            "total_vulnerabilities": len(scan_data.get('matches', [])),
            "severity_distribution": severity_counts,
            "top_vulnerable_packages": dict(top_packages),
            "fixable_vulnerabilities": fixable_count,
            "scan_timestamp": scan_data.get('timestamp', 'unknown')
        })
    except FileNotFoundError:
        return jsonify({"error": "Scan results file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON in scan results file"}), 500
    except Exception as e:
        return jsonify({"error": f"Error generating vulnerability statistics: {str(e)}"}), 500


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


@app.route('/critical-high', methods=['GET'])
def get_critical_high_vulnerabilities():
    try:
        with open(CRITICAL_HIGH_VULNS_PATH, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"error": "Critical/high vulnerabilities file not found"}), 404
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON in critical/high vulnerabilities file"}), 500
    except Exception as e:
        return jsonify({"error": f"Error reading critical/high vulnerabilities: {str(e)}"}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', PORT))
    app.run(host='0.0.0.0', port=port)