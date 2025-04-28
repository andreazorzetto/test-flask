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


@app.route('/status')
def status():
    try:
        # Get vulnerability statistics from EC2 instance
        response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/stats")

        if response.status_code == 200:
            return jsonify(response.json())
        else:
            # Fallback to manual calculation if stats endpoint is not available
            response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/results")

            if response.status_code == 200:
                scan_data = response.json()

                # Count vulnerabilities by severity
                vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}

                for match in scan_data.get('matches', []):
                    severity = match.get('vulnerability', {}).get('severity', '').capitalize()
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
                    else:
                        vuln_counts["Unknown"] += 1

                # Get scan timestamp if available
                timestamp = scan_data.get('timestamp', 'Unknown')

                return jsonify({
                    "scan_time": timestamp,
                    "vulnerability_counts": vuln_counts,
                    "total_vulnerabilities": sum(vuln_counts.values()),
                    "critical_high_count": vuln_counts["Critical"] + vuln_counts["High"]
                })
            else:
                return jsonify({"error": f"Failed to fetch scan results: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error generating status: {str(e)}"}), 500


@app.route('/scan', methods=['GET'])
@require_auth
def get_scan_results():
    try:
        # Get scan results from EC2 instance
        response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/results")

        if response.status_code == 200:
            scan_data = response.json()

            # Format the response as HTML
            html = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Vulnerability Scan Results</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                    }
                    h1, h2, h3 {
                        color: #2c5282;
                    }
                    .meta {
                        background-color: #f8f9fa;
                        border-radius: 8px;
                        padding: 15px;
                        margin-bottom: 20px;
                    }
                    table {
                        border-collapse: collapse;
                        width: 100%;
                        margin-bottom: 20px;
                    }
                    th, td {
                        border: 1px solid #ddd;
                        padding: 8px;
                        text-align: left;
                    }
                    th {
                        background-color: #f2f2f2;
                    }
                    tr:nth-child(even) {
                        background-color: #f9f9f9;
                    }
                    .critical { background-color: #fecaca; }
                    .high { background-color: #fed7aa; }
                    .medium { background-color: #fef08a; }
                    .low { background-color: #d1fae5; }
                    .negligible { background-color: #f3f4f6; }
                    .badge {
                        display: inline-block;
                        padding: 3px 8px;
                        border-radius: 4px;
                        font-size: 12px;
                        font-weight: bold;
                        text-transform: uppercase;
                        color: white;
                    }
                    .badge-critical { background-color: #dc2626; }
                    .badge-high { background-color: #ea580c; }
                    .badge-medium { background-color: #d97706; }
                    .badge-low { background-color: #65a30d; }
                    .badge-negligible { background-color: #9ca3af; }
                    .pagination {
                        display: flex;
                        list-style: none;
                        padding: 0;
                        margin: 20px 0;
                    }
                    .pagination li {
                        margin-right: 5px;
                    }
                    .pagination a {
                        display: block;
                        padding: 8px 12px;
                        text-decoration: none;
                        background-color: #f2f2f2;
                        color: #333;
                        border-radius: 4px;
                    }
                    .pagination a.active {
                        background-color: #3b82f6;
                        color: white;
                    }
                    .pagination a:hover:not(.active) {
                        background-color: #ddd;
                    }
                    .search {
                        margin-bottom: 20px;
                    }
                    .search input {
                        padding: 8px;
                        width: 300px;
                        border: 1px solid #ddd;
                        border-radius: 4px;
                    }
                    .search button {
                        padding: 8px 16px;
                        background-color: #3b82f6;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }
                    .search button:hover {
                        background-color: #2563eb;
                    }
                    .back-link {
                        display: inline-block;
                        margin-bottom: 20px;
                        color: #3b82f6;
                        text-decoration: none;
                    }
                    .back-link:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <a href="/dashboard" class="back-link">← Back to Dashboard</a>
                <h1>Vulnerability Scan Results</h1>

                <div class="meta">
                    <p><strong>Scan Time:</strong> ''' + (scan_data.get('timestamp', 'Unknown')) + '''</p>
                    <p><strong>Image:</strong> python:3.9-slim</p>
                </div>

                <div class="search">
                    <input type="text" id="searchInput" placeholder="Search for vulnerabilities...">
                    <button onclick="searchTable()">Search</button>
                    <button onclick="resetSearch()">Reset</button>
                </div>

                <table id="vulnTable">
                    <thead>
                        <tr>
                            <th>Vulnerability ID</th>
                            <th>Severity</th>
                            <th>Package</th>
                            <th>Version</th>
                            <th>Fixed Version</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody>
            '''

            # Add rows for each vulnerability
            for match in scan_data.get('matches', []):
                vuln = match.get('vulnerability', {})
                artifact = match.get('artifact', {})

                vuln_id = vuln.get('id', 'N/A')
                severity = vuln.get('severity', 'unknown').lower()
                package = artifact.get('name', 'N/A')
                version = artifact.get('version', 'N/A')

                # Handle fixed version
                fix = vuln.get('fix', {})
                fixed_version = 'N/A'
                if fix.get('versions'):
                    fixed_version = fix.get('versions')[0]
                elif fix.get('state'):
                    fixed_version = f"[{fix.get('state')}]"

                description = vuln.get('description', 'No description available')
                # Truncate long descriptions
                if len(description) > 200:
                    description = description[:197] + '...'

                # Set row class based on severity
                row_class = severity.lower() if severity.lower() in ['critical', 'high', 'medium', 'low',
                                                                     'negligible'] else ''

                # Create severity badge
                badge_class = f"badge-{severity.lower()}" if severity.lower() in ['critical', 'high', 'medium', 'low',
                                                                                  'negligible'] else ''
                severity_badge = f'<span class="badge {badge_class}">{severity}</span>'

                html += f'''
                <tr class="{row_class}">
                    <td>{vuln_id}</td>
                    <td>{severity_badge}</td>
                    <td>{package}</td>
                    <td>{version}</td>
                    <td>{fixed_version}</td>
                    <td>{description}</td>
                </tr>
                '''

            html += '''
                    </tbody>
                </table>

                <div id="pagination" class="pagination"></div>

                <script>
                    // Pagination
                    const rowsPerPage = 20;
                    let currentPage = 1;
                    const table = document.getElementById('vulnTable');
                    const rows = table.getElementsByTagName('tbody')[0].rows;
                    const totalPages = Math.ceil(rows.length / rowsPerPage);

                    function showPage(page) {
                        // Hide all rows
                        for (let i = 0; i < rows.length; i++) {
                            rows[i].style.display = 'none';
                        }

                        // Show rows for current page
                        const start = (page - 1) * rowsPerPage;
                        const end = start + rowsPerPage;
                        for (let i = start; i < end && i < rows.length; i++) {
                            rows[i].style.display = '';
                        }

                        // Update pagination
                        updatePagination();
                    }

                    function updatePagination() {
                        const pagination = document.getElementById('pagination');
                        pagination.innerHTML = '';

                        // Previous button
                        if (currentPage > 1) {
                            const prev = document.createElement('li');
                            const a = document.createElement('a');
                            a.href = '#';
                            a.textContent = '← Previous';
                            a.addEventListener('click', function(e) {
                                e.preventDefault();
                                currentPage--;
                                showPage(currentPage);
                            });
                            prev.appendChild(a);
                            pagination.appendChild(prev);
                        }

                        // Page numbers
                        const maxPages = 5; // Show at most 5 page numbers
                        let startPage = Math.max(1, currentPage - Math.floor(maxPages / 2));
                        let endPage = Math.min(totalPages, startPage + maxPages - 1);

                        if (endPage - startPage + 1 < maxPages && startPage > 1) {
                            startPage = Math.max(1, endPage - maxPages + 1);
                        }

                        for (let i = startPage; i <= endPage; i++) {
                            const li = document.createElement('li');
                            const a = document.createElement('a');
                            a.href = '#';
                            a.textContent = i;
                            if (i === currentPage) {
                                a.className = 'active';
                            }
                            a.addEventListener('click', function(e) {
                                e.preventDefault();
                                currentPage = i;
                                showPage(currentPage);
                            });
                            li.appendChild(a);
                            pagination.appendChild(li);
                        }

                        // Next button
                        if (currentPage < totalPages) {
                            const next = document.createElement('li');
                            const a = document.createElement('a');
                            a.href = '#';
                            a.textContent = 'Next →';
                            a.addEventListener('click', function(e) {
                                e.preventDefault();
                                currentPage++;
                                showPage(currentPage);
                            });
                            next.appendChild(a);
                            pagination.appendChild(next);
                        }
                    }

                    // Search functionality
                    function searchTable() {
                        const input = document.getElementById('searchInput');
                        const filter = input.value.toUpperCase();

                        for (let i = 0; i < rows.length; i++) {
                            let match = false;
                            for (let j = 0; j < rows[i].cells.length; j++) {
                                const cell = rows[i].cells[j];
                                if (cell) {
                                    const text = cell.textContent || cell.innerText;
                                    if (text.toUpperCase().indexOf(filter) > -1) {
                                        match = true;
                                        break;
                                    }
                                }
                            }
                            rows[i].style.display = match ? '' : 'none';
                        }

                        // Disable pagination when searching
                        document.getElementById('pagination').style.display = filter ? 'none' : 'flex';
                    }

                    function resetSearch() {
                        document.getElementById('searchInput').value = '';
                        for (let i = 0; i < rows.length; i++) {
                            rows[i].style.display = '';
                        }
                        currentPage = 1;
                        showPage(currentPage);
                        document.getElementById('pagination').style.display = 'flex';
                    }

                    // Initialize
                    showPage(currentPage);
                </script>
            </body>
            </html>
            '''

            return html
        else:
            return jsonify({"error": f"Failed to fetch scan results: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error fetching scan results: {str(e)}"}), 500 @ app.route('/dashboard')


def dashboard():
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Container Security Dashboard</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
                background-color: #f9fafb;
                margin: 0;
                padding: 0;
            }
            .header {
                background-color: #1a56db;
                color: white;
                padding: 1rem;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 1rem;
            }
            .card {
                background-color: white;
                border-radius: 0.5rem;
                padding: 1.5rem;
                box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
                margin-bottom: 1.5rem;
            }
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1rem;
                margin-bottom: 1.5rem;
            }
            .stat-card {
                background-color: white;
                border-radius: 0.5rem;
                padding: 1.5rem;
                box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            }
            .stat-title {
                font-size: 0.875rem;
                color: #4b5563;
                margin-bottom: 0.5rem;
            }
            .stat-value {
                font-size: 1.875rem;
                font-weight: 700;
                color: #111827;
            }
            .charts-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 1rem;
                margin-bottom: 1.5rem;
            }
            .loading {
                display: flex;
                justify-content: center;
                align-items: center;
                height: 300px;
            }
            .loading-spinner {
                border: 4px solid rgba(0, 0, 0, 0.1);
                border-left-color: #1a56db;
                border-radius: 50%;
                width: 36px;
                height: 36px;
                animation: spin 1s linear infinite;
            }
            @keyframes spin {
                to { transform: rotate(360deg); }
            }
            .alert {
                padding: 1rem;
                border-radius: 0.5rem;
                margin-bottom: 1rem;
            }
            .alert-error {
                background-color: #fee2e2;
                color: #b91c1c;
            }
            .alert-success {
                background-color: #d1fae5;
                color: #047857;
            }
            .alert-warning {
                background-color: #fffbeb;
                color: #d97706;
            }
            .btn {
                display: inline-block;
                background-color: #1a56db;
                color: white;
                padding: 0.5rem 1rem;
                border-radius: 0.25rem;
                text-decoration: none;
                font-weight: 500;
                transition: background-color 0.2s;
            }
            .btn:hover {
                background-color: #1e429f;
            }
            @media (max-width: 768px) {
                .charts-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="header">
            <div class="container">
                <h1 class="text-2xl font-bold">Container Security Dashboard</h1>
                <p>Python 3.9-slim Docker Image Vulnerability Analysis</p>
            </div>
        </div>

        <div class="container" id="dashboard-root">
            <div class="loading">
                <div class="loading-spinner"></div>
            </div>
        </div>

        <script>
            // Fetch vulnerability data
            async function fetchVulnerabilityData() {
                try {
                    const response = await fetch('/status');
                    if (!response.ok) {
                        throw new Error(`HTTP error! Status: ${response.status}`);
                    }
                    return await response.json();
                } catch (error) {
                    console.error('Error fetching vulnerability data:', error);
                    return null;
                }
            }

            // Format timestamp
            function formatTimestamp(timestamp) {
                if (!timestamp || timestamp === 'unknown') return 'Unknown';
                try {
                    return new Date(timestamp).toLocaleString();
                } catch (e) {
                    return timestamp;
                }
            }

            // Render dashboard
            async function renderDashboard() {
                const dashboardRoot = document.getElementById('dashboard-root');
                const data = await fetchVulnerabilityData();

                if (!data) {
                    dashboardRoot.innerHTML = `
                        <div class="alert alert-error">
                            <h3 class="font-bold">Error</h3>
                            <p>Failed to load vulnerability data. Please check your connection and try again.</p>
                        </div>
                    `;
                    return;
                }

                // Process data
                const severityDistribution = data.vulnerability_counts || data.severity_distribution || {};
                const timestamp = formatTimestamp(data.scan_timestamp || data.scan_time);
                const totalVulns = data.total_vulnerabilities || 0;
                const criticalHighCount = (severityDistribution.Critical || 0) + (severityDistribution.High || 0);
                const fixableCount = data.fixable_vulnerabilities || 0;

                dashboardRoot.innerHTML = `
                    <div class="my-4">
                        <h2 class="text-xl font-bold">Scan Results</h2>
                        <p class="text-gray-600">Last scan: ${timestamp}</p>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-card">
                            <div class="stat-title">Total Vulnerabilities</div>
                            <div class="stat-value">${totalVulns}</div>
                        </div>
                        <div class="stat-card ${criticalHighCount > 0 ? 'bg-red-50' : 'bg-green-50'}">
                            <div class="stat-title">Critical/High Vulnerabilities</div>
                            <div class="stat-value">${criticalHighCount}</div>
                        </div>
                        <div class="stat-card">
                            <div class="stat-title">Fixable Vulnerabilities</div>
                            <div class="stat-value">${fixableCount || 'N/A'}</div>
                        </div>
                    </div>

                    <div class="card ${criticalHighCount > 0 ? 'bg-red-50' : 'bg-green-50'}">
                        <h3 class="text-lg font-semibold mb-2">Security Recommendation</h3>
                        <p>${criticalHighCount > 0 ? 
                            'Critical or high severity vulnerabilities have been detected. Immediate action is recommended to address these issues.' : 
                            'No critical or high severity vulnerabilities detected. Continue regular scanning and monitoring to maintain security.'
                        }</p>
                        <div class="mt-4">
                            <a href="/scan" class="btn">View Detailed Report</a>
                        </div>
                    </div>

                    <div class="card">
                        <h3 class="text-lg font-semibold mb-2">Vulnerability Breakdown</h3>
                        <ul>
                            ${Object.entries(severityDistribution).map(([severity, count]) => 
                                `<li><strong>${severity}:</strong> ${count} vulnerabilities</li>`
                            ).join('')}
                        </ul>
                    </div>
                `;
            }

            // Initialize dashboard
            document.addEventListener('DOMContentLoaded', renderDashboard);
        </script>
    </body>
    </html>
    '''
    from flask import Flask, jsonify, request, Response, render_template, send_from_directory


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
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Container Security Scanner</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 800px;
                margin: 0 auto;
                padding: 20px;
            }
            h1 {
                color: #2c5282;
            }
            .card {
                background-color: #f8f9fa;
                border-radius: 8px;
                padding: 20px;
                margin-bottom: 20px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            a {
                display: inline-block;
                background-color: #4299e1;
                color: white;
                padding: 10px 15px;
                border-radius: 4px;
                text-decoration: none;
                margin-right: 10px;
                margin-top: 10px;
            }
            a:hover {
                background-color: #3182ce;
            }
        </style>
    </head>
    <body>
        <h1>Container Security Scanner</h1>
        <div class="card">
            <h2>Python 3.9-slim Image Security Scanner</h2>
            <p>This application provides security scanning results for the Python 3.9-slim Docker image.</p>
            <a href="/dashboard">View Dashboard</a>
            <a href="/scan">View Scan Results</a>
            <a href="/status">View API Status</a>
        </div>
    </body>
    </html>
    '''


@app.route('/status')
def status():
    try:
        # Get vulnerability statistics from EC2 instance
        response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/stats")

        if response.status_code == 200:
            return jsonify(response.json())
        else:
            # Fallback to manual calculation if stats endpoint is not available
            response = requests.get(f"http://{EC2_INSTANCE_IP}:{EC2_PORT}/results")

            if response.status_code == 200:
                scan_data = response.json()

                # Count vulnerabilities by severity
                vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}

                for match in scan_data.get('matches', []):
                    severity = match.get('vulnerability', {}).get('severity', '').capitalize()
                    if severity in vuln_counts:
                        vuln_counts[severity] += 1
                    else:
                        vuln_counts["Unknown"] += 1

                # Get scan timestamp if available
                timestamp = scan_data.get('timestamp', 'Unknown')

                return jsonify({
                    "scan_time": timestamp,
                    "vulnerability_counts": vuln_counts,
                    "total_vulnerabilities": sum(vuln_counts.values()),
                    "critical_high_count": vuln_counts["Critical"] + vuln_counts["High"]
                })
            else:
                return jsonify({"error": f"Failed to fetch scan results: {response.status_code}"}), 500
    except Exception as e:
        return jsonify({"error": f"Error generating status: {str(e)}"}), 500


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