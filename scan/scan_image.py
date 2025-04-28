#!/usr/bin/env python3
import subprocess
import json
import csv
import os
import argparse
from datetime import datetime


def run_command(command):
    """Run a shell command and return the output"""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {command}")
        print(f"Error: {e}")
        print(f"STDERR: {e.stderr}")
        return None


def pull_docker_image(image_name):
    """Pull a Docker image from a public registry"""
    print(f"Pulling Docker image: {image_name}")
    return run_command(f"docker pull {image_name}")


def scan_with_grype(image_name, output_file="vulnerability_scan.json"):
    """Scan the Docker image with Grype and save results to a JSON file"""
    print(f"Scanning image with Grype: {image_name}")
    result = run_command(f"grype {image_name} -o json > {output_file}")
    if not result:
        # Grype outputs directly to file, so we don't use the result
        # Just check if the file exists
        if os.path.exists(output_file):
            print(f"Scan complete. Results saved to {output_file}")
            return output_file
        else:
            print("Error: Scan results file not found")
            return None
    return output_file


def generate_sbom_with_syft(image_name, output_file="sbom.json"):
    """Generate a Software Bill of Materials (SBOM) using Syft"""
    print(f"Generating SBOM with Syft: {image_name}")
    result = run_command(f"syft {image_name} -o json > {output_file}")
    if not result:
        # Syft outputs directly to file, so we don't use the result
        # Just check if the file exists
        if os.path.exists(output_file):
            print(f"SBOM generation complete. Results saved to {output_file}")
            return output_file
        else:
            print("Error: SBOM file not found")
            return None
    return output_file


def parse_critical_and_high_vulnerabilities(input_file, output_json="critical_high_vulns.json",
                                            output_csv="critical_high_vulns.csv"):
    """Parse the Grype scan results and extract critical and high vulnerabilities"""
    print(f"Parsing critical and high vulnerabilities from: {input_file}")
    try:
        with open(input_file, 'r') as f:
            scan_data = json.load(f)

        # Extract critical and high vulnerabilities
        critical_high_vulns = []
        for match in scan_data.get('matches', []):
            severity = match.get('vulnerability', {}).get('severity', '').upper()
            if severity in ['CRITICAL', 'HIGH']:
                vuln = {
                    'id': match.get('vulnerability', {}).get('id', 'N/A'),
                    'severity': severity,
                    'package': match.get('artifact', {}).get('name', 'N/A'),
                    'version': match.get('artifact', {}).get('version', 'N/A'),
                    'type': match.get('artifact', {}).get('type', 'N/A'),
                    'fixed_version': match.get('vulnerability', {}).get('fix', {}).get('versions', ['N/A'])[
                        0] if match.get('vulnerability', {}).get('fix', {}).get('versions') else 'N/A',
                    'description': match.get('vulnerability', {}).get('description', 'N/A')
                }
                critical_high_vulns.append(vuln)

        # Save as JSON
        with open(output_json, 'w') as f:
            json.dump(critical_high_vulns, f, indent=2)

        # Save as CSV
        if critical_high_vulns:
            with open(output_csv, 'w', newline='') as f:
                fieldnames = critical_high_vulns[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(critical_high_vulns)
        else:
            # Create an empty CSV with headers if no vulnerabilities found
            with open(output_csv, 'w', newline='') as f:
                fieldnames = ['id', 'severity', 'package', 'version', 'type', 'fixed_version', 'description']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()

        print(f"Found {len(critical_high_vulns)} critical/high vulnerabilities")
        print(f"Results saved to {output_json} and {output_csv}")

        return critical_high_vulns
    except Exception as e:
        print(f"Error parsing vulnerabilities: {str(e)}")
        return []


def upload_to_s3(file_path, bucket_name, object_key=None):
    """Upload a file to an S3 bucket"""
    if not object_key:
        object_key = os.path.basename(file_path)

    print(f"Uploading {file_path} to S3 bucket {bucket_name} as {object_key}")
    return run_command(f"aws s3 cp {file_path} s3://{bucket_name}/{object_key}")


def main():
    parser = argparse.ArgumentParser(description='Scan a Docker image and generate reports')
    parser.add_argument('--image', default='python:3.9-slim', help='Docker image to scan (default: python:3.9-slim)')
    parser.add_argument('--s3-bucket', help='S3 bucket to upload results to (optional)')
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_output = f"vulnerability_scan_{timestamp}.json"
    sbom_output = f"sbom_{timestamp}.json"
    critical_high_json = f"critical_high_vulns_{timestamp}.json"
    critical_high_csv = f"critical_high_vulns_{timestamp}.csv"

    # Create symlinks for the latest files
    latest_scan = "vulnerability_scan.json"
    latest_sbom = "sbom.json"
    latest_critical_high_json = "critical_high_vulns.json"
    latest_critical_high_csv = "critical_high_vulns.csv"

    # Pull the Docker image
    pull_docker_image(args.image)

    # Scan with Grype
    scan_file = scan_with_grype(args.image, scan_output)
    if scan_file:
        if os.path.exists(latest_scan) and os.path.islink(latest_scan):
            os.unlink(latest_scan)
        os.symlink(scan_output, latest_scan)

    # Generate SBOM with Syft
    sbom_file = generate_sbom_with_syft(args.image, sbom_output)
    if sbom_file:
        if os.path.exists(latest_sbom) and os.path.islink(latest_sbom):
            os.unlink(latest_sbom)
        os.symlink(sbom_output, latest_sbom)

    # Parse critical and high vulnerabilities
    if scan_file:
        vulnerabilities = parse_critical_and_high_vulnerabilities(scan_file, critical_high_json, critical_high_csv)

        # Create symlinks for the latest files
        if os.path.exists(latest_critical_high_json) and os.path.islink(latest_critical_high_json):
            os.unlink(latest_critical_high_json)
        os.symlink(critical_high_json, latest_critical_high_json)

        if os.path.exists(latest_critical_high_csv) and os.path.islink(latest_critical_high_csv):
            os.unlink(latest_critical_high_csv)
        os.symlink(critical_high_csv, latest_critical_high_csv)

        print("Summary of critical and high vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"{vuln['id']} ({vuln['severity']}) - {vuln['package']} {vuln['version']}")

    # Upload to S3 if bucket is specified
    if args.s3_bucket:
        if scan_file:
            upload_to_s3(scan_file, args.s3_bucket, f"scans/{os.path.basename(scan_file)}")
        if sbom_file:
            upload_to_s3(sbom_file, args.s3_bucket, f"sboms/{os.path.basename(sbom_file)}")


if __name__ == "__main__":
    main()