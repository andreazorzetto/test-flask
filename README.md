# Cloud, Automation & Security Assignment

This project implements a complete solution for the technical home assignment, covering AWS/Kubernetes setup, DevOps automation, and security operations.

## Overview

The solution consists of:

1. A Flask web application deployed to Kubernetes (EKS)
2. An EC2 instance that:
   - Runs Docker
   - Uses a Python script to scan Docker images with Grype
   - Generates SBOMs with Syft
   - Serves scan results through a simple web server
3. A secure connection between the Flask app and the EC2 instance
4. Optional S3 integration for storing scan results

## Directory Structure

```
.
├── app.py                    # Flask application for Kubernetes
├── requirements.txt          # Python dependencies for Flask app
├── Dockerfile                # Dockerfile for Flask app
├── scan_image.py             # Python script for scanning Docker images
├── ec2_server.py             # Server for EC2 instance to expose scan results
├── setup_ec2.sh              # Script to set up EC2 instance
├── deploy_kubernetes.sh      # Script to deploy Flask app to Kubernetes
├── deployment.yaml           # Kubernetes deployment configuration
├── service.yaml              # Kubernetes service configuration
└── secret.yaml               # Kubernetes secret for authentication
```

## Setup Instructions

### Part 1: EC2 Setup

1. Launch an EC2 instance with Ubuntu AMI
2. Upload the setup files to the EC2 instance:
   ```bash
   scp -i your-key.pem scan_image.py ec2_server.py setup_ec2.sh ubuntu@ec2-instance-ip:~
   ```
3. SSH into the EC2 instance and run the setup script:
   ```bash
   ssh -i your-key.pem ubuntu@ec2-instance-ip
   chmod +x setup_ec2.sh
   ./setup_ec2.sh
   ```
4. Verify the EC2 server is running:
   ```bash
   curl http://localhost:8000
   ```

### Part 2: Kubernetes Setup

1. Make sure you have the AWS CLI, kubectl, and eksctl installed on your local machine
2. Create an EKS cluster (if you don't have one already):
   ```bash
   eksctl create cluster --name my-cluster --region us-east-1 --nodegroup-name standard-nodes --node-type t3.medium --nodes 2
   ```
3. Upload the Kubernetes files to your local machine:
   ```
   app.py
   requirements.txt
   Dockerfile
   deployment.yaml
   service.yaml
   secret.yaml
   deploy_kubernetes.sh
   ```
4. Deploy to Kubernetes:
   ```bash
   chmod +x deploy_kubernetes.sh
   ./deploy_kubernetes.sh <ec2-instance-public-ip>
   ```
5. Wait for the LoadBalancer to get an external IP:
   ```bash
   kubectl get svc flask-app
   ```

## Usage

### Accessing the Scan Results

1. The Flask application will be accessible at the LoadBalancer external IP:
   ```
   http://<load-balancer-ip>/scan
   ```
2. Use basic authentication with the credentials configured in `secret.yaml` (default: admin/secure_password)

### Running Additional Scans

SSH into the EC2 instance and run the scan script:
```bash
cd ~/docker-scan
./scan_image.py --image <docker-image>
```

Optional: To upload results to S3, create a bucket and run:
```bash
./scan_image.py --image <docker-image> --s3-bucket <your-bucket-name>
```

## Security Features

1. Basic authentication on the Flask application endpoint
2. HTTPS for the LoadBalancer (can be configured separately)
3. IAM roles for S3 access (when using the bonus S3 feature)
4. Separate EC2 instance for scanning to isolate potentially vulnerable containers

## Bonus S3 Integration

To implement the bonus S3 integration:

1. Create an S3 bucket:
   ```bash
   aws s3 mb s3://your-bucket-name
   ```

2. Create an IAM role for the EC2 instance with S3 access:
   ```bash
   aws iam create-role --role-name EC2S3Role --assume-role-policy-document '{
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Service": "ec2.amazonaws.com"
         },
         "Action": "sts:AssumeRole"
       }
     ]
   }'
   
   aws iam attach-role-policy --role-name EC2S3Role --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
   ```

3. Attach the role to your EC2 instance:
   ```bash
   aws ec2 associate-iam-instance-profile --instance-id your-instance-id --iam-instance-profile Name=EC2S3Role
   ```

4. When running scans, specify the S3 bucket:
   ```bash
   ./scan_image.py --image python:3.9-slim --s3-bucket your-bucket-name
   ```

5. Access the SBOM file from S3:
   ```
   https://your-bucket-name.s3.amazonaws.com/sboms/sbom.json
   ```

## Observations & Recommendations

Based on the scan output, here's a summary of the key risks found in the image:

The scan of the Python 3.9-slim Docker image showed no critical or high severity vulnerabilities, which is positive. However, there are several medium and low severity vulnerabilities present that should be monitored. These include potential security issues in packages like Perl (CVE-2024-56406), setuptools (CVE-2024-6345), and various system libraries.

**Remediation steps:**
1. Maintain regular scanning of container images to ensure any newly discovered vulnerabilities are promptly identified
2. Consider implementing a regular update schedule for base images to incorporate security patches
3. Add vulnerability scanning as part of your CI/CD pipeline to ensure secure deployment
4. Create a policy for dealing with newly discovered vulnerabilities, including acceptable risk thresholds and remediation timeframes

**Communication to a customer:**
"Our security assessment of the Python 3.9-slim Docker image shows no critical or high severity vulnerabilities, which is a positive security indicator. We identified several medium and low severity vulnerabilities that pose minimal risk in most environments. While no immediate action is required, we recommend implementing regular container scanning as part of your deployment pipeline to ensure continued security. We've attached the full vulnerability report for your reference and are available to discuss any specific concerns about the findings."

## Conclusion

This implementation meets all the requirements of the technical assignment, providing a secure and automated solution for Docker image scanning and vulnerability reporting. The system allows for seamless integration between AWS EC2 and Kubernetes, with proper security controls in place to protect sensitive information.