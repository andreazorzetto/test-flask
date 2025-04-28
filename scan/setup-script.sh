#!/bin/bash

# Update system packages
echo "Updating system packages..."
sudo apt-get update
sudo apt-get upgrade -y

# Install Docker
echo "Installing Docker..."
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt-get update
sudo apt-get install -y docker-ce
sudo usermod -aG docker $USER
sudo systemctl enable docker
sudo systemctl start docker

# Install Python and pip
echo "Installing Python and dependencies..."
sudo apt-get install -y python3 python3-pip
pip3 install flask requests

# Install AWS CLI
echo "Installing AWS CLI..."
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo apt-get install -y unzip
unzip awscliv2.zip
sudo ./aws/install

# Install Grype and Syft
echo "Installing Grype and Syft..."
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Copy the scanning script
echo "Setting up scanning script..."
mkdir -p ~/docker-scan
cp scan_image.py ~/docker-scan/
cp ec2_server.py ~/docker-scan/
chmod +x ~/docker-scan/scan_image.py

# Create a directory for templates
mkdir -p ~/docker-scan/templates
mkdir -p ~/docker-scan/static

# Create a configuration file for the EC2 server
cat << EOF > ~/docker-scan/config.json
{
  "scan_results_path": "vulnerability_scan.json",
  "sbom_path": "sbom.json",
  "critical_high_vulns_path": "critical_high_vulns.json",
  "port": 8000,
  "allowed_origins": ["*"]
}
EOF

# Create a systemd service for the EC2 server
echo "Creating EC2 server service..."
cat << EOF > /tmp/ec2-server.service
[Unit]
Description=EC2 Server for Docker Image Scanning
After=network.target

[Service]
User=$USER
WorkingDirectory=~/docker-scan
ExecStart=$(which python3) ec2_server.py
Restart=always
Environment=PORT=8000

[Install]
WantedBy=multi-user.target
EOF

sudo mv /tmp/ec2-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ec2-server
sudo systemctl start ec2-server

# Run the first scan
echo "Running initial Docker image scan..."
cd ~/docker-scan
./scan_image.py --image python:3.9-slim

echo "Setup complete!"
echo "EC2 server running at http://localhost:8000"
echo "Scan results available at http://localhost:8000/results"
echo "SBOM available at http://localhost:8000/sbom"