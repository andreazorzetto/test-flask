#!/bin/bash

# Variables
AWS_REGION=${AWS_REGION:-"us-east-1"}
ECR_REPOSITORY="flask-app"
IMAGE_TAG="latest"
EC2_INSTANCE_IP=$1  # Pass EC2 instance public IP as first argument

# Check if EC2 IP is provided
if [ -z "$EC2_INSTANCE_IP" ]; then
    echo "Error: EC2 instance IP is required."
    echo "Usage: $0 <ec2_instance_ip>"
    exit 1
fi

# Build Docker image
echo "Building Docker image..."
docker build -t $ECR_REPOSITORY:$IMAGE_TAG .

# Push to ECR (uncomment and configure if using ECR)
# echo "Logging in to ECR..."
# aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com

# echo "Creating ECR repository if it doesn't exist..."
# aws ecr describe-repositories --repository-names $ECR_REPOSITORY --region $AWS_REGION || \
#     aws ecr create-repository --repository-name $ECR_REPOSITORY --region $AWS_REGION

# echo "Tagging and pushing Docker image to ECR..."
# docker tag $ECR_REPOSITORY:$IMAGE_TAG $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG
# docker push $AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com/$ECR_REPOSITORY:$IMAGE_TAG

# Deploy to Kubernetes
echo "Deploying to Kubernetes..."

# Update Kubernetes config files with EC2 instance IP
sed -i "s/\${EC2_INSTANCE_IP}/$EC2_INSTANCE_IP/g" deployment.yaml

# Replace the ECR repository placeholder with the local image if not using ECR
sed -i "s|\${AWS_ACCOUNT_ID}.dkr.ecr.\${AWS_REGION}.amazonaws.com/flask-app:latest|flask-app:latest|g" deployment.yaml
sed -i "s/# image: flask-app:latest/image: flask-app:latest/g" deployment.yaml
sed -i "s/# imagePullPolicy: Never/imagePullPolicy: Never/g" deployment.yaml

# Apply Kubernetes configuration
kubectl apply -f secret.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml

# Wait for deployment to be ready
echo "Waiting for deployment to be ready..."
kubectl rollout status deployment/flask-app

# Get service information
echo "Getting service information..."
kubectl get service flask-app

echo "Deployment complete! The application should be accessible at the LoadBalancer external IP on port 80."
echo "Use basic auth with the credentials configured in secret.yaml."
