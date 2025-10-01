
#!/bin/bash

set -euo pipefail

# =======================
# Utility Functions
# =======================
print_info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
print_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
print_warning() { echo -e "\033[1;33m[WARNING]\033[0m $1"; }
print_error()   { echo -e "\033[1;31m[ERROR]\033[0m $1"; }

# Trap general errors
trap 'print_error "Script failed at line $LINENO"; exit 1' ERR

# =======================
# Input Variables
# =======================
NAMESPACE_NAME="mwaa-redshift-namespace"
WORKGROUP_NAME="mwaa-redshift-workgroup"
REGION="us-east-1"
DATABASE_NAME="mwaa_db"
ADMIN_USERNAME="adminuser"
ADMIN_PASSWORD=$(openssl rand -base64 16 | tr -d "=+/")1
SECRET_NAME="mwaa-redshift-secret"
IAM_ROLE_NAME="mwaa-redshift-role"
BASE_CAPACITY=32
SKIP_MWAA_SG=${SKIP_MWAA_SG:-false}
AWS_PROFILE_ARG=""

# =======================
# Functions
# =======================

create_namespace() {
  print_info "Creating Redshift Serverless namespace..."
  set +e
  OUTPUT=$(aws $AWS_PROFILE_ARG redshift-serverless create-namespace \
    --namespace-name "$NAMESPACE_NAME" \
    --db-name "$DATABASE_NAME" \
    --admin-username "$ADMIN_USERNAME" \
    --admin-user-password "$ADMIN_PASSWORD" \
    --iam-roles "$IAM_ROLE_ARN" \
    --region "$REGION" \
    --output json 2>&1)
  EXIT_CODE=$?
  set -e

  if [ $EXIT_CODE -ne 0 ]; then
    if echo "$OUTPUT" | grep -q "ConflictException"; then
      print_warning "Namespace already exists."
    else
      print_error "Namespace creation failed: $OUTPUT"
      exit 1
    fi
  else
    print_success "Namespace created."
  fi
}

create_workgroup() {
  print_info "Creating Redshift Serverless workgroup..."
  set +e
  OUTPUT=$(aws $AWS_PROFILE_ARG redshift-serverless create-workgroup \
    --workgroup-name "$WORKGROUP_NAME" \
    --namespace-name "$NAMESPACE_NAME" \
    --base-capacity "$BASE_CAPACITY" \
    --subnet-ids "$SUBNET_1" "$SUBNET_2" \
    --security-group-ids "$REDSHIFT_SG_ID" \
    --publicly-accessible false \
    --region "$REGION" \
    --output json 2>&1)
  EXIT_CODE=$?
  set -e

  if [ $EXIT_CODE -ne 0 ]; then
    if echo "$OUTPUT" | grep -q "ConflictException"; then
      print_warning "Workgroup already exists."
    else
      print_error "Workgroup creation failed: $OUTPUT"
      exit 1
    fi
  else
    print_success "Workgroup created."
  fi
}

create_secret() {
  print_info "Storing connection details in Secrets Manager..."
  SECRET_VALUE=$(jq -n \
    --arg host "$ENDPOINT" \
    --arg db "$DATABASE_NAME" \
    --arg user "$ADMIN_USERNAME" \
    --arg pass "$ADMIN_PASSWORD" \
    --arg wg "$WORKGROUP_NAME" \
    --arg ns "$NAMESPACE_NAME" \
    '{
      conn_type: "redshift_serverless",
      host: $host,
      port: 5439,
      database: $db,
      username: $user,
      password: $pass,
      workgroup_name: $wg,
      namespace_name: $ns
    }')

  set +e
  aws $AWS_PROFILE_ARG secretsmanager create-secret \
    --name "$SECRET_NAME" \
    --description "Redshift Serverless connection details for MWAA" \
    --secret-string "$SECRET_VALUE" \
    --region "$REGION" >/dev/null 2>&1
  EXIT_CODE=$?
  set -e

  if [ $EXIT_CODE -ne 0 ]; then
    print_warning "Secret already exists. Updating..."
    aws $AWS_PROFILE_ARG secretsmanager update-secret \
      --secret-id "$SECRET_NAME" \
      --secret-string "$SECRET_VALUE" \
      --region "$REGION"
  fi

  print_success "Secret stored in Secrets Manager: $SECRET_NAME"
}

# =======================
# VPC Setup
# =======================
print_info "Fetching VPC ID..."
VPC_ID=$(aws $AWS_PROFILE_ARG ec2 describe-vpcs \
  --query "Vpcs[0].VpcId" \
  --region "$REGION" \
  --output text)

print_info "Fetching Subnet IDs..."
SUBNETS=$(aws $AWS_PROFILE_ARG ec2 describe-subnets \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query "Subnets[].SubnetId" \
  --region "$REGION" \
  --output text)
SUBNET_1=$(echo "$SUBNETS" | awk '{print $1}')
SUBNET_2=$(echo "$SUBNETS" | awk '{print $2}')

# =======================
# Security Group
# =======================
REDSHIFT_SG_NAME="mwaa-redshift-sg"
if [ "$SKIP_MWAA_SG" = "false" ]; then
  print_info "Creating Security Group for Redshift..."
  set +e
  SG_OUTPUT=$(aws $AWS_PROFILE_ARG ec2 create-security-group \
    --group-name "$REDSHIFT_SG_NAME" \
    --description "Security group for Redshift Serverless workgroup" \
    --vpc-id "$VPC_ID" \
    --region "$REGION" 2>&1)
  EXIT_CODE=$?
  set -e

  if [ $EXIT_CODE -ne 0 ]; then
    if echo "$SG_OUTPUT" | grep -q "InvalidGroup.Duplicate"; then
      print_warning "Security group already exists."
      REDSHIFT_SG_ID=$(aws $AWS_PROFILE_ARG ec2 describe-security-groups \
        --filters "Name=group-name,Values=$REDSHIFT_SG_NAME" \
        --query "SecurityGroups[0].GroupId" \
        --region "$REGION" \
        --output text)
    else
      print_error "Failed to create Security Group: $SG_OUTPUT"
      exit 1
    fi
  else
    REDSHIFT_SG_ID=$(echo "$SG_OUTPUT" | jq -r '.GroupId')
    print_success "Created Security Group: $REDSHIFT_SG_ID"
  fi
else
  print_info "Skipping Security Group creation (using default)..."
  REDSHIFT_SG_ID=$(aws $AWS_PROFILE_ARG ec2 describe-security-groups \
    --filters "Name=vpc-id,Values=$VPC_ID" \
    --query "SecurityGroups[0].GroupId" \
    --region "$REGION" \
    --output text)
fi

# =======================
# IAM Role
# =======================
print_info "Creating IAM Role..."
set +e
IAM_OUTPUT=$(aws $AWS_PROFILE_ARG iam create-role \
  --role-name "$IAM_ROLE_NAME" \
  --assume-role-policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Effect":"Allow",
      "Principal":{"Service":"redshift-serverless.amazonaws.com"},
      "Action":"sts:AssumeRole"
    }]
  }' \
  --region "$REGION" 2>&1)
EXIT_CODE=$?
set -e

if [ $EXIT_CODE -ne 0 ]; then
  if echo "$IAM_OUTPUT" | grep -q "EntityAlreadyExists"; then
    print_warning "IAM Role already exists."
  else
    print_error "Failed to create IAM Role: $IAM_OUTPUT"
    exit 1
  fi
else
  print_success "IAM Role created: $IAM_ROLE_NAME"
fi

IAM_ROLE_ARN=$(aws $AWS_PROFILE_ARG iam get-role \
  --role-name "$IAM_ROLE_NAME" \
  --query "Role.Arn" \
  --output text \
  --region "$REGION")

print_info "Attaching AmazonS3ReadOnlyAccess policy to IAM Role..."
aws $AWS_PROFILE_ARG iam attach-role-policy \
  --role-name "$IAM_ROLE_NAME" \
  --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess \
  --region "$REGION"

# =======================
# Redshift Setup
# =======================
create_namespace
create_workgroup

# Fetch workgroup details
print_info "Fetching Redshift endpoint..."
ENDPOINT=$(aws $AWS_PROFILE_ARG redshift-serverless get-workgroup \
  --workgroup-name "$WORKGROUP_NAME" \
  --region "$REGION" \
  --query "workgroup.endpoint.address" \
  --output text)

# =======================
# Secrets Manager
# =======================
create_secret

# =======================
# Summary
# =======================
print_success "Setup complete!"

cat <<EOF

Redshift Serverless Setup Summary:
---------------------------------
Namespace:      $NAMESPACE_NAME
Workgroup:      $WORKGROUP_NAME
Database:       $DATABASE_NAME
Admin User:     $ADMIN_USERNAME
Endpoint:       $ENDPOINT
IAM Role:       $IAM_ROLE_ARN
Secret Name:    $SECRET_NAME
Region:         $REGION
EOF
```
