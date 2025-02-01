"""
AWS Lambda function to retrieve OAuth credentials from AWS Secrets Manager
and request an OAuth token from the vendor's OAuth2 endpoint.
"""

import json
import os
import time
import boto3
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from botocore.exceptions import ClientError
from urllib.parse import urlencode

# AWS Secrets Manager Client
secrets_client = boto3.client("secretsmanager")
ssm_client = boto3.client("ssm")

# Vendor OAuth Token URL (Updated from API Documentation)
VENDOR_TOKEN_URL = "https://sandboxapi.1link.net.pk/uat-1link/sandbox/oauth2/token"

# Correct Host Header (Based on API Docs)
HOST = "https://sandboxapi.1link.net.pk"

ONE_HOUR_GRACE_PERIOD = 3600

# Configure Retry Policy for Transient Failures
retry_strategy = Retry(
    total=3,
    status_forcelist=[500, 502, 503, 504],  # Retries on these HTTP errors
    allowed_methods=["POST"],
)
adapter = HTTPAdapter(max_retries=retry_strategy)
session = requests.Session()
session.mount("https://", adapter)


def get_oauth_credentials():
    """Retrieve OAuth credentials securely from AWS Secrets Manager."""
    secret_name = os.getenv("SECRET_NAME")

    try:
        response = secrets_client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response["SecretString"])
        return secret["CLIENT_ID"], secret["CLIENT_SECRET"]
    except Exception as e:
        print(f"Error retrieving secret: {str(e)}")
        raise


def set_token_in_ssm(token, expires_in):
    """Store OAuth token securely in AWS Systems Manager Parameter Store."""
    try:
        ssm_client.put_parameter(
            Name="/oauth/token", Value=token, Type="SecureString", Overwrite=True
        )
        ssm_client.put_parameter(
            Name="/oauth/token_expiry",
            Value=str(time.time() + expires_in - ONE_HOUR_GRACE_PERIOD),
            Type="String",
            Overwrite=True,
        )
        print("Token stored successfully")
    except ClientError as e:
        print(f"Error storing token in SSM: {str(e)}")
        raise


def get_valid_token():
    """Check if OAuth token stored in AWS Systems Manager Parameter Store is valid."""
    try:
        response = ssm_client.get_parameter(Name="/oauth/token", WithDecryption=True)
        expiry_response = ssm_client.get_parameter(Name="/oauth/token_expiry")
        # Calculate expiry time (1 hour before actual expiry)
        expiry_time = (
            float(expiry_response["Parameter"]["Value"]) - ONE_HOUR_GRACE_PERIOD
        )
        current_time = time.time()

        if current_time < expiry_time:
            print(
                f"Token is still valid until: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expiry_time))}"
            )
            return {
                "access_token": response["Parameter"]["Value"],
                "expires_in": expiry_response["Parameter"]["Value"],
            }
        print("Token expired")
        return None
    except ClientError as e:
        print(f"Error retrieving token from SSM: {str(e)}")
        return None


def return_success(token):
    """Return a successful response with the OAuth token."""
    return {
        "statusCode": 200,
        "body": json.dumps(token),
    }


def return_error(status_code, error_message):
    """Return an error response with the error message."""
    return {
        "statusCode": status_code,
        "body": json.dumps({"error": error_message}),
    }


def main(event, context):
    """Main Lambda handler to request OAuth token from vendor's API."""
    client_id, client_secret = get_oauth_credentials()

    # check if we have a valid token in SSM or not
    token = get_valid_token()

    if token:
        return return_success(token)

    print("Requesting new token")

    # OAuth2 Token Request Payload
    # Convert data dictionary into URL-encoded format
    data_encoded = urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "1LinkApi",
        }
    )

    # OAuth2 Headers (With Correct Host Header)
    headers = {
        "X-IBM-Client-Id": client_id,
        "Content-Type": "application/x-www-form-urlencoded",
    }

    try:
        response = session.post(VENDOR_TOKEN_URL, data=data_encoded, headers=headers)

        if response.status_code != 200:
            print(f"OAuth request failed: {response.text}")
            return return_error(
                response.status_code,
                {"error": "OAuth request failed", "details": response.text},
            )

        token_response = response.json()
        set_token_in_ssm(token_response["access_token"], token_response["expires_in"])

        return return_success(token_response)

    except requests.exceptions.SSLError as ssl_error:
        print(f"SSL Error: {ssl_error}")

        return return_error(
            502, {"error": "SSL handshake failed, possible incorrect SNI."}
        )

    except requests.exceptions.RequestException as req_error:
        print(f"HTTP Request Error: {req_error}")
        return return_error(
            500, {"error": "OAuth request failed", "details": str(req_error)}
        )
