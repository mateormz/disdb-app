import boto3
import hashlib
import uuid
from datetime import datetime, timedelta
import os
from boto3.dynamodb.conditions import Key
import json

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def lambda_handler(event, context):
    try:
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        user_table_name = os.environ['TABLE_USERS']
        token_table_name = os.environ['TABLE_TOKENS']
        email_index = os.environ['INDEX_EMAIL_USERS']

        user_table = dynamodb.Table(user_table_name)
        token_table = dynamodb.Table(token_table_name)

        # Parse the request body
        body = event.get('body')
        if not body:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Request body is missing"}
            }

        body = json.loads(body)
        email = body.get('email')
        password = body.get('password')

        if not all([email, password]):
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Missing required fields"}
            }

        # Hash the password
        hashed_password = hash_password(password)

        # Query the user by email using the global secondary index
        response = user_table.query(
            IndexName=email_index,
            KeyConditionExpression=Key('email').eq(email)
        )

        # Validate credentials
        if not response['Items'] or response['Items'][0]['password_hash'] != hashed_password:
            return {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Invalid credentials"}
            }

        # Get user data
        user = response['Items'][0]
        pk = user['PK']
        sk = user['SK']
        role = user['role']

        # Create token
        token = str(uuid.uuid4())
        expiration = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')

        # Store the token in the tokens table
        token_table.put_item(
            Item={
                'token': token,
                'expiration': expiration
            }
        )

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {
                "token": token,
                "expires": expiration,
                "PK": pk,
                "SK": sk,
                "role": role
            }
        }

    except Exception as e:
        print("Error:", str(e))
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Internal Server Error", "details": str(e)}
        }