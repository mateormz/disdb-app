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
        print("[INFO] Received event:", json.dumps(event, indent=2))

        # Initialize DynamoDB
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            user_table_name = os.environ['TABLE_USERS']
            token_table_name = os.environ['TABLE_TOKENS']
            email_index = os.environ['INDEX_EMAIL_USERS']
            print("[INFO] Environment variables loaded successfully")
            print(f"[DEBUG] User table name: {user_table_name}")
            print(f"[DEBUG] Token table name: {token_table_name}")
            print(f"[DEBUG] Email index: {email_index}")
        except KeyError as env_error:
            print(f"[ERROR] Missing environment variable: {str(env_error)}")
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': f"Missing environment variable: {str(env_error)}"})
            }

        user_table = dynamodb.Table(user_table_name)
        token_table = dynamodb.Table(token_table_name)

        # Parse request body
        if 'body' not in event or not event['body']:
            print("[WARNING] Request body is missing")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Request body is missing'})
            }

        try:
            body = json.loads(event['body'])  # Parse the string body to a Python dictionary
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse JSON body: {str(e)}")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Invalid JSON in request body'})
            }

        email = body.get('email')
        password = body.get('password')
        print(f"[DEBUG] Email: {email}, Password: {'*' * len(password) if password else None}")

        if not all([email, password]):
            print("[WARNING] Missing required fields")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Missing required fields'})
            }

        # Hash the password
        hashed_password = hash_password(password)
        print(f"[DEBUG] Hashed password: {hashed_password}")

        # Query the user by email
        print(f"[INFO] Querying user table for email: {email}")
        response = user_table.query(
            IndexName=email_index,
            KeyConditionExpression=Key('email').eq(email)
        )
        print(f"[DEBUG] Query response: {response}")

        # Validate credentials
        if not response['Items'] or response['Items'][0]['password_hash'] != hashed_password:
            print("[WARNING] Invalid credentials")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Invalid credentials'})
            }

        # Get user data
        user = response['Items'][0]
        print(f"[INFO] User retrieved: {user}")

        pk = user['PK']
        sk = user['SK']
        role = user['role']

        # Create token
        token = str(uuid.uuid4())
        expiration = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[INFO] Token generated: {token}, Expiration: {expiration}")

        # Store the token in the tokens table
        print("[INFO] Storing token in token table")
        token_table.put_item(
            Item={
                'token': token,
                'expiration': expiration,
                'role': role,
                'pk': pk,
                'sk': sk
            }
        )

        # Return success response
        print("[INFO] Returning successful response")
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'token': token,
                'expires': expiration,
                'PK': pk,
                'SK': sk,
                'role': role
            })
        }

    except KeyError as e:
        print(f"[ERROR] KeyError encountered: {str(e)}")
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': f'Missing field: {str(e)}'})
        }
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }