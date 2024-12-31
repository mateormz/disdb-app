import boto3
import hashlib
import uuid
from datetime import datetime, timedelta
import os
from boto3.dynamodb.conditions import Key
import json


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def generate_short_code():
    """Generates the first 8 characters of a UUID."""
    return str(uuid.uuid4())[:8].upper()


def lambda_handler(event, context):
    try:
        dynamodb = boto3.resource('dynamodb')
        user_table_name = os.environ['TABLE_USERS']
        token_table_name = os.environ['TABLE_TOKENS']
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
        role = body.get('role')  # 'distributor' or 'delivery_person'
        name = body.get('name')
        lastName = body.get('lastName')
        phoneNumber = body.get('phoneNumber')

        if not all([email, password, role, name, lastName, phoneNumber]):
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Missing required fields"}
            }

        # Validate the role
        if role not in ['distributor', 'delivery_person']:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Invalid role. Must be distributor or delivery_person"}
            }

        # Check if the email is already registered
        response = user_table.query(
            IndexName=os.environ['INDEX_EMAIL_USERS'],
            KeyConditionExpression=Key('email').eq(email)
        )

        if response['Items']:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "The email is already registered"}
            }

        # Create the user
        user_id = str(uuid.uuid4())
        if role == 'distributor':
            # Generate a unique short code
            while True:
                short_code = generate_short_code()
                code_check = user_table.query(
                    IndexName=os.environ['INDEX_SHORTCODE_USERS'],
                    KeyConditionExpression=Key('short_code').eq(short_code)
                )
                if not code_check['Items']:
                    break

            pk = user_id
            sk = 'metadata'
            item = {
                'PK': pk,
                'SK': sk,
                'email': email,
                'password_hash': hash_password(password),
                'role': role,
                'short_code': short_code,
                'name': name,
                'lastName': lastName,
                'phoneNumber': phoneNumber,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        else:  # role == 'delivery_person'
            pk = 'unassigned'
            sk = user_id
            item = {
                'PK': pk,
                'SK': sk,
                'email': email,
                'password_hash': hash_password(password),
                'role': role,
                'name': name,
                'lastName': lastName,
                'phoneNumber': phoneNumber,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

        # Save the user to DynamoDB
        user_table.put_item(Item=item)

        # Create a token
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