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
        print("[INFO] Received event:", json.dumps(event, indent=2))

        # Initialize DynamoDB
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            user_table_name = os.environ['TABLE_USERS']
            token_table_name = os.environ['TABLE_TOKENS']
            email_index = os.environ['INDEX_EMAIL_USERS']
            short_code_index = os.environ['INDEX_SHORTCODE_USERS']
            print("[INFO] Environment variables loaded successfully")
            print(f"[DEBUG] User table name: {user_table_name}")
            print(f"[DEBUG] Token table name: {token_table_name}")
            print(f"[DEBUG] Email index: {email_index}")
            print(f"[DEBUG] Short code index: {short_code_index}")
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
            body = json.loads(event['body'])
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
        role = body.get('role')  # 'distributor' or 'delivery_person'
        name = body.get('name')
        lastName = body.get('lastName')
        phoneNumber = body.get('phoneNumber')

        print(f"[DEBUG] Parsed email: {email}")
        print(f"[DEBUG] Parsed password: {password}")
        print(f"[DEBUG] Parsed role: {role}")
        print(f"[DEBUG] Parsed name: {name}")
        print(f"[DEBUG] Parsed lastName: {lastName}")
        print(f"[DEBUG] Parsed phoneNumber: {phoneNumber}")

        if not all([email, password, role, name, lastName, phoneNumber]):
            print("[WARNING] Missing required fields")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Missing required fields'})
            }

        # Validate the role
        if role not in ['distributor', 'delivery_person']:
            print("[WARNING] Invalid role provided")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Invalid role. Must be distributor or delivery_person'})
            }

        # Check if the email is already registered
        print(f"[INFO] Checking if email is already registered: {email}")
        response = user_table.query(
            IndexName=email_index,
            KeyConditionExpression=Key('email').eq(email)
        )
        print(f"[DEBUG] Email query response: {response}")

        if response['Items']:
            print("[WARNING] Email is already registered")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'The email is already registered'})
            }

        # Create the user
        user_id = str(uuid.uuid4())
        if role == 'distributor':
            # Generate a unique short code
            print("[INFO] Generating unique short code")
            while True:
                short_code = generate_short_code()
                code_check = user_table.query(
                    IndexName=short_code_index,
                    KeyConditionExpression=Key('short_code').eq(short_code)
                )
                if not code_check['Items']:
                    break
            print(f"[DEBUG] Generated short code: {short_code}")

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

        print(f"[INFO] Saving user to DynamoDB: {item}")
        user_table.put_item(Item=item)

        # Create a token
        token = str(uuid.uuid4())
        expiration = (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
        print(f"[INFO] Token generated: {token}, Expiration: {expiration}")

        print("[INFO] Storing token in DynamoDB")
        token_table.put_item(
            Item={
                'token': token,
                'expiration': expiration
            }
        )

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

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }
