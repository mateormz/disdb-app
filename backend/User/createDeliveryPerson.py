import boto3
import uuid
import os
from datetime import datetime
import hashlib
import json
from boto3.dynamodb.conditions import Key

def lambda_handler(event, context):
    try:
        print("[INFO] Received event:", json.dumps(event, indent=2))

        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            user_table_name = os.environ['TABLE_USERS']
            email_index = os.environ['INDEX_EMAIL_USERS']
            validate_function_name = f"{os.environ['SERVICE_NAME']}-{os.environ['STAGE']}-{os.environ['VALIDATE_TOKEN_FUNCTION']}"
            print("[INFO] Environment variables loaded successfully")
        except KeyError as env_error:
            print(f"[ERROR] Missing environment variable: {str(env_error)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f"Missing environment variable: {str(env_error)}"})
            }

        user_table = dynamodb.Table(user_table_name)

        # Extract Authorization token
        token = event.get('headers', {}).get('Authorization')
        print(f"[DEBUG] Authorization token: {token}")
        if not token:
            print("[WARNING] Authorization token is missing")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Authorization token is missing'})
            }

        # Invoke validateToken function
        lambda_client = boto3.client('lambda')
        payload = {"body": json.dumps({"token": token})}
        print("[INFO] Invoking validateToken function with payload:", json.dumps(payload))

        validate_response = lambda_client.invoke(
            FunctionName=validate_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        validation_result = json.loads(validate_response['Payload'].read())
        print("[INFO] Validation function response received:", validation_result)

        if validation_result.get('statusCode') != 200:
            print("[WARNING] Token validation failed")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - Invalid or expired token'})
            }

        # Extract user information from validation response
        user_info = json.loads(validation_result.get('body', '{}'))
        role = user_info.get('role')
        print(f"[DEBUG] User role: {role}")

        if role != 'distributor':
            print("[WARNING] User is not authorized to create delivery persons")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - Only distributors can create delivery persons'})
            }

        # Parse request body
        if 'body' not in event or not event['body']:
            print("[WARNING] Request body is missing")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Request body is missing'})
            }

        try:
            body = json.loads(event['body'])
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse JSON body: {str(e)}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid JSON in request body'})
            }

        pk = body.get('pk')
        name = body.get('name')
        lastName = body.get('lastName')
        phoneNumber = body.get('phoneNumber')
        email = body.get('email')
        password = body.get('password')
        dni = body.get('dni')

        if not all([pk, name, lastName, phoneNumber, email, password, dni]):
            print("[WARNING] Missing required fields")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing required fields'})
            }

        # Verify that the PK corresponds to an existing distributor
        print(f"[INFO] Verifying if PK={pk} corresponds to a distributor")
        distributor_response = user_table.get_item(
            Key={
                'PK': pk,
                'SK': 'metadata'
            }
        )
        print(f"[DEBUG] Distributor query response: {distributor_response}")

        if 'Item' not in distributor_response or distributor_response['Item'].get('role') != 'distributor':
            print("[WARNING] The provided PK does not belong to a valid distributor")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Invalid PK - No distributor found with the provided PK'})
            }

        # Check if the email is already registered
        print(f"[INFO] Checking if email is already registered: {email}")
        email_response = user_table.query(
            IndexName=email_index,
            KeyConditionExpression=Key('email').eq(email)
        )
        print(f"[DEBUG] Email query response: {email_response}")

        if email_response['Items']:
            print("[WARNING] Email is already registered")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'The email is already registered'})
            }

        # Create the delivery person
        delivery_person_id = str(uuid.uuid4())
        sk = delivery_person_id
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        item = {
            'PK': pk,
            'SK': sk,
            'email': email,
            'password_hash': hashed_password,
            'role': 'delivery_person',
            'name': name,
            'lastName': lastName,
            'phoneNumber': phoneNumber,
            'dni': dni,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        print(f"[INFO] Saving delivery person to DynamoDB: {item}")
        user_table.put_item(Item=item)

        print("[INFO] Returning successful response")
        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Delivery person created successfully',
                'PK': pk,
                'SK': sk
            })
        }

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }