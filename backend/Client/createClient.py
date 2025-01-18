import boto3
import uuid
import os
import json
from datetime import datetime

def lambda_handler(event, context):
    try:
        print("[INFO] Received event:", json.dumps(event, indent=2))

        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            client_table_name = os.environ['TABLE_CLIENTS']
            user_table_name = os.environ['TABLE_USERS']
            validate_function_name = f"{os.environ['USER_API']}-{os.environ['STAGE']}-{os.environ['VALIDATE_TOKEN_FUNCTION']}"
            print("[INFO] Environment variables loaded successfully")
        except KeyError as env_error:
            print(f"[ERROR] Missing environment variable: {str(env_error)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f"Missing environment variable: {str(env_error)}"})
            }

        client_table = dynamodb.Table(client_table_name)
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

        # Validate token
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

        # Extract authenticated user information
        user_info = json.loads(validation_result.get('body', '{}'))
        authenticated_pk = user_info.get('PK')
        authenticated_role = user_info.get('role')
        print(f"[INFO] Authenticated user PK: {authenticated_pk}, Role: {authenticated_role}")

        if authenticated_role != 'distributor':
            print("[WARNING] User is not authorized to create clients")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - Only distributors can create clients'})
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

        # Extract fields from request body
        name = body.get('Nombre')
        lastName = body.get('Apellido')
        dni = body.get('DNI')
        phoneNumber = body.get('Teléfono')
        email = body.get('Email')
        address = body.get('Dirección')
        distributor = body.get('Distributor')

        if not all([name, lastName, dni, phoneNumber, email, address, distributor]):
            print("[WARNING] Missing required fields")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing required fields'})
            }

        # Ensure the authenticated user is creating clients under their own distributor account
        if distributor != authenticated_pk:
            print("[WARNING] User is attempting to create clients for an unauthorized distributor")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - You can only create clients under your own distributor account'})
            }

        # Generate a unique ID for the client
        client_id = str(uuid.uuid4())

        # Create client item
        item = {
            'PK': distributor,
            'SK': client_id,
            'Nombre': name,
            'Apellido': lastName,
            'DNI': dni,
            'Teléfono': phoneNumber,
            'Email': email,
            'Dirección': address,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

        print(f"[INFO] Saving client to DynamoDB: {item}")
        client_table.put_item(Item=item)

        print("[INFO] Returning successful response")
        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Client created successfully',
                'PK': distributor,
                'SK': client_id,
                'Nombre': name,
                'Apellido': lastName,
                'DNI': dni,
                'Teléfono': phoneNumber,
                'Email': email,
                'Dirección': address,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
        }

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }