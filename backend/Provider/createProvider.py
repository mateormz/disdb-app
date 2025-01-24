import boto3
import uuid
import os
import json
from datetime import datetime

def create_provider_handler(event, context):
    try:
        print("[INFO] Received event:", json.dumps(event, indent=2))

        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            provider_table_name = os.environ['TABLE_PROVIDERS']
            validate_function_name = f"{os.environ['USER_API']}-{os.environ['STAGE']}-{os.environ['VALIDATE_TOKEN_FUNCTION']}"
            print("[INFO] Environment variables loaded successfully")
        except KeyError as env_error:
            print(f"[ERROR] Missing environment variable: {str(env_error)}")
            return {
                'statusCode': 500,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f"Missing environment variable: {str(env_error)}"})
            }

        provider_table = dynamodb.Table(provider_table_name)

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

        # Ensure only distributors can access this function
        if authenticated_role != 'distributor':
            print("[WARNING] Unauthorized role attempting to access createProvider")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - Only distributors can create providers'})
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
        distributor_pk = body.get('distributor_pk')
        name = body.get('name')
        dni = body.get('dni')
        ruc = body.get('ruc')
        phoneNumber1 = body.get('phoneNumber1')
        phoneNumber2 = body.get('phoneNumber2')

        if not all([distributor_pk, name, dni, ruc, phoneNumber1]):
            print("[WARNING] Missing required fields")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Missing required fields'})
            }

        # Ensure the authenticated user is creating providers for their own account
        if authenticated_pk != distributor_pk:
            print("[WARNING] Distributor is attempting to create providers for an unauthorized account")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - You can only create providers under your own account'})
            }

        # Generate a unique ID for the provider
        provider_id = str(uuid.uuid4())

        # Create provider item
        item = {
            'PK': distributor_pk,
            'SK': provider_id,
            'name': name,
            'dni': dni,
            'ruc': ruc,
            'phoneNumber1': phoneNumber1,
            'phoneNumber2': phoneNumber2,
            'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'created_by': authenticated_pk
        }

        print(f"[INFO] Saving provider to DynamoDB: {item}")
        provider_table.put_item(Item=item)

        print("[INFO] Returning successful response")
        return {
            'statusCode': 201,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'message': 'Provider created successfully',
                'PK': item['PK'],
                'SK': item['SK'],
                'name': item['name'],
                'dni': item['dni'],
                'ruc': item['ruc'],
                'phoneNumber1': item['phoneNumber1'],
                'phoneNumber2': item['phoneNumber2'],
                'created_at': item['created_at']
            })
        }

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }