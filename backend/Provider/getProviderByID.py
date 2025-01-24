import boto3
import os
import json

def get_provider_by_id_handler(event, context):
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
        print(f"[INFO] Authenticated user PK: {authenticated_pk}")

        # Parse path parameters
        try:
            pk = event['pathParameters']['PK']
            sk = event['pathParameters']['SK']
            print(f"[INFO] Path parameters retrieved: PK={pk}, SK={sk}")
        except KeyError as path_error:
            print(f"[ERROR] Missing path parameter: {str(path_error)}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f'Missing path parameter: {str(path_error)}'})
            }

        # Query DynamoDB to get the provider
        print(f"[INFO] Querying DynamoDB for provider with PK={pk} and SK={sk}")
        response = provider_table.get_item(Key={'PK': pk, 'SK': sk})
        print(f"[DEBUG] DynamoDB get_item response: {response}")

        if 'Item' not in response:
            print("[WARNING] Provider not found in DynamoDB")
            return {
                'statusCode': 404,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Provider not found'})
            }

        provider = response['Item']

        # Authorization: Ensure user has access
        if provider['PK'] != authenticated_pk:
            print("[WARNING] User is trying to access unauthorized provider data")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - You can only access your own providers'})
            }

        print("[INFO] Returning successful response")
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps(provider)
        }

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }