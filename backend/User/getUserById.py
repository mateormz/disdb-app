import boto3
import os
from boto3.dynamodb.conditions import Key
import json

def lambda_handler(event, context):
    try:
        # Log the incoming event
        print("[INFO] Received event:", json.dumps(event, indent=2))
        
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            user_table_name = os.environ['TABLE_USERS']
            validate_function_name = f"{os.environ['SERVICE_NAME']}-{os.environ['STAGE']}-{os.environ['VALIDATE_TOKEN_FUNCTION']}"
            print("[INFO] Environment variables loaded successfully")
            print(f"[DEBUG] User table name: {user_table_name}")
            print(f"[DEBUG] Validate function name: {validate_function_name}")
        except KeyError as env_error:
            print(f"[ERROR] Missing environment variable: {str(env_error)}")
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': f"Missing environment variable: {str(env_error)}"}
            }
        
        user_table = dynamodb.Table(user_table_name)

        # Extract Authorization token from headers
        token = event.get('headers', {}).get('Authorization')
        print(f"[DEBUG] Authorization token: {token}")
        if not token:
            print("[WARNING] Authorization token is missing")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'Authorization token is missing'}
            }

        # Invoke validateToken function
        lambda_client = boto3.client('lambda')
        payload = {
            "body": {
                "token": token
            }
        }
        print("[INFO] Invoking validateToken function with payload:", json.dumps(payload))
        
        validate_response = lambda_client.invoke(
            FunctionName=validate_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)  # Aquí se mantiene json.dumps
        )
        validation_result = json.loads(validate_response['Payload'].read())
        print("[INFO] Validation function response received")
        print(f"[DEBUG] Validation result: {validation_result}")

        if validation_result.get('statusCode') != 200:
            print("[WARNING] Token validation failed")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'Unauthorized - Invalid or expired token'}
            }

        # Extract PK and SK from path parameters
        try:
            pk = event['pathParameters']['PK']
            sk = event['pathParameters']['SK']
            print(f"[INFO] Path parameters retrieved: PK={pk}, SK={sk}")
        except KeyError as path_error:
            print(f"[ERROR] Missing path parameter: {str(path_error)}")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': f'Missing path parameter: {str(path_error)}'}
            }

        # Query DynamoDB to get the user
        print(f"[INFO] Querying DynamoDB for PK={pk} and SK={sk}")
        response = user_table.get_item(
            Key={
                'PK': pk,
                'SK': sk
            }
        )
        print(f"[DEBUG] DynamoDB get_item response: {response}")

        if 'Item' not in response:
            print("[WARNING] User not found in DynamoDB")
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'User not found'}
            }

        user = response['Item']
        print(f"[INFO] User retrieved: {user}")

        # Remove sensitive information
        if 'password_hash' in user:
            print("[DEBUG] Removing sensitive information (password_hash) from user data")
            user.pop('password_hash', None)

        print("[INFO] Returning successful response")
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': {'user': user}
        }

    except KeyError as e:
        print(f"[ERROR] KeyError encountered: {str(e)}")
        return {
            'statusCode': 400,
            'headers': {
                    'Content-Type': 'application/json'
            },
            'body': {'error': f'Missing field: {str(e)}'}
        }
    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': {'error': 'Internal Server Error', 'details': str(e)}
        }