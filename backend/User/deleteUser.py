import boto3
import os
from boto3.dynamodb.conditions import Key
import json

def lambda_handler(event, context):
    try:
        print("[INFO] Received event:", json.dumps(event, indent=2))

        # Initialize DynamoDB
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            user_table_name = os.environ['TABLE_USERS']
            validate_function_name = f"{os.environ['SERVICE_NAME']}-{os.environ['STAGE']}-{os.environ['VALIDATE_TOKEN_FUNCTION']}"
            print("[INFO] Environment variables loaded successfully")
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
        print("[INFO] Validation function response received")
        print(f"[DEBUG] Validation result: {validation_result}")

        if validation_result.get('statusCode') != 200:
            print("[WARNING] Token validation failed")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Unauthorized - Invalid or expired token'})
            }

        # Extract role from validation result
        user_info = json.loads(validation_result.get('body', '{}'))
        role = user_info.get('role')
        print(f"[INFO] User role retrieved: {role}")

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
                'body': json.dumps({'error': f'Missing path parameter: {str(path_error)}'})
            }

        # Check if the user exists in DynamoDB
        print(f"[INFO] Checking if user exists with PK={pk} and SK={sk}")
        get_response = user_table.get_item(
            Key={
                'PK': pk,
                'SK': sk
            }
        )
        print(f"[DEBUG] DynamoDB get_item response: {get_response}")

        if 'Item' not in get_response:
            print("[WARNING] User does not exist")
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'User not found'})
            }

        user_to_delete = get_response['Item']
        user_role = user_to_delete.get('role')
        print(f"[INFO] Role of user to delete: {user_role}")

        if user_role == 'distributor':
            # Delete all users with the same PK (distributor and associated delivery persons)
            print("[INFO] Deleting distributor and all associated delivery persons")
            query_response = user_table.query(
                KeyConditionExpression=Key('PK').eq(pk)
            )
            print(f"[DEBUG] Query response for associated users: {query_response}")

            with user_table.batch_writer() as batch:
                for item in query_response['Items']:
                    print(f"[INFO] Deleting item with PK={item['PK']} and SK={item['SK']}")
                    batch.delete_item(
                        Key={
                            'PK': item['PK'],
                            'SK': item['SK']
                        }
                    )
        elif user_role == 'delivery_person':
            # Delete only the specific delivery person
            print("[INFO] Deleting delivery person")
            user_table.delete_item(
                Key={
                    'PK': pk,
                    'SK': sk
                }
            )
        else:
            print("[WARNING] Unsupported role for deletion")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Unsupported role for deletion'})
            }

        print("[INFO] User deletion successful")
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'message': 'User and associated accounts deleted successfully' if user_role == 'distributor' else 'User deleted successfully'})
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