import boto3
import os
import json

def lambda_handler(event, context):
    try:
        print("[INFO] Received event:", json.dumps(event, indent=2))

        # Initialize DynamoDB
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            user_table_name = os.environ['TABLE_USERS']
            print("[INFO] Environment variables loaded successfully")
            print(f"[DEBUG] User table name: {user_table_name}")
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

        # User exists, proceed with deletion
        print(f"[INFO] Deleting user from DynamoDB with PK={pk} and SK={sk}")
        delete_response = user_table.delete_item(
            Key={
                'PK': pk,
                'SK': sk
            }
        )
        print(f"[DEBUG] DynamoDB delete_item response: {delete_response}")

        # Return success response
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({'message': 'User deleted successfully'})
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