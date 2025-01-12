import boto3
from datetime import datetime
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
            token_table_name = os.environ['TABLE_TOKENS']
            index_name = os.environ['INDEX_TOKENS']  # token-index
            print("[INFO] Environment variables loaded successfully")
            print(f"[DEBUG] Token table name: {token_table_name}")
            print(f"[DEBUG] Token index name: {index_name}")
        except KeyError as env_error:
            print(f"[ERROR] Missing environment variable: {str(env_error)}")
            return {
                'statusCode': 500,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': f'Missing environment variable: {str(env_error)}'})
            }

        table = dynamodb.Table(token_table_name)

        # Get token from body
        if not event.get('body'):
            print("[WARNING] Request body is missing")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Request body is missing'})
            }

        try:
            body = json.loads(event['body'])  # Convert the string body to a Python dictionary
        except json.JSONDecodeError as e:
            print(f"[ERROR] Failed to parse JSON body: {str(e)}")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Invalid JSON in request body'})
            }

        token = body.get('token')
        print(f"[DEBUG] Token received: {token}")

        if not token:
            print("[WARNING] Token not provided")
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Token not provided'})
            }

        # Use index to find token in table
        print("[INFO] Querying DynamoDB for token")
        response = table.query(
            IndexName=index_name,
            KeyConditionExpression=Key('token').eq(token)
        )
        print(f"[DEBUG] DynamoDB query response: {response}")

        if not response['Items']:
            print("[WARNING] Invalid token")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Invalid token'})
            }

        # Verify token expiration
        token_data = response['Items'][0]
        expiration = token_data['expiration']
        print(f"[DEBUG] Token expiration: {expiration}")

        if datetime.now().strftime('%Y-%m-%d %H:%M:%S') > expiration:
            print("[WARNING] Token expired")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': json.dumps({'error': 'Token expired'})
            }

        print("[INFO] Token is valid")

        role = token_data['role']
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': json.dumps({
                'message': 'Token is valid',
                'expiration': expiration,
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