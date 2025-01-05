import boto3
import os
from boto3.dynamodb.conditions import Key
import json

def lambda_handler(event, context):
    try:
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        user_table_name = os.environ['TABLE_USERS']
        validate_function_name = os.environ['VALIDATE_TOKEN_FUNCTION']
        user_table = dynamodb.Table(user_table_name)

        # Extract Authorization token from headers
        token = event['headers'].get('Authorization')
        if not token:
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
        validate_response = lambda_client.invoke(
            FunctionName=validate_function_name,
            InvocationType='RequestResponse',
            Payload=json.dumps(payload)
        )
        validation_result = json.loads(validate_response['Payload'].read())

        if validation_result.get('statusCode') != 200:
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'Unauthorized - Invalid or expired token'}
            }

        # Extract PK and SK from the request body
        body = event.get('body')
        if not body:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'Request body is missing'}
            }

        pk = body.get('PK')
        sk = body.get('SK')
        if not pk or not sk:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'PK or SK is missing'}
            }

        # Query DynamoDB to get the user
        response = user_table.get_item(
            Key={
                'PK': pk,
                'SK': sk
            }
        )

        if 'Item' not in response:
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json'
                },
                'body': {'error': 'User not found'}
            }

        user = response['Item']

        # Remove sensitive information
        user.pop('password_hash', None)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': {'user': user}
        }

    except KeyError as e:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': {'error': f'Missing field: {str(e)}'}
        }
    except Exception as e:
        print("Error:", str(e))
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json'
            },
            'body': {'error': 'Internal Server Error', 'details': str(e)}
        }