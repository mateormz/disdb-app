import boto3
from datetime import datetime
import os
from boto3.dynamodb.conditions import Key

def lambda_handler(event, context):
    try:
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        token_table_name = os.environ['TABLE_TOKENS']
        index_name = os.environ['INDEX_TOKENS']  # token-index
        table = dynamodb.Table(token_table_name)

        # Get token from body
        if not event.get('body'):
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Request body is missing"}
            }

        body = event['body']
        token = body.get('token')

        if not token:
            return {
                "statusCode": 400,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Token not provided"}
            }

        # Use index to find token in table
        response = table.query(
            IndexName=index_name,
            KeyConditionExpression=Key('token').eq(token)
        )

        if not response['Items']:
            return {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Invalid token"}
            }

        # Verify token expiration
        token_data = response['Items'][0]
        expiration = token_data['expiration']

        if datetime.now().strftime('%Y-%m-%d %H:%M:%S') > expiration:
            return {
                "statusCode": 403,
                "headers": {"Content-Type": "application/json"},
                "body": {"error": "Token expired"}
            }

        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": {
                "message": "Token is valid",
                "expiration": expiration
            }
        }

    except KeyError as e:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": f"Missing field: {str(e)}"}
        }
    except Exception as e:
        print("Error:", str(e))
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": {"error": "Internal Server Error", "details": str(e)}
        }