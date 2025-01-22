import boto3
import os
import json
from boto3.dynamodb.conditions import Key
from urllib.parse import quote, unquote

def lambda_handler(event, context):
    try:
        print("[INFO] Received event:", json.dumps(event, indent=2))

        # Initialize DynamoDB
        dynamodb = boto3.resource('dynamodb')

        # Environment variables
        try:
            client_table_name = os.environ['TABLE_CLIENTS']
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

        # Extract Authorization token from headers
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
        print("[INFO] Validation function response received")
        print(f"[DEBUG] Validation result: {validation_result}")

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

        # Extract PK from path parameters
        try:
            pk = event['pathParameters']['PK']
            print(f"[INFO] Path parameter retrieved: PK={pk}")
        except KeyError as path_error:
            print(f"[ERROR] Missing path parameter: {str(path_error)}")
            return {
                'statusCode': 400,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': f'Missing path parameter: {str(path_error)}'})
            }

        # Ensure the authenticated user matches or belongs to the distributor
        if  pk != authenticated_pk:
            print("[WARNING] Unauthorized access - Distributor cannot access another distributor's clients")
            return {
                'statusCode': 403,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Unauthorized - You can only access your own distributor\'s clients'})
            }

        # Handle pagination and limit
        query_params = event.get('queryStringParameters', {})
        encoded_last_evaluated_key = query_params.get('LastEvaluatedKey') if query_params else None
        limit = int(query_params.get('limit', 10)) if query_params else 10

        print(f"[INFO] Limit for query: {limit}")
        exclusive_start_key = None
        if encoded_last_evaluated_key:
            try:
                exclusive_start_key = json.loads(unquote(encoded_last_evaluated_key))
                print(f"[INFO] Decoded LastEvaluatedKey: {exclusive_start_key}")
            except json.JSONDecodeError:
                print("[WARNING] Invalid LastEvaluatedKey format, ignoring...")

        # Query DynamoDB for clients
        scan_kwargs = {
            'KeyConditionExpression': Key('PK').eq(pk),
            'Limit': limit
        }
        if exclusive_start_key:
            scan_kwargs['ExclusiveStartKey'] = exclusive_start_key

        print("[INFO] Querying DynamoDB for clients")
        response = client_table.query(**scan_kwargs)
        print(f"[DEBUG] DynamoDB query response: {response}")

        # Prepare the result
        clients = response.get('Items', [])
        last_evaluated_key = response.get('LastEvaluatedKey')

        # Encode LastEvaluatedKey for the response
        encoded_last_evaluated_key = quote(json.dumps(last_evaluated_key)) if last_evaluated_key else None
        print(f"[INFO] Encoded LastEvaluatedKey for response: {encoded_last_evaluated_key}")

        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'clients': clients,
                'LastEvaluatedKey': encoded_last_evaluated_key
            })
        }

    except Exception as e:
        print(f"[ERROR] Unexpected error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal Server Error', 'details': str(e)})
        }