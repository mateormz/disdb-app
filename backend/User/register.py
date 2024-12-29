import boto3
import hashlib
import uuid
from datetime import datetime
import os
from boto3.dynamodb.conditions import Key

def generate_short_code():
    """Generates the first 8 characters of a UUID."""
    return str(uuid.uuid4())[:8].upper()

def lambda_handler(event, context):
    try:
        dynamodb = boto3.resource('dynamodb')
        table_name = os.environ['TABLE_NAME']
        table = dynamodb.Table(table_name)

        email = event['body'].get('email')
        password = event['body'].get('password')
        role = event['body'].get('role')  # 'distributor' or 'delivery_person'
        name = event['body'].get('name')
        lastName = event['body'].get('lastName')

        if not all([email, password, role, name, lastName]):
            return {
                'statusCode': 400,
                'body': {'error': 'Faltan campos requeridos'}
            }

        # Check role
        if role not in ['distributor', 'delivery_person']:
            return {
                'statusCode': 400,
                'body': {'error': 'Rol no válido. Debe ser distributor o delivery_person'}
            }

        # Check if the email is already registered
        response = table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email)
        )

        if response['Items']:
            return {
                'statusCode': 400,
                'body': {'error': 'El email ya está registrado'}
            }

        # Create user
        user_id = str(uuid.uuid4())
        if role == 'distributor':
            # Generate short_code
            while True:
                short_code = generate_short_code()
                code_check = table.query(
                    IndexName='short-code-index',
                    KeyConditionExpression=Key('short_code').eq(short_code)
                )
                if not code_check['Items']:
                    break

            pk = user_id
            sk = 'metadata'
            item = {
                'PK': pk,
                'SK': sk,
                'email': email,
                'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                'role': role,
                'short_code': short_code,
                'name': name,
                'lastName': lastName,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        else:  # role == 'delivery_person'
            pk = 'unassigned'
            sk = user_id
            item = {
                'PK': pk,
                'SK': sk,
                'email': email,
                'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                'role': role,
                'name': name,
                'lastName': lastName,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

        # Save in DynamoDB
        table.put_item(Item=item)

        return {
            'statusCode': 200,
            'body': {
                'message': 'Account created successfully',
                'user_id': user_id,
                'role': role,
            }
        }

    except KeyError as e:
        return {
            'statusCode': 400,
            'body': {'error': f'Required field not found: {str(e)}'}
        }
    except Exception as e:
        print("Error:", str(e))
        return {
            'statusCode': 500,
            'body': {'error': 'Internal Server Error', 'details': str(e)}
        }