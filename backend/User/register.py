import boto3
import hashlib
import uuid
from datetime import datetime
import os
from boto3.dynamodb.conditions import Key

def generate_short_code():
    """Genera los primeros 8 caracteres de un UUID."""
    return str(uuid.uuid4())[:8].upper()

def lambda_handler(event, context):
    try:
        dynamodb = boto3.resource('dynamodb')
        table_name = os.environ['TABLE_NAME']
        table = dynamodb.Table(table_name)

        tenant_id = event['body'].get('tenant_id')
        email = event['body'].get('email')
        password = event['body'].get('password')
        role = event['body'].get('role')  # 'distributor' o 'delivery_person'

        if not all([tenant_id, email, password, role]):
            return {
                'statusCode': 400,
                'body': {'error': 'Faltan campos requeridos'}
            }

        # Validar que el rol sea válido
        if role not in ['distributor', 'delivery_person']:
            return {
                'statusCode': 400,
                'body': {'error': 'Rol no válido. Debe ser distributor o delivery_person'}
            }

        # Comprobar si el email ya está registrado
        response = table.query(
            IndexName='email-index',
            KeyConditionExpression=Key('email').eq(email)
        )

        if response['Items']:
            return {
                'statusCode': 400,
                'body': {'error': 'El email ya está registrado'}
            }

        # Crear usuario según el rol
        user_id = str(uuid.uuid4())
        if role == 'distributor':
            # Generar un código único y verificar su unicidad
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
                'tenant_id': tenant_id,
                'email': email,
                'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                'role': role,
                'short_code': short_code,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        else:  # role == 'delivery_person'
            pk = 'unassigned'
            sk = user_id
            item = {
                'PK': pk,
                'SK': sk,
                'tenant_id': tenant_id,
                'email': email,
                'password_hash': hashlib.sha256(password.encode()).hexdigest(),
                'role': role,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

        # Guardar el usuario en DynamoDB
        table.put_item(Item=item)

        return {
            'statusCode': 201,
            'body': {
                'message': 'Usuario registrado exitosamente',
                'user_id': user_id,
                'role': role,
                'short_code': short_code if role == 'distributor' else None
            }
        }

    except KeyError as e:
        return {
            'statusCode': 400,
            'body': {'error': f'Campo requerido no encontrado: {str(e)}'}
        }
    except Exception as e:
        print("Error:", str(e))
        return {
            'statusCode': 500,
            'body': {'error': 'Error interno del servidor', 'details': str(e)}
        }