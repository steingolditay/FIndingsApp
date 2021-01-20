import boto3

def create_db():
    dynamodb = boto3.resource('dynamodb')

    table = dynamodb.create_table(
        TableName='posts',
        KeySchema=[
            {
                'AttributeName': 'uid',
                'KeyType': 'HASH'
            },
            {
                'AttributeName': 'poster_uid',
                'KeyType': 'RANGE'
            },
        ],
        AttributeDefinitions=[
            {
                'AttributeName': 'uid',
                'AttributeType': 'S'
            },
            {
                'AttributeName': 'poster_uid',
                'AttributeType': 'S'
            },
        ],
        ProvisionedThroughput={
            'ReadCapacityUnits': 1,
            'WriteCapacityUnits': 1
        }
    )
    # table.meta.client.get_waiter('table_exists').wait(TableName='posts')
    # print(table.item_count)