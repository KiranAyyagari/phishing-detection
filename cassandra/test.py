import dotenv
from astrapy.collections import create_client, AstraCollection
import uuid
import os
from dotenv import load_dotenv
import json

load_dotenv(dotenv.find_dotenv())

# get Astra connection information from environment variables
ASTRA_DB_ID = os.getenv('ASTRA_DB_ID')
ASTRA_DB_REGION = os.getenv('ASTRA_DB_REGION')
ASTRA_DB_APPLICATION_TOKEN = os.getenv('ASTRA_DB_APPLICATION_TOKEN')
ASTRA_DB_KEYSPACE = os.getenv('ASTRA_DB_KEYSPACE')
TEST_COLLECTION_NAME = os.getenv('COLLECTION_NAME')
KEY_PATH = os.getenv('KEY_PATH')

print(KEY_PATH)

# setup an Astra Client and create a shortcut to our test colllection
astra_client = create_client(astra_database_id=ASTRA_DB_ID,
                                astra_database_region=ASTRA_DB_REGION,
                                astra_application_token=ASTRA_DB_APPLICATION_TOKEN)
test_collection = astra_client.namespace(ASTRA_DB_KEYSPACE).collection(TEST_COLLECTION_NAME)


# create a new document
cliff_uuid = str(uuid.uuid4())
print(cliff_uuid)

f = open('C:\\Users\\saiki\\PycharmProjects\\phishing-detection\\data\\dataset.json')

data = json.load(f)

# for maindata in data:
#     print(maindata)
#     test_collection.create(path=cliff_uuid, document=maindata)
#     break
records = test_collection.delete(path=KEY_PATH)
print(records)
