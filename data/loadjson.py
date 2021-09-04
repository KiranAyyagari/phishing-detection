import json
from types import SimpleNamespace

f = open('dataset.json')

data = json.load(f)

print(data)

