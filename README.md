# postman-import-python
A python library that allows importing of Postman 2.1 JSON collections into ready to use requests objects


## Work in progress, still in development
Currently working on adding more auth types

Usage Guide

The `ParsePostmanJSON` function, defined in **`postman_parser.py`**, transforms a Postman v2.1 collection (in JSON form) into a list of ready to use request objects.

An example program that takes in a Postman 2.1 JSON collection ```-c``` and sends all requests is provided in postman_example.py

---

## Function Signature

```python
from postman_parser import ParsePostmanJSON

entries = ParsePostmanJSON(collection_json: dict) -> List[dict]
```

* **Input:**

  * `collection_json` — A Python `dict` loaded from a Postman v2.1 collection file.

* **Output:** A `list` of **entry** dictionaries, each with:

  * `name` (`str`): The **name** of the request (from Postman). May be empty.
  * `description` (`str`): The Postman request **description**, if present.
  * `request` (`dict`): A spec suitable for `requests.request(**spec)`, containing:

    * `method` (`str`): HTTP method in **lowercase**.
    * `url` (`str`): The raw URL (with `{{vars}}` substituted).
    * `headers` (`dict`): Any HTTP headers (including Authorization).
    * `params` (`dict`): URL query parameters.
    * Optional `auth`: An **`HTTPBasicAuth`**, `HTTPDigestAuth`, `OAuth1`, etc.
    * Optional `data` / `json`: The request body.

---

## Example: Loading & Inspecting Entries

```python
import json
from postman_parser import ParsePostmanJSON

# 1) Load your Postman collection JSON
with open('my_collection.json', 'r', encoding='utf-8') as f:
    col = json.load(f)

# 2) Parse into entries
entries = ParsePostmanJSON(col)

# 3) Inspect the first entry
first = entries[0]
print("Name:", first['name'])
print("Description:\n", first['description'])
print("Request spec:", first['request'])
```

*Output:*

```
Name: Basic Auth
Description:
  This request uses Basic Auth to authenticate with an API...
Request spec: {
  'method': 'get',
  'url': 'https://httpbin.org/basic-auth/user/pass',
  'headers': {},
  'params': {},
  'auth': <requests.auth.HTTPBasicAuth object at 0x...>
}
```

---

## Example: Executing All Requests

```python
import requests
from postman_parser import ParsePostmanJSON

# load & parse
collection = json.load(open('my_collection.json'))
entries = ParsePostmanJSON(collection)

# send each request
for entry in entries:
    spec = entry['request']
    response = requests.request(**spec)
    print(f"=> {entry['name'] or spec['url']} -> {response.status_code}")
```

This snippet will iterate through every Postman request in your collection, fire it off via `requests`, and print the HTTP status code.

Yes I ChatGPT'ed the docs, deal with it.
