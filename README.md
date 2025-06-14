# postman-import-python
A python library that allows importing of Postman 2.1 JSON collections into ready to use requests objects


## Work in progress, still in early development
**This is still in very early development, and specs are subject to change at any time. If you want to use it for something quick go ahead, but I would not advise usage of this library (in its current state) in any application intended for long term usage.**

TODO:
- add the remaining auth types
- test for different data types (binary???)


### Usage Guide

The `ParsePostmanJSON` function transforms a Postman v2.1 collection (in JSON form) into a list of ready to use request objects. Supports variables and multiple authentication types including Basic Auth, Digest Auth, Bearer Token, API Key, OAuth1, OAuth2, Hawk, NTLM, EdgeGrid, ASAP, and AWS Signature V4.

### Installation

```bash
pip install -r requirements.txt
```

### Testing instructions
- An example program that takes in a Postman 2.1 JSON collection ```-c``` and sends all requests is provided in postman_example.py  
- A demo postman collection is provided in ```demo_test_cases.json``` that demonstrates a basic implementation of all the auth types currently supported.  
- An example webapp to handle the example postman collection is provided in ```demo_webapp.py```.  
- config.json just contains the vars for the webapp. No modification needed.  

```bash
python demo_webapp.py
python postman_example.py -c .\demo_test_cases.json
```

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
    * `url` (`str`): The raw URL.
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
import json
import requests
from postman_parser import ParsePostmanJSON

# load & parse
with open('my_collection.json', 'r', encoding='utf-8') as f:
    collection = json.load(f)
entries = ParsePostmanJSON(collection)

# send each request
for entry in entries:
    spec = entry['request']
    response = requests.request(**spec)
    print(f"=> {entry['name'] or spec['url']} -> {response.status_code}")
```

This snippet will iterate through every Postman request in your collection, fire it off via `requests`, and print the HTTP status code.

## Supported Authentication Types

The library supports the following authentication types:
- Basic Auth
- Digest Auth
- Bearer Token
- API Key (header, query, or cookie)
- OAuth1
- OAuth2
- Hawk
- NTLM
- EdgeGrid
- ASAP
- AWS Signature V4

# Usual obligatory disclaimer
This project is generally less "offensive" than my other projects, since its more of a QoL utility for API testing more than it is offensive tooling. I'm just throwing this here because it could potentially help someone else. But in the off chance that you cause nuclear war or the total collapse of the global economy using this code, while funny, I am not responsible for (at least not legally). I dont encourage it (but I will laugh)  

Insert usual disclaimer about non malicious educational use here, whatever. I'm not responsible for random strangers on the internet.


