import json
import argparse
import requests
from termcolor import colored
from postman_parser import ParsePostmanJSON


def print_request_details(entry):
    name = entry.get('name','')
    desc = entry.get('description','')
    spec = entry['request']
    print(colored(f"\n=== Request: {name or spec.get('url','<no url>')} ===", 'cyan', attrs=['bold']))
    if desc:
        print(colored(f"Description: {desc}", 'magenta'))
    print(colored(f"Method: {spec.get('method','').upper()}", 'yellow'))
    print(colored(f"URL: {spec.get('url','')}" , 'yellow'))
    headers = spec.get('headers', {})
    if headers:
        print(colored("Headers:", 'cyan'))
        for k, v in headers.items(): print(colored(f"  {k}: {v}", 'yellow'))
    params = spec.get('params', {})
    if params:
        print(colored("Params:", 'cyan'))
        for k, v in params.items(): print(colored(f"  {k}: {v}", 'yellow'))
    if 'data' in spec:
        print(colored("Body mode: raw", 'cyan'))
        print(colored(f"  {spec['data']}", 'yellow'))
    if 'json' in spec:
        print(colored("Body mode: raw", 'cyan'))
        print(colored(json.dumps(spec['json'], indent=2), 'yellow'))
    print(colored("="*50, 'cyan'))


def print_http_details(entry, resp):
    name = entry.get('name','')
    spec = entry['request']
    print(colored(f"\n=== Response: {name or spec.get('url','<no url>')} ===", 'cyan', attrs=['bold']))
    print(colored(f"Status: {resp.status_code} {resp.reason}", 'yellow'))
    print(colored("Response Headers:", 'cyan'))
    for k, v in resp.headers.items(): print(colored(f"  {k}: {v}", 'yellow'))
    try:
        data = resp.json()
        print(colored("Response Body JSON:", 'cyan'))
        print(json.dumps(data, indent=2))
    except ValueError:
        print(colored("Response Body:", 'cyan'))
        print(resp.text)
    print(colored("="*50, 'cyan'))


def main():
    parser = argparse.ArgumentParser(description='Run a Postman v2.1 collection')
    parser.add_argument('-c', '--collection', required=True, help='Collection JSON file')
    args = parser.parse_args()

    with open(args.collection, 'r', encoding='utf-8') as f:
        collection = json.load(f)

    entries = ParsePostmanJSON(collection)
    for entry in entries:
        print_request_details(entry)
        try:
            resp = requests.request(**entry['request'], timeout=30)
            print_http_details(entry, resp)
        except Exception as e:
            print(colored(f"Error executing {entry.get('name','<no name>')}: {e}", 'red'))


if __name__ == '__main__':
    main()
