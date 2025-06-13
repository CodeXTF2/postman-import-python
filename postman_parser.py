import json
import re
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from requests_oauthlib import OAuth1
from mohawk import Sender


def deep_replace(obj, mapper):
    """
    Recursively replace {{variable}} placeholders in obj using mapper dict.
    """
    if isinstance(obj, str):
        return re.sub(r"{{\s*([^}]+?)\s*}}",
                      lambda m: str(mapper.get(m.group(1), m.group(0))),
                      obj)
    if isinstance(obj, list):
        return [deep_replace(i, mapper) for i in obj]
    if isinstance(obj, dict):
        return {k: deep_replace(v, mapper) for k, v in obj.items()}
    return obj


def ParsePostmanJSON(collection_json):
    """
    Given a Postman v2.1 collection as a dict, return a list of entries:
    each entry is a dict with keys: name, description, request
    where 'request' is a dict suitable for requests.request(**request).
    """
    variables = {v['key']: v.get('value', '') for v in collection_json.get('variable', [])}
    entries = []

    for item in collection_json.get('item', []):
        name = item.get('name', '')
        raw_req = item.get('request', {})
        description = raw_req.get('description', '')
        req = deep_replace(raw_req, variables)

        # build request spec
        method = req.get('method', 'GET').lower()
        url = req.get('url', {}).get('raw', '')
        headers = {}
        params = {}
        auth = None

        auth_block = req.get('auth', {})
        typ = auth_block.get('type', '').lower()
        if typ == 'basic':
            creds = {i['key']: i['value'] for i in auth_block.get('basic', [])}
            auth = HTTPBasicAuth(creds.get('username'), creds.get('password'))
        elif typ == 'digest':
            creds = {i['key']: i['value'] for i in auth_block.get('digest', [])}
            auth = HTTPDigestAuth(creds.get('username'), creds.get('password'))
        elif typ == 'bearer':
            token = None
            for b in auth_block.get('bearer', []):
                if isinstance(b, dict) and b.get('key') == 'token':
                    token = b.get('value'); break
            if token:
                headers['Authorization'] = f"Bearer {token}"
        elif typ == 'apikey':
            cfg = {i['key']: i['value'] for i in auth_block.get('apikey', [])}
            key, val = cfg.get('key'), cfg.get('value')
            where = cfg.get('in', 'header')
            if where == 'header': headers[key] = val
            elif where == 'query': params[key] = val
            elif where == 'cookie': headers['Cookie'] = f"{key}={val}"
        elif typ == 'oauth1':
            cfg = {i['key']: i['value'] for i in auth_block.get('oauth1', [])}
            auth = OAuth1(
                client_key=cfg.get('consumerKey'),
                client_secret=cfg.get('consumerSecret'),
                resource_owner_key=cfg.get('token'),
                resource_owner_secret=cfg.get('tokenSecret'),
                signature_method=cfg.get('signatureMethod', 'HMAC-SHA1')
            )
        elif typ == 'oauth2':
            cfg = {i['key']: i['value'] for i in auth_block.get('oauth2', [])}
            token = cfg.get('accessToken')
            if token:
                headers['Authorization'] = f"Bearer {token}"
        elif typ == 'hawk':
            cfg = {i['key']: i['value'] for i in auth_block.get('hawk', [])}
            creds = {'id': cfg.get('authId'), 'key': cfg.get('authKey'),
                     'algorithm': cfg.get('algorithm', 'sha256')}
            sender = Sender(credentials=creds, url=url,
                            method=method.upper(), content=b'', content_type='text/plain')
            headers['Authorization'] = sender.request_header

        body = req.get('body', {})
        data = None
        json_data = None
        mode = body.get('mode')
        if mode == 'raw':
            if body.get('options', {}).get('raw', {}).get('language') == 'json':
                json_data = json.loads(body.get('raw', ''))
            else:
                data = body.get('raw')
        elif mode == 'urlencoded':
            data = {i['key']: i['value'] for i in body.get('urlencoded', [])}
        elif mode == 'formdata':
            data = {i['key']: i['value'] for i in body.get('formdata', [])}

        request_spec = {'method': method, 'url': url, 'headers': headers, 'params': params}
        if auth is not None:
            request_spec['auth'] = auth
        if data is not None:
            request_spec['data'] = data
        if json_data is not None:
            request_spec['json'] = json_data

        entries.append({'name': name, 'description': description, 'request': request_spec})

    return entries
