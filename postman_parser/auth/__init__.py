#!/usr/bin/env python3

from .basic import handle_basic_auth
from .digest import handle_digest_auth
from .bearer import handle_bearer_auth
from .apikey import handle_apikey_auth
from .oauth1 import handle_oauth1_auth
from .oauth2 import handle_oauth2_auth
from .hawk import handle_hawk_auth
from .ntlm import handle_ntlm_auth
from .edgegrid import handle_edgegrid_auth
from .asap import handle_asap_auth
from .aws import handle_aws_auth

__all__ = [
    'handle_basic_auth',
    'handle_digest_auth',
    'handle_bearer_auth',
    'handle_apikey_auth',
    'handle_oauth1_auth',
    'handle_oauth2_auth',
    'handle_hawk_auth',
    'handle_ntlm_auth',
    'handle_edgegrid_auth',
    'handle_asap_auth',
    'handle_aws_auth',
] 