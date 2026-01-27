from urllib.parse import urlparse, unquote
from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from ipapython.kerberos import Principal
from ipalib import api, errors
import time
import requests

class ExternalIdPValidator(RequestValidator):

    def __init__(self, api):
        self.api = api
        # In-memory storage for authorization codes and tokens
        # TODO: Use persistent storage for production (e.g., LDAP, Redis, or IPA cache)
        self.authorization_codes = {}  # code -> {client_id, user, scopes, redirect_uri, expires_at}
        self.bearer_tokens = {}  # token -> {client_id, user, scopes, expires_at}

    # Pre- and post-authorization.

    def validate_client_id(self, client_id, request, *args, **kwargs):
        krb_id = Principal(client_id)
        if krb_id.realm and krb_id.realm != self.api.env.realm:
            return False
        if not(krb_id.is_service or krb_id.is_host):
            return False
        ldap = self.api.Backend.ldap2
        search_kw = {'objectclass': ['krbprincipal', 'ipaservice'],
                     'krbcanonicalname': str(krb_id)}
        filter = ldap.make_filter(search_kw, rules=ldap.MATCH_ALL)
        base_dn=self.api.env.container_accounts + self.api.env.basedn
        try:
            entries, truncated = ldap.find_entries(
                filter=filter, attrs_list=['krbprincipalname'], base_dn=base_dn)
            if len(entries) > 1:
                return False
        except errors.NotFound:
            return False
        return True

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        krb_id = Principal(client_id)
        uri = urlparse(redirect_uri)
        # uri.netloc includes port, so we need to extract just the hostname
        # or compare with the full netloc if it matches the hostname
        hostname = uri.hostname or uri.netloc
        if krb_id.hostname != hostname:
            return False
        return True

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        krb_id = Principal(client_id)
        # Assume Cockpit
        if krb_id.is_host:
            return f"https://{krb_id.hostname}:9090/"
        return None

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        # For now, allow basic OpenID Connect scopes
        allowed_scopes = {'openid', 'profile', 'email'}
        return all(scope in allowed_scopes for scope in scopes)

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        return ['openid', 'profile']

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        return response_type == 'code'

    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        self.authorization_codes[code['code']] = {
            'client_id': client_id,
            'user': request.user,
            'scopes': request.scopes,
            'redirect_uri': request.redirect_uri,
            'expires_at': time.time() + 600  # 10 minutes expiration
        }

    # Token request

    def client_authentication_required(self, request, *args, **kwargs):
        # Check if the client provided authentication information that needs to
        # be validated, e.g. HTTP Basic auth
        # We always require authentication via ipa_session cookie
        return True

    def authenticate_client(self, request, *args, **kwargs):
        # Validate ipa_session cookie provided as client_secret
        client_id = request.client_id
        client_secret = request.client_secret

        if not client_secret:
            return False

        # URL-decode the cookie if needed
        cookie_value = unquote(client_secret)

        # Validate the cookie by calling /ipa/session/json with whoami command
        try:
            session_url = f"https://{self.api.env.host}/ipa/session/json"
            whoami_request = {
                "id": 0,
                "method": "whoami/1",
                "params": [[], {"version": self.api.env.api_version}]
            }

            cookies = {'ipa_session': cookie_value}
            headers = {
                'referer': f"https://{self.api.env.host}/ipa",
                'Content-Type': 'application/json'
            }

            response = requests.post(
                session_url,
                json=whoami_request,
                cookies=cookies,
                headers=headers,
                verify=True
            )

            if response.status_code != 200:
                return False

            result = response.json()

            # Check if there's an error
            if result.get('error'):
                return False

            # Verify the principal matches the client_id
            principal = result.get('principal')
            if not principal or principal != client_id:
                return False

            # Verify the object type is service or host
            obj_type = result.get('result', {}).get('object')
            if obj_type not in ('service', 'host'):
                return False

            # Store the authenticated client
            request.client = client_id
            return True

        except Exception:
            return False

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # All our clients are confidential (require authentication)
        # This method is only called for public clients
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes
        # and user to request.scopes and request.user.
        auth_code = self.authorization_codes.get(code)

        if not auth_code:
            return False

        # Check if code has expired
        if time.time() > auth_code['expires_at']:
            del self.authorization_codes[code]
            return False

        # Verify the code belongs to this client
        if auth_code['client_id'] != client_id:
            return False

        # Set the scopes and user on the request
        request.scopes = auth_code['scopes']
        request.user = auth_code['user']

        return True

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        auth_code = self.authorization_codes.get(code)

        if not auth_code:
            return False

        return auth_code['redirect_uri'] == redirect_uri

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" (no refresh_token per design)
        return grant_type == 'authorization_code'

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        access_token = token.get('access_token')
        expires_in = token.get('expires_in', 1800)  # Default 30 minutes

        self.bearer_tokens[access_token] = {
            'client_id': request.client_id,
            'user': request.user,
            'scopes': request.scopes,
            'expires_at': time.time() + expires_in
        }

        # No refresh_token support per design document

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        if code in self.authorization_codes:
            del self.authorization_codes[code]

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        token_data = self.bearer_tokens.get(token)

        if not token_data:
            return False

        # Check if token has expired
        if time.time() > token_data['expires_at']:
            del self.bearer_tokens[token]
            return False

        # Check if requested scopes are subset of token scopes
        if not all(scope in token_data['scopes'] for scope in scopes):
            return False

        # Set user information on request
        request.user = token_data['user']
        request.client_id = token_data['client_id']
        request.scopes = token_data['scopes']

        return True

    # Token refresh request

    def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        # Obtain the token associated with the given refresh_token and
        # return its scopes, these will be passed on to the refreshed
        # access token if the client did not specify a scope during the
        # request.
        # No refresh token support per design document
        return []


validator = ExternalIdPValidator(api)
server = WebApplicationServer(validator)
