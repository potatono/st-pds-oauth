import requests
import base64
import hashlib
import jwt
import random
import datetime
import re
import uuid
import urllib.parse
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class OAuth:
    def __init__(self, app, on_tokens):
        self.webserver = app.webserver
        self.log = app.log
        self.secrets = app.secrets
        self.config = app.config
        self.url = app.url
        self.on_tokens = on_tokens
        self.nonce = None

        self.authserver_url = self.config.get('DEFAULT', 'authserver_url')
        self.access_token = self.secrets.get("DEFAULT", "access_token", fallback=None)
        self.refresh_token = self.secrets.get("DEFAULT", "refresh_token", fallback=None)
        self.access_token_expires = self.secrets.get("DEFAULT", "access_token_expires", fallback=None)

        # access_token_expires is from isoformat() so deserialize it
        if self.access_token_expires:
            self.access_token_expires = datetime.datetime.fromisoformat(self.access_token_expires)

        self.init()
    
    def init(self):
        self.webserver.add_mapping("GET", "/oauth/callback", self.handle_oauth_callback)
        self.webserver.add_mapping("GET", "/oauth/metadata.json", self.get_client_metadata)
        self.init_authserver()
        self.init_challenge()
        self.init_jwt()

    def init_authserver(self):
        url = self.config.get('DEFAULT', 'authserver_metadata_url')
        res = requests.get(url)

        if res.status_code == 200:
            self.authserver_metadata = res.json()
            self.log.debug(self.authserver_metadata)
        else:
            self.log.error(f"Could not get authserver metadata: {res.status_code}")
            sys.exit(1)

    def init_challenge(self):
        self.code_verifier = self.randomstring()
        self.code_hash = hashlib.sha256(bytes(self.code_verifier, encoding="utf8"))
        self.code_challenge = self.base64_urlencode(self.code_hash.digest())

        self.log.debug(f"code_verifier={self.code_verifier}")
        self.log.debug(f"code_challenge={self.code_challenge}")

    def init_jwt(self):
        self.jwt = self.generate_oauth_jwt(
            audience=self.config.get('DEFAULT', 'authserver_url')
        )

        self.log.debug(f"JWT: {self.jwt}")

    def get_client_id(self):
        return f"{self.url}/oauth/metadata.json"

    def get_client_metadata(self, query):
        data = {
            "client_id": self.get_client_id(),
            "client_name": 'StreamTooth',
            "client_uri": self.url,
            "redirect_uris": [f"{self.url}/oauth/callback"],
            "scope": "atproto transition:generic",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "application_type": "web",
            "token_endpoint_auth_method": "none",
            "dpop_bound_access_tokens": True
        }   

        return data
   
    def get_token_request_payload(self, endpoint_url, code):
        jwt = self.generate_oauth_jwt(endpoint_url)
        payload = {
            "client_id": self.get_client_id(),
            "code": code,
            "code_verifier": self.code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": f"{self.url}/oauth/callback",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt
        }

        return payload
    
    def get_token_refresh_payload(self, endpoint_url):
        jwt = self.generate_oauth_jwt(endpoint_url)
        payload = {
            "client_id": self.get_client_id(),
            "refresh_token": self.refresh_token,
            "grant_type": "refresh_token",
            "scope": "atproto transition:generic offline_access",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": jwt
        }

        return payload

    def request_token_refresh(self):
        token_endpoint_url = self.authserver_metadata['token_endpoint']
        payload = self.get_token_refresh_payload(token_endpoint_url)

        headers = { 
            "DPoP": self.generate_dpop_jwt("POST", token_endpoint_url)
        }
        res = requests.post(token_endpoint_url, data=payload, headers=headers)
        if (res.status_code == 200):
            ## We have the tokens
            data = res.json()
            self.update_tokens(data)

            return data
        elif (res.status_code == 400):
            error = res.json()

            ## If the server asks for nonce and returns it we try again with that
            ## data
            if error['error'] == 'use_dpop_nonce' and self.nonce is None:
                self.nonce = res.headers['dpop-nonce']
                self.log.error("Server requested nonce, retrying with nonce...")
                return self.request_token_refresh()
            else:
                self.log.error("Server returned error 400")
                self.log.error(error)
        else:
            self.log.error(f"Token request failed: {res.status_code}")
            self.log.error(res.text)
            self.log.error(res.headers)
            return
        
    def handle_oauth_callback(self, query):
        token_endpoint_url = self.authserver_metadata['token_endpoint']
        code = query['code']
        payload = self.get_token_request_payload(token_endpoint_url, code)

        headers = { 
            "DPoP": self.generate_dpop_jwt("POST", token_endpoint_url)
        }
        res = requests.post(token_endpoint_url, data=payload, headers=headers)
        if (res.status_code == 200):
            ## We have the tokens
            data = res.json()
            self.update_tokens(data)
            return data
        elif (res.status_code == 400):
            error = res.json()

            ## If the server asks for nonce and returns it we try again with that
            ## data
            if error['error'] == 'use_dpop_nonce' and self.nonce is None:
                self.nonce = res.headers['dpop-nonce']
                self.log.error("Server requested nonce, retrying with nonce...")
                return self.handle_oauth_callback(query)
            else:
                self.log.error("Server returned error 400")
                self.log.error(error)
        else:
            self.log.error(f"Token request failed: {res.status_code}")
            self.log.error(res.text)
            self.log.error(res.headers)
            return
    
    def randomchar(self):
        i = random.randint(0,65)

        if i < 10:
            return chr(i+48)
        elif i < 36:
            return chr(i-10+65)
        elif i < 62:
            return chr(i-36+97)
        elif i == 62:
            return "-"
        elif i == 63:
            return "."
        elif i == 64:
            return "_"
        elif i == 65:
            return "~"
        
        return None

    def randomstring(self, len=127):
        s = ""

        for _ in range(len):
            s += self.randomchar()

        return s

    def base64_urlencode(self, data):
        result = base64.urlsafe_b64encode(data).decode("utf8")
        result = re.sub("=+$","", result)

        return result

    

    def generate_oauth_jwt(self, audience, expiration_minutes=60):
        """
        Generate a JWT for OAuth 2.0 as described in RFC7523.

        :param issuer: The issuer of the JWT.
        :param subject: The subject of the JWT.
        :param audience: The audience of the JWT.
        :param secret: The secret key to sign the JWT.
        :param algorithm: The algorithm to use for signing the JWT.
        :param expiration_minutes: The expiration time of the JWT in minutes.
        :return: The generated JWT as a string.
        """

        issuer = self.get_client_id(),
        subject = self.config.get('DEFAULT', 'jwt_subject'),
        now = datetime.datetime.utcnow()
        payload = {
            'iss': issuer,
            'sub': subject,
            'aud': audience,
            'iat': now,
            'exp': now + datetime.timedelta(minutes=expiration_minutes)
        }

        private_key = self.secrets.get("DEFAULT", "jwt_private_key")
        token = jwt.encode(payload, private_key, algorithm='RS256')
        return token

    def generate_dpop_jwt(self, http_method, http_uri):
        """
        Generate a DPoP JWT.

        :param http_method: The HTTP method (e.g., "POST").
        :param http_uri: The HTTP URI.
        :param private_key: The private key to sign the JWT.
        :param algorithm: The algorithm to use for signing the JWT.
        :return: The generated DPoP JWT as a string.
        """
        now = datetime.datetime.utcnow()
        headers = {
            'typ': 'dpop+jwt',
            'alg': 'RS256',
            'jwk': self.get_json_web_key()
        }
        payload = {
            'htm': http_method,
            'htu': http_uri,
            'iat': now,
            'jti': str(uuid.uuid4())
        }

        if self.nonce:
            payload['nonce'] = self.nonce
        
        if self.has_valid_access_token():
            access_token_hash = hashlib.sha256(self.access_token.encode("utf-8")).digest()
            payload['ath'] = base64.urlsafe_b64encode(access_token_hash).decode('utf-8').rstrip('=')

        self.log.debug(headers)
        self.log.debug(payload)

        private_key = self.secrets.get("DEFAULT", "jwt_private_key")
        token = jwt.encode(payload, private_key, headers=headers, algorithm='RS256')
        return token

    def get_json_web_key(self):
        """
        Convert a public key in ASCII armor format to a JSON Web Key (JWK).

        :param public_key_pem: The public key in ASCII armor format.
        :return: The public key in JWK format.
        """
        public_key_pem = self.config.get("DEFAULT", "jwt_public_key")
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        
        if isinstance(public_key, rsa.RSAPublicKey):
            public_numbers = public_key.public_numbers()
            jwk = {
                "kty": "RSA",
                "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('='),
                "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')
            }
            return jwk
        else:
            raise ValueError("Unsupported key type")

    def get_par_payload(self):
        payload = {
            "client_id": self.get_client_id(),
            "code_challenge": self.code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": f"{self.url}/oauth/callback",
            "response_type": "code",
            "scope": "atproto transition:generic",
            "state": self.randomstring(),
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": self.jwt
        }

        return payload

    def send_par_request(self):
        url = self.authserver_metadata["pushed_authorization_request_endpoint"]
        payload = self.get_par_payload()
        res = requests.post(url, data=payload)

        if res.status_code == 201:
            data = res.json()
            self.log.debug(data)
            return data['request_uri']
        else:
            self.log.error(f"PAR request failed: {res.status_code}")
            self.log.error(res.text)

    def redirect_to_authserver(self, request_uri):
        auth_url = self.authserver_metadata['authorization_endpoint']
        request_uri = urllib.parse.quote(request_uri)
        client_id = urllib.parse.quote(self.get_client_id())

        redirect_url = f"{auth_url}?client_id={client_id}&request_uri={request_uri}"

        self.log.info(f"Redirecting to {redirect_url}")

    def update_tokens(self, data):
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        self.access_token_expires = datetime.datetime.now() + datetime.timedelta(seconds=data['expires_in'])

        self.secrets.set("DEFAULT", "access_token", self.access_token)
        self.secrets.set("DEFAULT", "refresh_token", self.refresh_token)
        self.secrets.set("DEFAULT", "access_token_expires", self.access_token_expires.isoformat())

        self.on_tokens(data)

    def xrpc_call(self, endpoint, payload=None):
        url = f"{self.authserver_url}{endpoint}"

        headers = {
            "Authorization": f"DPoP {self.access_token}",
            "DPoP": self.generate_dpop_jwt("GET", url)
        }

        if (payload):
            res = requests.post(url, headers=headers, json=payload)
        else:
            res = requests.get(url, headers=headers)

        if res.status_code == 200:
            data = res.json()
            self.log.debug(data)
            return data
        elif res.status_code == 401:
            error = res.json()
            self.log.debug(res.headers)
            self.log.debug(error)

            if error['error'] == 'use_dpop_nonce' and self.nonce is None:    
                self.nonce = res.headers['dpop-nonce']
                if self.nonce:
                    self.log.error("Server requested nonce, retrying with nonce...")
                    return self.xrpc_call(endpoint, payload)
            
            
        elif res.status_code == 400:
            error = res.json()
            self.log.error(f"Server returned error 400")
            self.log.error(error)
            return None
        else:
            self.log.error(f"Failed to retrieve profile: {res.status_code}")
            self.log.error(res.text)
            return None
    
    def has_valid_access_token(self):
        if not self.access_token:
            return False

        if datetime.datetime.now() > self.access_token_expires:
            return False

        return True
    
    def has_refresh_token(self):
        return self.refresh_token is not None
    
    def start(self):
        if not self.has_refresh_token():
            request_uri = self.send_par_request()
            self.redirect_to_authserver(request_uri)
        elif not self.has_valid_access_token():
            self.request_token_refresh()
