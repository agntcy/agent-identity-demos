import importlib.util
from pathlib import Path
import time
import unittest
import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

spec = importlib.util.spec_from_file_location('simple_demo', Path(__file__).parents[1] / 'webapp' / 'simple_demo.py')
simple = importlib.util.module_from_spec(spec)
spec.loader.exec_module(simple)


class WorkloadAuthenticationTests(unittest.IsolatedAsyncioTestCase):
    async def authenticate(self, **changes):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        issuer = 'https://login.example/realms/demo'
        claims = dict(iss=issuer, sub='workload-id', azp='publisher', preferred_username='service-account-publisher', iat=int(time.time()), exp=int(time.time()) + 120)
        claims.update(changes)
        token = jwt.encode(claims, key, algorithm='RS256', headers={'kid': 'test-key'})
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
        jwk.update(kid='test-key', use='sig')
        def handle(request):
            if request.url.path.endswith('/token'):
                return httpx.Response(200, json={'access_token': token})
            if request.url.path.endswith('/certs'):
                return httpx.Response(200, json={'keys': [jwk]})
            return httpx.Response(200, json={'issuer': issuer})
        async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
            return await simple.login(client, 'http://keycloak', 'demo', 'publisher', 'fixture-secret')

    async def test_valid_workload_returns_no_token(self):
        result = await self.authenticate()
        self.assertTrue(result['signature_verified'])
        self.assertNotIn('access_token', result)

    async def test_wrong_client_rejected(self):
        with self.assertRaises(ValueError):
            await self.authenticate(azp='another-client')

    async def test_wrong_issuer_rejected(self):
        with self.assertRaises(jwt.InvalidIssuerError):
            await self.authenticate(iss='https://wrong.example')

    async def test_expired_token_rejected(self):
        with self.assertRaises(jwt.ExpiredSignatureError):
            await self.authenticate(exp=int(time.time()) - 10)
