import boto3
import botocore.exceptions
import hmac
import hashlib
import base64
import logging
import sys

#logging.basicConfig()
logHandler = logging.StreamHandler(sys.stdout)
logFormatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
#logHandler.formatter = logFormatter
logger = logging.getLogger("auth-aws-cognito")
logger.addHandler(logHandler)
logger.setLevel(logging.DEBUG)

class authentication():
    def  __init__(self, configuration):
        if not isinstance(configuration, dict):
            configuration = dict(configuration)
        try:
            self.USER_POOL_ID = configuration['user_pool_id']
            self.CLIENT_ID = configuration['client_id']
            self.CLIENT_SECRET = configuration['client_secret']
        except:
            # Couldn't find cognito credentials
            logging.error("Missing AWS congnito credentials in configuration")
            return ValueError
        self.awscognito_client = boto3.client('cognito-idp')

    def get_secret_hash(self, username):
        msg = username + self.CLIENT_ID
        dig = hmac.new(str(self.CLIENT_SECRET).encode('utf-8'),
                       msg=str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
        d2 = base64.b64encode(dig).decode()
        return d2


    def password_verify(self, username, password):
        # Authentication based on username & password
        secret_hash = self.get_secret_hash(username)
        try:
            resp = self.awscognito_client.admin_initiate_auth(
                UserPoolId=self.USER_POOL_ID,
                ClientId=self.CLIENT_ID,
                AuthFlow='ADMIN_NO_SRP_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'SECRET_HASH': secret_hash,
                    'PASSWORD': password,
                },
                ClientMetadata={
                    'username': username,
                    'password': password, })
        except self.awscognito_client.exceptions.NotAuthorizedException or self.awscognito_client.exceptions.UserNotConfirmedException:
            return False
        except Exception as e:
            return False
        return True