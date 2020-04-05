import logging
import sys
from configparser import ConfigParser
from werkzeug.wrappers import AuthorizationMixin, BaseRequest, Response
from werkzeug.routing import Map, Rule, NotFound, RequestRedirect
from local_store import local, local_manager
import boto3
import hmac
import hashlib
import base64
from urllib.parse import unquote_plus
import traceback

import pyslet.odata2.metadata as edmx
from pyslet.odata2.server import ReadOnlyServer

cache_app = None  #: our Server instance

#logging.basicConfig()
logHandler = logging.StreamHandler(sys.stdout)
logFormatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
#logHandler.formatter = logFormatter
logger = logging.getLogger("odata-influxdb")
logger.addHandler(logHandler)
logger.setLevel(logging.DEBUG)

config_file = "production.conf"

def get_config(config):
    c = ConfigParser(allow_no_value=True)
    with open(config, 'r') as fp:
        #c = get_sample_config()
        c.read_file(fp)
    return c

def prepareSchemaMetadata(req, bucket_name):
    try:
        config = get_config(config_file)
        metadata_filename = config.get('metadata', 'metadata_file')
        logger.info("Generating OData metadata xml file from InfluxDB metadata")
        influxdb_version = config.getint('metadata', 'influxdb_version')
        if influxdb_version == 2:
            from influxdbmeta_v2 import generate_metadata
            metadata = generate_metadata(connection=config._sections['influxdb2'], bucket=bucket_name)
        else:
            from influxdbmeta import generate_metadata
            dsn = config.get('influxdb', 'dsn')
            metadata = generate_metadata(dsn)

        with open(metadata_filename, 'w') as f:
                f.write(metadata)
        success_msg = "Successfully created Odata provider metadata for bucket '{}' at {}".format(str(bucket_name), metadata_filename)
        return '200 OK', [str.encode(metadata)]
    except Exception as e:
        traceback.print_exc()
        err_msg = "Failed to create Odata provider metadata for bucket '{}' due to following error : {}".format(str(bucket_name), str(e))
        return '400 Bad Request', [str.encode(err_msg)]

url_map = Map([
    Rule('/dev/createmetadata/<bucket_name>', endpoint='prepareSchemaMetadata')
])
views = {'prepareSchemaMetadata': prepareSchemaMetadata}

class Request(BaseRequest, AuthorizationMixin):
    pass


class prepareHTTPProxy(object):
    def __init__(self, app):
        self.wrapped = app

    def __call__(self, environ, start_response):
        local.request = req = Request(environ)
        urls = url_map.bind_to_environ(environ)
        try:
            endpoint, args = urls.match()
        except Exception as e:
            return self.wrapped(environ, start_response)
        status, res = urls.dispatch(lambda e, v: views[e](req, **v),catch_http_exceptions=True)
        start_response(status,  [('Content-Type', 'text/plain')])
        return res


class Auth():
    def __init__(self, app, cognito_credentials):
        self._app = app
        cognito_credentials = dict(cognito_credentials)
        try:
            self.USER_POOL_ID = cognito_credentials['user_pool_id']
            self.CLIENT_ID = cognito_credentials['client_id']
            self.CLIENT_SECRET = cognito_credentials['client_secret']
        except:
            # Couldn't find cognito credentials
            logging.error("Missing AWS congnito credentials in configuration")

        self.awscognito_client = boto3.client('cognito-idp')

    def __call__(self, environ, start_response):
        # AWS API Gateway quotes URLs with urllb.quote_plus function
        # Hence, spaces are replaced with '+' and special chars are escaped.
        # Pyslet accepts '%20' instead of '+'. Thus, query_string is modified accordingly
        query_string = environ['QUERY_STRING']
        environ.update({"QUERY_STRING": unquote_plus(query_string).replace(' ', '%20')})

        # supports HTTP basic auth and header based authentication
        http_auth_header = environ.get('HTTP_AUTHORIZATION', None)
        if http_auth_header is not None:
            if self._basicHTTPAuthenticated(http_auth_header):
                return self._app(environ, start_response)
            return self._failed(environ, start_response)
        else:
            # no http_authorization reader found
            return self._failed(environ, start_response)

    """
    def _authenticated(self, header):
        if not header:
            return False
        username = header.get("username", None)
        password = header.get("password", None)
        if username is None or password is None:
            return False
        return self.awscognito_auth(username, password)

    """

    def _basicHTTPAuthenticated(self, header):
        # for basic HTTP authorization
        from base64 import b64decode
        if not header:
            return False
        _, encoded = header.split(None, 1)
        decoded = b64decode(encoded).decode('UTF-8')
        username, password = decoded.split(':', 1)
        return self.awscognito_auth(username, password)

    def _failed(self, environ, start_response):
        start_response('401 Authentication Required',
                       [('Content-Type', 'text/plain'),
                        ('WWW-Authenticate', 'Basic realm="Login"')])
        return ['Authentication error. Make sure username and password are correct.']

    def get_secret_hash(self, username):
        msg = username + self.CLIENT_ID
        dig = hmac.new(str(self.CLIENT_SECRET).encode('utf-8'),
                       msg=str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
        d2 = base64.b64encode(dig).decode()
        return d2

    def awscognito_auth(self, username, password):
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


def load_metadata(config):
    """Regenerate and load the metadata file and connects the InfluxDBEntityContainer."""
    metadata_filename = config.get('metadata', 'metadata_file')
    influxdb_version = config.getint('metadata', 'influxdb_version')
    try:
        topmax = config.getint('metadata', 'max_items_per_query')
    except:
        topmax = 50

    doc = edmx.Document()
    with open(metadata_filename, 'rb') as f:
        doc.read_from_stream(f)
    container = doc.root.DataServices['InfluxDBSchema.InfluxDB']

    if influxdb_version == 2:
        from influxdbds_v2 import InfluxDBEntityContainer
        conn = dict(config._sections['influxdb2'])
        InfluxDBEntityContainer(container=container, connection=conn, topmax=topmax)
    else:
        from influxdbds import InfluxDBEntityContainer
        dsn = config.get('influxdb', 'dsn')
        InfluxDBEntityContainer(container=container, dsn=dsn, topmax=topmax)

    return doc


def configure_app(c, doc):
    service_root = c.get('server', 'service_advertise_root')
    logger.info("Advertising service at %s" % service_root)
    app = ReadOnlyServer(serviceRoot=service_root)
    app.set_model(doc)
    return app


if __name__ == "__main__":
    # parse config file
    c = get_config(config_file)    # args.config

    # generate and load metadata
    doc = load_metadata(c)

    # start server
    app = configure_app(c, doc)
    app = prepareHTTPProxy(app)
    app = local_manager.make_middleware(app)

    if c.getboolean('authentication', 'required'):
        cognito_credentials = c._sections["authentication"]
        app = Auth(app, cognito_credentials)

    from werkzeug.serving import run_simple
    listen_interface = c.get('server', 'server_listen_interface')
    listen_port = int(c.get('server', 'server_listen_port'))
    logger.info("Starting HTTP server on: interface: %s, port: %i..." % (listen_interface, listen_port))
    run_simple(listen_interface, listen_port, application=app)

