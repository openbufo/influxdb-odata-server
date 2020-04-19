import logging
import sys
from configparser import ConfigParser
from werkzeug.wrappers import AuthorizationMixin, BaseRequest
from local import local, local_manager
from importlib import import_module
import traceback
import argparse

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

class Request(BaseRequest, AuthorizationMixin):
    pass

def get_config(config):
    c = ConfigParser(allow_no_value=True)
    with open(config, 'r') as fp:
        #c = get_sample_config()
        c.read_file(fp)
    return c


class prepareHTTPProxy(object):
    def __init__(self, app):
        self.wrapped = app

    def __call__(self, environ, start_response):
        local.request = req = Request(environ)
        return self.wrapped(environ, start_response)


class Auth():
    def __init__(self, app, auth_config):
        self._app = app

        self.auth_method_function_mapping = {'basic_http' : '_basicHTTPAuthenticated'}

        self.auth_method = auth_config['method']
        if self.auth_method not in self.auth_method_function_mapping.keys():
            logger.exception("Authentication method '{}' not supported in this version. Allowed authentication "
                             "methods are {}".format(auth_config['method'], str(list(self.auth_method_function_mapping.keys()))))
            raise ValueError()

        try:
            auth_module = import_module('authentication.{}'.format(auth_config['validator']))
            logger.info("Initialising authentication service using with '{}' as validator and {} as authentication method"
                        .format(auth_config['validator'], self.auth_method))
            self.authentication_client =  getattr(auth_module, 'authentication')(auth_config)
        except (ImportError, AttributeError) as e:
            logger.exception("Failed to configure authentication module. Make sure validator and method are valid "
                             "in authentication section of the configuation")
            raise ImportError()

    def __call__(self, environ, start_response):
        # supports HTTP basic auth and header based authentication
        http_auth_header = environ.get('HTTP_AUTHORIZATION', None)
        if http_auth_header is not None:
            # if self._basicHTTPAuthenticated(http_auth_header):
            if getattr(self, self.auth_method_function_mapping[self.auth_method])(http_auth_header):
                return self._app(environ, start_response)
            return self._failed(environ, start_response)
        else:
            # no http_authorization reader found
            return self._failed(environ, start_response)

    def _basicHTTPAuthenticated(self, header):
        # for basic HTTP authorization
        from base64 import b64decode
        if not header:
            return False
        _, encoded = header.split(None, 1)
        decoded = b64decode(encoded).decode('UTF-8')
        username, password = decoded.split(':', 1)
        return self.authentication_client.password_verify(username, password) #self.awscognito_auth(username, password)

    def _failed(self, environ, start_response):
        start_response('401 Authentication Required',
                       [('Content-Type', 'text/plain'),
                        ('WWW-Authenticate', 'Basic realm="Login"')])
        yield b'Authentication error. Make sure username/password or tokens are correct'


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

def createSchemaMetadata(config):
    try:
        metadata_filename = config.get('metadata', 'metadata_file')
        logger.info("Generating OData metadata xml file from InfluxDB metadata")
        influxdb_version = config.getint('metadata', 'influxdb_version')
        if influxdb_version == 2:
            from influxdbmeta_v2 import generate_metadata
            metadata = generate_metadata(connection=config._sections['influxdb2'])
        else:
            from influxdbmeta import generate_metadata
            metadata = generate_metadata(connection=config._sections['influxdb'])

        with open(metadata_filename, 'w') as f:
                f.write(metadata)
        logger.info("Successfully created Odata provider metadata at {}".format(metadata_filename))
        return True
    except Exception as e:
        traceback.print_exc()
        logger.exception("Failed to create Odata provider metadata due to following error : {}".format(str(e)))
        return False

def configure_app(c, doc):
    service_root = c.get('server', 'service_advertise_root')
    logger.info("Advertising service at %s" % service_root)
    app = ReadOnlyServer(serviceRoot=service_root)
    app.set_model(doc)
    return app


if __name__ == "__main__":
    """read config and start odata api server"""
    # parse arguments
    p = argparse.ArgumentParser(description='Odata sevice provider for InfluxDB')
    p.add_argument('-c', '--config',
                   help='specify a conf file (default=settings.conf)',
                   default='settings.conf')
    p.add_argument('-m', '--createmetadata',
                   help='generates xml metadata metadata.conf in your current directory (does not start server)',
                   action="store_true")
    args = p.parse_args()

    # parse config file
    c = get_config(args.config)    # args.config

    if args.createmetadata:
        createSchemaMetadata(c)
        sys.exit()

    # generate and load metadata
    doc = load_metadata(c)

    # start server
    app = configure_app(c, doc)
    app = prepareHTTPProxy(app)
    app = local_manager.make_middleware(app)

    if c.getboolean('authentication', 'required'):
        auth_config = c._sections["authentication"]
        app = Auth(app, auth_config)

    from werkzeug.serving import run_simple
    listen_interface = c.get('server', 'server_listen_interface')
    listen_port = int(c.get('server', 'server_listen_port'))
    logger.info("Starting HTTP server on: interface: %s, port: %i..." % (listen_interface, listen_port))
    run_simple(listen_interface, listen_port, application=app)

