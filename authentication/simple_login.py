import logging
import sys

#logging.basicConfig()
logHandler = logging.StreamHandler(sys.stdout)
logFormatter = logging.Formatter(fmt='%(levelname)s:%(name)s:%(message)s')
#logHandler.formatter = logFormatter
logger = logging.getLogger("auth-simple-login")
logger.addHandler(logHandler)
logger.setLevel(logging.DEBUG)

class authentication():
    def  __init__(self, configuration):
        if not isinstance(configuration, dict):
            configuration = dict(configuration)
        try:
            self.username = configuration['username']
            self.password = configuration['password']
        except:
            # Couldn't find credentials
            logging.error("Missing user credentials in configuration")

    def password_verify(self, username, password):
        # Authentication based on username & password
        if self.username == username and self.password == password:
            return True
        return False