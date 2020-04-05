from werkzeug.local import Local, LocalManager, LocalProxy
#if __name__ == "__main__":
local = Local()
local_manager = LocalManager([local])
#request = local('request')
request = LocalProxy(local, 'request')