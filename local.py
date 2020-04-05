from werkzeug.local import Local, LocalManager

local = Local()
local_manager = LocalManager()

request = local('request')


"""from werkzeug.local import Local, LocalManager

if __name__ == "__main__":
    local = Local()
    #request = LocalProxy(local, 'request')
    request = ('request')
    local_manager = LocalManager([local])
#request = LocalProxy(local, 'request')
#request = LocalManager([local])"""