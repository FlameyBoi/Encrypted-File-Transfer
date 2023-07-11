from defs import *


# ClientHeader: Class representing a protocol header of user sent messages
class ClientHeader:
    def __init__(self, uid, code, size):
        self.uid = uid
        self.ver = VER
        self.code = code
        self.size = size


# ServerHeader: Object representing a protocol header of server sent messages
class ServerHeader:
    def __init__(self, code, size):
        self.ver = VER
        self.code = code
        self.size = size
