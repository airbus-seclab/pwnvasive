class PwnvasiveException(Exception):
    pass
class NoCredsFound(PwnvasiveException):
    def __str__(self):
        return f"{self.__class__.__name__}: no creds found for {self.args[0]}"

class OSNotIdentified(PwnvasiveException):
    pass

class NodeUnreachable(PwnvasiveException):
    pass
