from smartcard.CardConnection import CardConnection

class Reader:
    def createConnection(self) -> CardConnection: ...
