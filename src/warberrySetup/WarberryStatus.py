

class WarberryStatus:

    def __init__(self):
        self.status = ""

    def updateStatus(self, str):
        self.status+=str

    def warberryHEADER(self, str):
        print (str)
        self.updateStatus(str)

    def warberryOKBLUE(self, str):
        print (str)
        self.updateStatus(str)

    def warberryOKGREEN(self, str):
        print (str)
        self.updateStatus(str)

    def warberryWARNING(self, str):
        print (str)
        self.updateStatus( str)

    def warberryFAIL(self, str):
        print (str)
        self.updateStatus(str)

    def warberryBOLD(self, str):
        print (str)
        self.updateStatus(str)

    def warberryTITLE(self, str):
        print (str)
        self.updateStatus(str)
