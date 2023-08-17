"""
Modeled on the patterns in Python3's `zipfile`.
"""


class CpkFile:
    def __init__(self, name):
        self.name = name

    @classmethod
    def fromLocalPath(cls, filename):
        return cls(filename)

    def infolist(self):
        return [
            CpkInfo(self.name)
        ]


class CpkInfo:
    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return f"CpkInfo(name={self.name})"