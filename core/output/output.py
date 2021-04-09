class Output:
    def __init__(self, path: str):
        self.path = path
        self.file = open(path, 'w')

    def __del__(self):
        self.file.close()

    def write(self, x: str):
        self.file.write(x)
