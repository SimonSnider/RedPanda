class Pearson:
    def __init__(self, xBar, yBar):
        self.xBar = xBar
        self.yBar = yBar
        self.points = []

    def addPoint(self, x, y):
        self.points.append([x, y])

    def calcPearsons(self):

        num = 0
        denomX = 0
        denomY = 0

        for point in self.points:
            xi = point[0]
            yi = point[1]

            num += (xi - xBar) * (yi - yBar)
            denomX = (xi - xBar)**2
            denomY = (yi - yBar)**2

        return num / (denomX*denomY)
