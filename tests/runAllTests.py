import threading as thread

def ctt():
    numSuccess = 0
    from compareToTaintTests import test
    try:
        test.test1()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test1 failed!")

    try:
        test.test2()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test2 failed!")

    try:
        test.test3()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test3 failed!")

    try:
        test.testModelCollection()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests testModelCollection failed!")

    print(numSuccess, " tests passed in compareToTaintTests.")
        
if __name__ == "__main__":
    t1 = t.Thread(target=ctt,args=())

    t1.start()

    t1.join()

    print("All tests compete.")

