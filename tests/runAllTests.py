import _thread as thread

def ctt():
    numSuccess = 0
    from compareToTaintTests.test import *
    try:
        test1()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test1 failed!")

    try:
        test2()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test2 failed!")

    try:
        test3()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests test3 failed!")

    try:
        testModelCollection()
        numSuccess += 1
    except AssertionError:
        print("compareToTaintTests testModelCollection failed!")

    print(numSuccess, " tests passed in compareToTaintTests.")
        
thread.start_new_thread(ctt,("",0,))

