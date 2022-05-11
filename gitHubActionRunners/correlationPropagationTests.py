from tests.getCorrelationsTests import propagationTests

test = propagationTests.TestPropagation()

test.testNoMem()
test.testSmallScale()
test.testLargeScale()
