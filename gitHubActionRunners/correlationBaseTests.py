from tests.getCorrelationsTests import regToRegTest

test = regToRegTest.Tests()

test.test_noCorrelations()
test.test_allCorrelated()
test.test_addCorrelated()
test.test_addCorrelatedWithExtra()
