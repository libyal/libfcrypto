#!/bin/sh
# Script to run tests
#
# Version: 20260609

if test -f ${PWD}/libfcrypto/.libs/libfcrypto.1.dylib && test -f ./pyfcrypto/.libs/pyfcrypto.so
then
	install_name_tool -change /usr/local/lib/libfcrypto.1.dylib ${PWD}/libfcrypto/.libs/libfcrypto.1.dylib ./pyfcrypto/.libs/pyfcrypto.so
fi

make check-build > /dev/null

make check $@
RESULT=$?

if test ${RESULT} -ne 0
then
	find . -name \*.log -path \*.dir/\*/\*.log -print -exec cat {} \;
fi
exit ${RESULT}

