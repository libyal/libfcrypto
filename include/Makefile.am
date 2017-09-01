include_HEADERS = \
	libfcrypto.h

pkginclude_HEADERS = \
	libfcrypto/definitions.h \
	libfcrypto/error.h \
	libfcrypto/extern.h \
	libfcrypto/features.h \
	libfcrypto/types.h

EXTRA_DIST = \
	libfcrypto.h.in \
	libfcrypto/definitions.h.in \
	libfcrypto/features.h.in \
	libfcrypto/types.h.in

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f libfcrypto.h
	/bin/rm -f libfcrypto/definitions.h
	/bin/rm -f libfcrypto/features.h
	/bin/rm -f libfcrypto/types.h
	/bin/rm -f Makefile

