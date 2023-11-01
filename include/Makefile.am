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
	-rm -f libfcrypto.h
	-rm -f libfcrypto/definitions.h
	-rm -f libfcrypto/features.h
	-rm -f libfcrypto/types.h
	-rm -f Makefile

