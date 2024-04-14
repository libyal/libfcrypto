AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBFCRYPTO_DLL_EXPORT@

lib_LTLIBRARIES = libfcrypto.la

libfcrypto_la_SOURCES = \
	libfcrypto.c \
	libfcrypto_blowfish_context.c libfcrypto_blowfish_context.h \
	libfcrypto_definitions.h \
	libfcrypto_des3_context.c libfcrypto_des3_context.h \
	libfcrypto_extern.h \
	libfcrypto_error.c libfcrypto_error.h \
	libfcrypto_libcerror.h \
	libfcrypto_rc4_context.c libfcrypto_rc4_context.h \
	libfcrypto_serpent_context.c libfcrypto_serpent_context.h \
	libfcrypto_support.c libfcrypto_support.h \
	libfcrypto_types.h \
	libfcrypto_unused.h

libfcrypto_la_LIBADD = \
	@LIBCERROR_LIBADD@

libfcrypto_la_LDFLAGS = -no-undefined -version-info 1:0:0

EXTRA_DIST = \
	libfcrypto_definitions.h.in \
	libfcrypto.rc \
	libfcrypto.rc.in

DISTCLEANFILES = \
	libfcrypto_definitions.h \
	libfcrypto.rc \
	Makefile \
	Makefile.in

sources-local: $(BUILT_SOURCES)

splint-local:
	@echo "Running splint on libfcrypto ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(libfcrypto_la_SOURCES)

