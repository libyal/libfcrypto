if HAVE_PYTHON
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBFCRYPTO_DLL_IMPORT@

pyexec_LTLIBRARIES = pyfcrypto.la

pyfcrypto_la_SOURCES = \
	pyfcrypto.c pyfcrypto.h \
	pyfcrypto_crypt.c pyfcrypto_crypt.h \
	pyfcrypto_crypt_modes.c pyfcrypto_crypt_modes.h \
	pyfcrypto_des3_context.c pyfcrypto_des3_context.h \
	pyfcrypto_error.c pyfcrypto_error.h \
	pyfcrypto_libcerror.h \
	pyfcrypto_libfcrypto.h \
	pyfcrypto_python.h \
	pyfcrypto_rc4_context.c pyfcrypto_rc4_context.h \
	pyfcrypto_unused.h

pyfcrypto_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libfcrypto/libfcrypto.la

pyfcrypto_la_CPPFLAGS = $(PYTHON_CPPFLAGS)
pyfcrypto_la_LDFLAGS  = -module -avoid-version $(PYTHON_LDFLAGS)

endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

