# Note that we cannot use: AUTOMAKE_OPTIONS = subdir-objects
# subdir-objects will compile the source files to a single version of Python.
# Since subdir-objects is being deprecated we copy the source files instead.
am__installdirs = "$(DESTDIR)$(pyexecdir3)"
pyexecdir = $(pyexecdir3)

if HAVE_PYTHON3
AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBFCRYPTO_DLL_IMPORT@

am_pyfcrypto_la_rpath = -rpath $(pyexecdir3)

BUILT_SOURCES = \
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

pyexec_LTLIBRARIES = pyfcrypto.la

nodist_pyfcrypto_la_SOURCES = $(BUILT_SOURCES)

pyfcrypto_la_LIBADD = \
	@LIBCERROR_LIBADD@ \
	../libfcrypto/libfcrypto.la

pyfcrypto_la_CPPFLAGS = $(PYTHON3_CPPFLAGS)
pyfcrypto_la_LDFLAGS  = -module -avoid-version $(PYTHON3_LDFLAGS)

$(BUILT_SOURCES):
	/bin/cp -f $(top_srcdir)/pyfcrypto/$@ $@

endif

MAINTAINERCLEANFILES = \
	Makefile.in

clean-local:
	/bin/rm -f pyfcrypto*.[ch]

distclean: clean
	/bin/rm -f Makefile

