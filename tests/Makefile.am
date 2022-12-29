AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBFCRYPTO_DLL_IMPORT@

if HAVE_PYTHON_TESTS
TESTS_PYFCRYPTO = \
	test_python_module.sh
endif

TESTS = \
	test_library.sh \
	$(TESTS_PYFCRYPTO)

check_SCRIPTS = \
	pyfcrypto_test_des3_context.py \
	pyfcrypto_test_rc4_context.py \
	pyfcrypto_test_support.py \
	test_library.sh \
	test_manpage.sh \
	test_python_module.sh \
	test_runner.sh

EXTRA_DIST = \
	$(check_SCRIPTS)

check_PROGRAMS = \
	fcrypto_test_des3_context \
	fcrypto_test_error \
	fcrypto_test_rc4_context \
	fcrypto_test_serpent_context \
	fcrypto_test_support

fcrypto_test_des3_context_SOURCES = \
	fcrypto_test_des3_context.c \
	fcrypto_test_libcerror.h \
	fcrypto_test_libfcrypto.h \
	fcrypto_test_macros.h \
	fcrypto_test_memory.c fcrypto_test_memory.h \
	fcrypto_test_unused.h

fcrypto_test_des3_context_LDADD = \
	../libfcrypto/libfcrypto.la \
	@LIBCERROR_LIBADD@

fcrypto_test_error_SOURCES = \
	fcrypto_test_error.c \
	fcrypto_test_libfcrypto.h \
	fcrypto_test_macros.h \
	fcrypto_test_unused.h

fcrypto_test_error_LDADD = \
	../libfcrypto/libfcrypto.la

fcrypto_test_rc4_context_SOURCES = \
	fcrypto_test_libcerror.h \
	fcrypto_test_libfcrypto.h \
	fcrypto_test_macros.h \
	fcrypto_test_memory.c fcrypto_test_memory.h \
	fcrypto_test_rc4_context.c \
	fcrypto_test_unused.h

fcrypto_test_rc4_context_LDADD = \
	../libfcrypto/libfcrypto.la \
	@LIBCERROR_LIBADD@

fcrypto_test_serpent_context_SOURCES = \
	fcrypto_test_libcerror.h \
	fcrypto_test_libfcrypto.h \
	fcrypto_test_macros.h \
	fcrypto_test_memory.c fcrypto_test_memory.h \
	fcrypto_test_serpent_context.c \
	fcrypto_test_unused.h

fcrypto_test_serpent_context_LDADD = \
	../libfcrypto/libfcrypto.la \
	@LIBCERROR_LIBADD@

fcrypto_test_support_SOURCES = \
	fcrypto_test_libfcrypto.h \
	fcrypto_test_macros.h \
	fcrypto_test_support.c \
	fcrypto_test_unused.h

fcrypto_test_support_LDADD = \
	../libfcrypto/libfcrypto.la

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

