AM_CPPFLAGS = \
	-I../include -I$(top_srcdir)/include \
	-I../common -I$(top_srcdir)/common \
	@LIBCERROR_CPPFLAGS@ \
	@LIBFCRYPTO_DLL_IMPORT@

check_PYTHONdir = $(abs_top_builddir)

BUILT_SOURCES = package.m4

check_AUTOTESTS = \
	test_library \
	test_manpages

if HAVE_PYTHON_TESTS
check_AUTOTESTS += test_python_module
endif

check_PYTHON_SCRIPTS = \
	pyfcrypto_test_blowfish_context.py \
	pyfcrypto_test_des3_context.py \
	pyfcrypto_test_rc4_context.py \
	pyfcrypto_test_serpent_context.py \
	pyfcrypto_test_support.py

check_PROGRAMS = \
	fcrypto_test_blowfish_context \
	fcrypto_test_des3_context \
	fcrypto_test_error \
	fcrypto_test_rc4_context \
	fcrypto_test_serpent_context \
	fcrypto_test_support

fcrypto_test_blowfish_context_SOURCES = \
	fcrypto_test_blowfish_context.c \
	fcrypto_test_libcerror.h \
	fcrypto_test_libfcrypto.h \
	fcrypto_test_macros.h \
	fcrypto_test_memory.c fcrypto_test_memory.h \
	fcrypto_test_unused.h

fcrypto_test_blowfish_context_LDADD = \
	../libfcrypto/libfcrypto.la \
	@LIBCERROR_LIBADD@

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

AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

SUFFIXES = .at

.at:
	$(AM_V_GEN)rm -f $@ $@.tmp; \
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $< && \
	mv $@.tmp $@

atconfig: $(top_builddir)/config.status
	cd $(top_builddir) && $(SHELL) ./config.status tests/$@

check-build: $(check_PROGRAMS)

check-local: $(check_AUTOTESTS)
	@fail=0; \
	for test_suite in $(check_AUTOTESTS); do \
		$(AM_TESTS_ENVIRONMENT) $(SHELL) "./$$test_suite" $(TESTSUITEFLAGS) || fail=1; \
		echo ""; \
	done; \
	exit $$fail

clean-local:
	for test_suite in $(check_AUTOTESTS); do \
		test ! -f "$$test_suite" || $(SHELL) "./$$test_suite" --clean; \
	done

package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):; \
	{ \
	  echo 'm4_define([AT_PACKAGE_NAME], [$(PACKAGE_NAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_TARNAME], [$(PACKAGE_TARNAME)])' ; \
	  echo 'm4_define([AT_PACKAGE_VERSION], [$(PACKAGE_VERSION)])' ; \
	  echo 'm4_define([AT_PACKAGE_STRING], [$(PACKAGE_STRING)])' ; \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])' ; \
	} > $@

test_library: package.m4 test_library.at test_macros.at

test_python_module: package.m4 test_python_module.at

EXTRA_DIST = \
	$(check_AUTOTESTS:=.at) \
	$(check_PYTHON_SCRIPTS) \
	package.m4 \
	test_macros.at

CLEANFILES = \
	$(check_AUTOTESTS) \
	*.exe \
	*.tmp

DISTCLEANFILES = \
	*.log \
	atconfig \
	Makefile \
	Makefile.in

