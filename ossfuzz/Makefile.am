if HAVE_LIB_FUZZING_ENGINE
AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common

bin_PROGRAMS = \
	crypt_rc4_fuzzer \
	crypt_serpent_cbc_fuzzer \
	crypt_serpent_ecb_fuzzer

crypt_rc4_fuzzer_SOURCES = \
	crypt_rc4_fuzzer.cc \
	ossfuzz_libfcrypto.h

crypt_rc4_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libfcrypto/libfcrypto.la

crypt_serpent_cbc_fuzzer_SOURCES = \
	crypt_serpent_cbc_fuzzer.cc \
	ossfuzz_libfcrypto.h

crypt_serpent_cbc_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libfcrypto/libfcrypto.la

crypt_serpent_ecb_fuzzer_SOURCES = \
	crypt_serpent_ecb_fuzzer.cc \
	ossfuzz_libfcrypto.h

crypt_serpent_ecb_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../libfcrypto/libfcrypto.la
endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile

splint:
	@echo "Running splint on crypt_rc4_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_rc4_fuzzer_SOURCES)
	@echo "Running splint on crypt_serpent_cbc_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_serpent_cbc_fuzzer_SOURCES)
	@echo "Running splint on crypt_serpent_ecb_fuzzer ..."
	-splint -preproc -redef $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(crypt_serpent_ecb_fuzzer_SOURCES)

