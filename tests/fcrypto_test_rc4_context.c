/*
 * Library rc4_context type test program
 *
 * Copyright (C) 2017, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This software is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <file_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "fcrypto_test_libcerror.h"
#include "fcrypto_test_libfcrypto.h"
#include "fcrypto_test_macros.h"
#include "fcrypto_test_memory.h"
#include "fcrypto_test_unused.h"

/* Tests the libfcrypto_rc4_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_context_initialize(
     void )
{
	libcerror_error_t *error              = NULL;
	libfcrypto_rc4_context_t *rc4_context = NULL;
	int result                            = 0;

#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	int number_of_malloc_fail_tests       = 1;
	int number_of_memset_fail_tests       = 1;
	int test_number                       = 0;
#endif

	/* Test regular cases
	 */
	result = libfcrypto_rc4_context_initialize(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_rc4_context_free(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfcrypto_rc4_context_initialize(
	          NULL,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	rc4_context = (libfcrypto_rc4_context_t *) 0x12345678UL;

	result = libfcrypto_rc4_context_initialize(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	rc4_context = NULL;

#if defined( HAVE_FCRYPTO_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libfcrypto_rc4_context_initialize with malloc failing
		 */
		fcrypto_test_malloc_attempts_before_fail = test_number;

		result = libfcrypto_rc4_context_initialize(
		          &rc4_context,
		          &error );

		if( fcrypto_test_malloc_attempts_before_fail != -1 )
		{
			fcrypto_test_malloc_attempts_before_fail = -1;

			if( rc4_context != NULL )
			{
				libfcrypto_rc4_context_free(
				 &rc4_context,
				 NULL );
			}
		}
		else
		{
			FCRYPTO_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			FCRYPTO_TEST_ASSERT_IS_NULL(
			 "rc4_context",
			 rc4_context );

			FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libfcrypto_rc4_context_initialize with memset failing
		 */
		fcrypto_test_memset_attempts_before_fail = test_number;

		result = libfcrypto_rc4_context_initialize(
		          &rc4_context,
		          &error );

		if( fcrypto_test_memset_attempts_before_fail != -1 )
		{
			fcrypto_test_memset_attempts_before_fail = -1;

			if( rc4_context != NULL )
			{
				libfcrypto_rc4_context_free(
				 &rc4_context,
				 NULL );
			}
		}
		else
		{
			FCRYPTO_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			FCRYPTO_TEST_ASSERT_IS_NULL(
			 "rc4_context",
			 rc4_context );

			FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_FCRYPTO_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( rc4_context != NULL )
	{
		libfcrypto_rc4_context_free(
		 &rc4_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_rc4_context_free function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_context_free(
     void )
{
#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	libfcrypto_rc4_context_t *rc4_context = NULL;
#endif

	libcerror_error_t *error              = NULL;
	int result                            = 0;

	/* Test error cases
	 */
	result = libfcrypto_rc4_context_free(
	          NULL,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	/* Initialize test
	 */
	result = libfcrypto_rc4_context_initialize(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test libfcrypto_rc4_context_free with memset failing
	 */
	fcrypto_test_memset_attempts_before_fail = 0;

	result = libfcrypto_rc4_context_free(
	          &rc4_context,
	          &error );

	if( fcrypto_test_memset_attempts_before_fail != -1 )
	{
		fcrypto_test_memset_attempts_before_fail = -1;
	}
	else
	{
		FCRYPTO_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 -1 );

		FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
		 "error",
		 error );

		libcerror_error_free(
		 &error );
	}
	/* Clean up
	 */
	result = libfcrypto_rc4_context_free(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

#endif /* defined( HAVE_FCRYPTO_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	if( rc4_context != NULL )
	{
		libfcrypto_rc4_context_free(
		 &rc4_context,
		 NULL );
	}
#endif
	return( 0 );
}

/* Tests the libfcrypto_rc4_context_set_key function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_context_set_key(
     void )
{
	libcerror_error_t *error              = NULL;
	libfcrypto_rc4_context_t *rc4_context = NULL;
	int result                            = 0;

	/* Initialize test
	 */
	result = libfcrypto_rc4_context_initialize(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test set key
	 */
	result = libfcrypto_rc4_context_set_key(
	          rc4_context,
	          (uint8_t *) "test1",
	          40,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfcrypto_rc4_context_set_key(
	          NULL,
	          (uint8_t *) "test1",
	          40,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_context_set_key(
	          rc4_context,
	          NULL,
	          40,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_context_set_key(
	          rc4_context,
	          (uint8_t *) "test1",
	          32,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libfcrypto_rc4_context_free(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( rc4_context != NULL )
	{
		libfcrypto_rc4_context_free(
		 &rc4_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_rc4_crypt function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt(
     void )
{
	uint8_t input_data[ 48 ];
	uint8_t output_data[ 48 ];

	libcerror_error_t *error              = NULL;
	libfcrypto_rc4_context_t *rc4_context = NULL;
	int result                            = 0;

	/* Initialize test
	 */
	result = libfcrypto_rc4_context_initialize(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_rc4_context_set_key(
	          rc4_context,
	          (uint8_t *) "test1",
	          40,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test de- or encrypting a buffer of data
	 */
	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          input_data,
	          48,
	          output_data,
	          48,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

/* TODO check output_data */

	/* Test error cases
	 */
	result = libfcrypto_rc4_crypt(
	          NULL,
	          input_data,
	          48,
	          output_data,
	          48,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          NULL,
	          48,
	          output_data,
	          48,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          input_data,
	          (size_t) SSIZE_MAX + 1,
	          output_data,
	          48,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          input_data,
	          48,
	          NULL,
	          48,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          input_data,
	          48,
	          output_data,
	          (size_t) SSIZE_MAX + 1,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          input_data,
	          48,
	          output_data,
	          32,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	/* Clean up
	 */
	result = libfcrypto_rc4_context_free(
	          &rc4_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "rc4_context",
	 rc4_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( rc4_context != NULL )
	{
		libfcrypto_rc4_context_free(
		 &rc4_context,
		 NULL );
	}
	return( 0 );
}

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc FCRYPTO_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] FCRYPTO_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc FCRYPTO_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] FCRYPTO_TEST_ATTRIBUTE_UNUSED )
#endif
{
	FCRYPTO_TEST_UNREFERENCED_PARAMETER( argc )
	FCRYPTO_TEST_UNREFERENCED_PARAMETER( argv )

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_context_initialize",
	 fcrypto_test_rc4_context_initialize );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_context_free",
	 fcrypto_test_rc4_context_free );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_context_set_key",
	 fcrypto_test_rc4_context_set_key );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt",
	 fcrypto_test_rc4_crypt );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

