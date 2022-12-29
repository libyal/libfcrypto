/*
 * Library des3_context type test program
 *
 * Copyright (C) 2017-2022, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <file_stream.h>
#include <memory.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "fcrypto_test_libcerror.h"
#include "fcrypto_test_libfcrypto.h"
#include "fcrypto_test_macros.h"
#include "fcrypto_test_memory.h"
#include "fcrypto_test_unused.h"

#include "../libfcrypto/libfcrypto_des3_context.h"

/* Tests the libfcrypto_des3_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_des3_context_initialize(
     void )
{
	libcerror_error_t *error                = NULL;
	libfcrypto_des3_context_t *des3_context = NULL;
	int result                              = 0;

#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	int number_of_malloc_fail_tests         = 1;
	int number_of_memset_fail_tests         = 1;
	int test_number                         = 0;
#endif

	/* Test regular cases
	 */
	result = libfcrypto_des3_context_initialize(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "des3_context",
	 des3_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_des3_context_free(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "des3_context",
	 des3_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfcrypto_des3_context_initialize(
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

	des3_context = (libfcrypto_des3_context_t *) 0x12345678UL;

	result = libfcrypto_des3_context_initialize(
	          &des3_context,
	          &error );

	des3_context = NULL;

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

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libfcrypto_des3_context_initialize with malloc failing
		 */
		fcrypto_test_malloc_attempts_before_fail = test_number;

		result = libfcrypto_des3_context_initialize(
		          &des3_context,
		          &error );

		if( fcrypto_test_malloc_attempts_before_fail != -1 )
		{
			fcrypto_test_malloc_attempts_before_fail = -1;

			if( des3_context != NULL )
			{
				libfcrypto_des3_context_free(
				 &des3_context,
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
			 "des3_context",
			 des3_context );

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
		/* Test libfcrypto_des3_context_initialize with memset failing
		 */
		fcrypto_test_memset_attempts_before_fail = test_number;

		result = libfcrypto_des3_context_initialize(
		          &des3_context,
		          &error );

		if( fcrypto_test_memset_attempts_before_fail != -1 )
		{
			fcrypto_test_memset_attempts_before_fail = -1;

			if( des3_context != NULL )
			{
				libfcrypto_des3_context_free(
				 &des3_context,
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
			 "des3_context",
			 des3_context );

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
	if( des3_context != NULL )
	{
		libfcrypto_des3_context_free(
		 &des3_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_des3_context_free function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_des3_context_free(
     void )
{
#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	libfcrypto_des3_context_t *des3_context = NULL;
#endif

	libcerror_error_t *error                = NULL;
	int result                              = 0;

	/* Test error cases
	 */
	result = libfcrypto_des3_context_free(
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
	result = libfcrypto_des3_context_initialize(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "des3_context",
	 des3_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test libfcrypto_des3_context_free with memset failing
	 */
	fcrypto_test_memset_attempts_before_fail = 0;

	result = libfcrypto_des3_context_free(
	          &des3_context,
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
	result = libfcrypto_des3_context_free(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "des3_context",
	 des3_context );

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
	if( des3_context != NULL )
	{
		libfcrypto_des3_context_free(
		 &des3_context,
		 NULL );
	}
#endif
	return( 0 );
}

/* Tests the libfcrypto_des3_context_set_key function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_des3_context_set_key(
     void )
{
	uint8_t key[ 8 ] = {
		0x01, 0xea, 0x97, 0xbf, 0x45, 0x1c, 0xa8, 0x15 };

	libcerror_error_t *error                = NULL;
	libfcrypto_des3_context_t *des3_context = NULL;
	int result                              = 0;

	/* Initialize test
	 */
	result = libfcrypto_des3_context_initialize(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "des3_context",
	 des3_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular case
	 */
	result = libfcrypto_des3_context_set_key(
	          des3_context,
	          key,
	          64,
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
	result = libfcrypto_des3_context_set_key(
	          NULL,
	          key,
	          64,
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

	result = libfcrypto_des3_context_set_key(
	          des3_context,
	          NULL,
	          64,
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

	result = libfcrypto_des3_context_set_key(
	          des3_context,
	          key,
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
	result = libfcrypto_des3_context_free(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "des3_context",
	 des3_context );

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
	if( des3_context != NULL )
	{
		libfcrypto_des3_context_free(
		 &des3_context,
		 NULL );
	}
	return( 0 );
}

#if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT )

/* Tests the libfcrypto_internal_des3_context_crypt_block function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_internal_des3_context_crypt_block(
     void )
{
	libcerror_error_t *error                = NULL;
	libfcrypto_des3_context_t *des3_context = NULL;
	uint64_t output_value                   = 0;
	int result                              = 0;

	/* Initialize test
	 */
	result = libfcrypto_des3_context_initialize(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "des3_context",
	 des3_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular case
	 */
	result = libfcrypto_internal_des3_context_crypt_block(
	          (libfcrypto_internal_des3_context_t *) des3_context,
	          0x9837239487ULL,
	          LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT,
	          0x2983123819080ac1ULL,
	          &output_value,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_EQUAL_UINT64(
	 "output_value",
	 output_value,
	 (uint64_t) 0xa9494d9bbdc2873fULL );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_internal_des3_context_crypt_block(
	          (libfcrypto_internal_des3_context_t *) des3_context,
	          0x3719827398ULL,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          0x344720e90cdc908fULL,
	          &output_value,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_EQUAL_UINT64(
	 "output_value",
	 output_value,
	 (uint64_t) 0x6d0ee7e5792e2a93ULL );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfcrypto_internal_des3_context_crypt_block(
	          NULL,
	          0x9837239487ULL,
	          LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT,
	          0x2983123819080ac1ULL,
	          &output_value,
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

	result = libfcrypto_internal_des3_context_crypt_block(
	          (libfcrypto_internal_des3_context_t *) des3_context,
	          0x9837239487ULL,
	          -1,
	          0x2983123819080ac1ULL,
	          &output_value,
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

	result = libfcrypto_internal_des3_context_crypt_block(
	          (libfcrypto_internal_des3_context_t *) des3_context,
	          0x9837239487ULL,
	          LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT,
	          0x2983123819080ac1ULL,
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

	/* Clean up
	 */
	result = libfcrypto_des3_context_free(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "des3_context",
	 des3_context );

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
	if( des3_context != NULL )
	{
		libfcrypto_des3_context_free(
		 &des3_context,
		 NULL );
	}
	return( 0 );
}

#endif /* if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT ) */

/* Tests the libfcrypto_des3_crypt function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_des3_crypt(
     void )
{
	uint8_t key[ 8 ] = {
		0x01, 0xea, 0x97, 0xbf, 0x45, 0x1c, 0xa8, 0x15 };

	uint8_t input_data[ 8 ] = {
		0xc2, 0x0d, 0x08, 0x10, 0x9a, 0x04, 0x04, 0xbf };

	uint8_t expected_output_data[ 8 ] = {
		0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };

	uint8_t output_data[ 8 ];

	libcerror_error_t *error                = NULL;
	libfcrypto_des3_context_t *des3_context = NULL;
	int result                              = 0;

	/* Initialize test
	 */
	result = libfcrypto_des3_context_initialize(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "des3_context",
	 des3_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_des3_context_set_key(
	          des3_context,
	          key,
	          64,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test decrypting a buffer of data
	 */
	result = libfcrypto_des3_crypt(
	          des3_context,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          input_data,
	          8,
	          output_data,
	          8,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = memory_compare(
	          output_data,
	          expected_output_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = libfcrypto_des3_crypt(
	          NULL,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          input_data,
	          8,
	          output_data,
	          8,
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

	result = libfcrypto_des3_crypt(
	          des3_context,
	          -1,
	          input_data,
	          8,
	          output_data,
	          8,
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

	result = libfcrypto_des3_crypt(
	          des3_context,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          NULL,
	          8,
	          output_data,
	          8,
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

	result = libfcrypto_des3_crypt(
	          des3_context,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          input_data,
	          (size_t) SSIZE_MAX + 1,
	          output_data,
	          8,
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

	result = libfcrypto_des3_crypt(
	          des3_context,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          input_data,
	          8,
	          NULL,
	          8,
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

	result = libfcrypto_des3_crypt(
	          des3_context,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          input_data,
	          8,
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

	result = libfcrypto_des3_crypt(
	          des3_context,
	          LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
	          input_data,
	          8,
	          output_data,
	          4,
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
	result = libfcrypto_des3_context_free(
	          &des3_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "des3_context",
	 des3_context );

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
	if( des3_context != NULL )
	{
		libfcrypto_des3_context_free(
		 &des3_context,
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
	 "libfcrypto_des3_context_initialize",
	 fcrypto_test_des3_context_initialize );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_des3_context_free",
	 fcrypto_test_des3_context_free );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_des3_context_set_key",
	 fcrypto_test_des3_context_set_key );

#if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT )

	FCRYPTO_TEST_RUN(
	 "libfcrypto_internal_des3_context_crypt_block",
	 fcrypto_test_internal_des3_context_crypt_block );

#endif /* if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT ) */

	FCRYPTO_TEST_RUN(
	 "libfcrypto_des3_crypt",
	 fcrypto_test_des3_crypt );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

