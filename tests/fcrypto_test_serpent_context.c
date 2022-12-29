/*
 * Library serpent_context type test program
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

/* Tests the libfcrypto_serpent_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_serpent_context_initialize(
     void )
{
	libcerror_error_t *error                      = NULL;
	libfcrypto_serpent_context_t *serpent_context = NULL;
	int result                                    = 0;

#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	int number_of_malloc_fail_tests               = 1;
	int number_of_memset_fail_tests               = 1;
	int test_number                               = 0;
#endif

	/* Test regular cases
	 */
	result = libfcrypto_serpent_context_initialize(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "serpent_context",
	 serpent_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_serpent_context_free(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "serpent_context",
	 serpent_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfcrypto_serpent_context_initialize(
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

	serpent_context = (libfcrypto_serpent_context_t *) 0x12345678UL;

	result = libfcrypto_serpent_context_initialize(
	          &serpent_context,
	          &error );

	serpent_context = NULL;

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
		/* Test libfcrypto_serpent_context_initialize with malloc failing
		 */
		fcrypto_test_malloc_attempts_before_fail = test_number;

		result = libfcrypto_serpent_context_initialize(
		          &serpent_context,
		          &error );

		if( fcrypto_test_malloc_attempts_before_fail != -1 )
		{
			fcrypto_test_malloc_attempts_before_fail = -1;

			if( serpent_context != NULL )
			{
				libfcrypto_serpent_context_free(
				 &serpent_context,
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
			 "serpent_context",
			 serpent_context );

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
		/* Test libfcrypto_serpent_context_initialize with memset failing
		 */
		fcrypto_test_memset_attempts_before_fail = test_number;

		result = libfcrypto_serpent_context_initialize(
		          &serpent_context,
		          &error );

		if( fcrypto_test_memset_attempts_before_fail != -1 )
		{
			fcrypto_test_memset_attempts_before_fail = -1;

			if( serpent_context != NULL )
			{
				libfcrypto_serpent_context_free(
				 &serpent_context,
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
			 "serpent_context",
			 serpent_context );

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
	if( serpent_context != NULL )
	{
		libfcrypto_serpent_context_free(
		 &serpent_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_serpent_context_free function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_serpent_context_free(
     void )
{
#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	libfcrypto_serpent_context_t *serpent_context = NULL;
#endif

	libcerror_error_t *error                      = NULL;
	int result                                    = 0;

	/* Test error cases
	 */
	result = libfcrypto_serpent_context_free(
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
	result = libfcrypto_serpent_context_initialize(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "serpent_context",
	 serpent_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test libfcrypto_serpent_context_free with memset failing
	 */
	fcrypto_test_memset_attempts_before_fail = 0;

	result = libfcrypto_serpent_context_free(
	          &serpent_context,
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
	result = libfcrypto_serpent_context_free(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "serpent_context",
	 serpent_context );

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
	if( serpent_context != NULL )
	{
		libfcrypto_serpent_context_free(
		 &serpent_context,
		 NULL );
	}
#endif
	return( 0 );
}

/* Tests the libfcrypto_serpent_context_set_key function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_serpent_context_set_key(
     void )
{
	uint8_t key[ 16 ] = {
	    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	libcerror_error_t *error                      = NULL;
	libfcrypto_serpent_context_t *serpent_context = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libfcrypto_serpent_context_initialize(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "serpent_context",
	 serpent_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular case
	 */
	result = libfcrypto_serpent_context_set_key(
	          serpent_context,
	          key,
	          128,
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
	result = libfcrypto_serpent_context_set_key(
	          NULL,
	          key,
	          128,
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

	result = libfcrypto_serpent_context_set_key(
	          serpent_context,
	          NULL,
	          128,
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

	result = libfcrypto_serpent_context_set_key(
	          serpent_context,
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
	result = libfcrypto_serpent_context_free(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "serpent_context",
	 serpent_context );

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
	if( serpent_context != NULL )
	{
		libfcrypto_serpent_context_free(
		 &serpent_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_serpent_crypt_ecb function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_serpent_crypt_ecb(
     void )
{
	uint8_t key[ 16 ] = {
		0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	uint8_t input_data[ 48 ];
	uint8_t output_data[ 48 ];

	libcerror_error_t *error                      = NULL;
	libfcrypto_serpent_context_t *serpent_context = NULL;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libfcrypto_serpent_context_initialize(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "serpent_context",
	 serpent_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_serpent_context_set_key(
	          serpent_context,
	          key,
	          128,
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
	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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

	/* Test encrypting a buffer of data
	 */
	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT,
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

	/* Test error cases
	 */
	result = libfcrypto_serpent_crypt_ecb(
	          NULL,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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

	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          -1,
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

	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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

	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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

	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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

	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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

	result = libfcrypto_serpent_crypt_ecb(
	          serpent_context,
	          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
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
	result = libfcrypto_serpent_context_free(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "serpent_context",
	 serpent_context );

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
	if( serpent_context != NULL )
	{
		libfcrypto_serpent_context_free(
		 &serpent_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_serpent_crypt function with a NESSIE test vector
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_serpent_crypt_ecb_with_nessie_test_vector(
     const uint8_t *key, 
     size_t key_size,
     uint8_t *input_data,
     uint8_t *expected_output_data_iterations_1,
     uint8_t *expected_output_data_iterations_100,
     uint8_t *expected_output_data_iterations_1000 )
{
	libcerror_error_t *error                      = NULL;
	libfcrypto_serpent_context_t *serpent_context = NULL;
	int iteration                                 = 0;
	int result                                    = 0;

	/* Initialize test
	 */
	result = libfcrypto_serpent_context_initialize(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "serpent_context",
	 serpent_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_serpent_context_set_key(
	          serpent_context,
	          key,
	          key_size,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test encrypting a buffer of data
	 */
	for( iteration = 1;
	     iteration <= 1000;
	     iteration++ )
	{
		result = libfcrypto_serpent_crypt_ecb(
		          serpent_context,
		          LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT,
		          input_data,
		          16,
		          input_data,
		          16,
		          &error );

		FCRYPTO_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		FCRYPTO_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		if( iteration == 1 )
		{
			result = memory_compare(
			          input_data,
			          expected_output_data_iterations_1,
			          16 );

			FCRYPTO_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 0 );
		}
		else if( iteration == 100 )
		{
			result = memory_compare(
			          input_data,
			          expected_output_data_iterations_100,
			          16 );

			FCRYPTO_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 0 );
		}
	}
	result = memory_compare(
	          input_data,
	          expected_output_data_iterations_1000,
	          16 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test decrypting a buffer of data
	 */
	for( iteration = 999;
	     iteration >= 1;
	     iteration-- )
	{
		result = libfcrypto_serpent_crypt_ecb(
		          serpent_context,
		          LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT,
		          input_data,
		          16,
		          input_data,
		          16,
		          &error );

		FCRYPTO_TEST_ASSERT_EQUAL_INT(
		 "result",
		 result,
		 1 );

		FCRYPTO_TEST_ASSERT_IS_NULL(
		 "error",
		 error );

		if( iteration == 1 )
		{
			result = memory_compare(
			          input_data,
			          expected_output_data_iterations_1,
			          16 );

			FCRYPTO_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 0 );
		}
		else if( iteration == 100 )
		{
			result = memory_compare(
			          input_data,
			          expected_output_data_iterations_100,
			          16 );

			FCRYPTO_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 0 );
		}
	}
	/* Clean up
	 */
	result = libfcrypto_serpent_context_free(
	          &serpent_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "serpent_context",
	 serpent_context );

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
	if( serpent_context != NULL )
	{
		libfcrypto_serpent_context_free(
		 &serpent_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_serpent_crypt function with the NESSIE test vectors for a 128-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_serpent_crypt_ecb_nessie_128bit(
     void )
{
	uint8_t keys[ 2 ][ 16 ] = {
		{ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		{ 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
	};

	uint8_t input_data[ 16 ] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	uint8_t expected_output_data_iterations_1[ 2 ][ 16 ] = {
		{ 0x26, 0x4e, 0x54, 0x81, 0xef, 0xf4, 0x2a, 0x46, 0x06, 0xab, 0xda, 0x06, 0xc0, 0xbf, 0xda, 0x3d },
		{ 0x4a, 0x23, 0x1b, 0x3b, 0xc7, 0x27, 0x99, 0x34, 0x07, 0xac, 0x6e, 0xc8, 0x35, 0x0e, 0x85, 0x24 },
	};

	uint8_t expected_output_data_iterations_100[ 2 ][ 16 ] = {
		{ 0xef, 0xe6, 0xf0, 0x58, 0xd7, 0x4e, 0x35, 0x7a, 0x1c, 0xa9, 0x35, 0xd3, 0x5e, 0x0e, 0x4f, 0x24 },
		{ 0x0d, 0x66, 0xa1, 0x0f, 0x4c, 0xcf, 0xa9, 0x64, 0xd6, 0xbe, 0xb7, 0x4c, 0x19, 0x94, 0x9f, 0xb9 },
	};

	uint8_t expected_output_data_iterations_1000[ 2 ][ 16 ] = {
		{ 0x10, 0x36, 0xff, 0x01, 0x64, 0xe1, 0x92, 0xd2, 0x7a, 0xf3, 0x51, 0x73, 0x41, 0x41, 0x99, 0x4a },
		{ 0xf6, 0x71, 0xfe, 0x66, 0x2e, 0x31, 0x74, 0x5e, 0x6c, 0x41, 0x3e, 0x77, 0x8f, 0x51, 0x5c, 0xdb },
	};

	int result     = 0;
	int test_index = 0;

	for( test_index = 0;
	     test_index < 2;
	     test_index++ )
	{
		memory_set(
		 input_data,
		 0,
		 sizeof( uint8_t ) * 16 );

		result = fcrypto_test_serpent_crypt_ecb_with_nessie_test_vector(
		          keys[ test_index ],
		          128,
		          input_data,
		          expected_output_data_iterations_1[ test_index ],
		          expected_output_data_iterations_100[ test_index ],
		          expected_output_data_iterations_1000[ test_index ] );

		if( result != 1 )
		{
			break;
		}
	}
	return( result );
}

/* TODO implement test vectors
 */

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
	 "libfcrypto_serpent_context_initialize",
	 fcrypto_test_serpent_context_initialize );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_serpent_context_free",
	 fcrypto_test_serpent_context_free );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_serpent_context_set_key",
	 fcrypto_test_serpent_context_set_key );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_serpent_crypt_ecb",
	 fcrypto_test_serpent_crypt_ecb );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_serpent_crypt_ecb with NESSIE test vector and 128-bit key",
	 fcrypto_test_serpent_crypt_ecb_nessie_128bit );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

