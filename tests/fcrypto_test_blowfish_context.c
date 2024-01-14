/*
 * Library blowfish_context type test program
 *
 * Copyright (C) 2017-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include "../libfcrypto/libfcrypto_blowfish_context.h"

/* Tests the libfcrypto_blowfish_context_initialize function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_context_initialize(
     void )
{
	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	int number_of_malloc_fail_tests                 = 1;
	int number_of_memset_fail_tests                 = 1;
	int test_number                                 = 0;
#endif

	/* Test regular cases
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfcrypto_blowfish_context_initialize(
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

	blowfish_context = (libfcrypto_blowfish_context_t *) 0x12345678UL;

	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	blowfish_context = NULL;

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
		/* Test libfcrypto_blowfish_context_initialize with malloc failing
		 */
		fcrypto_test_malloc_attempts_before_fail = test_number;

		result = libfcrypto_blowfish_context_initialize(
		          &blowfish_context,
		          &error );

		if( fcrypto_test_malloc_attempts_before_fail != -1 )
		{
			fcrypto_test_malloc_attempts_before_fail = -1;

			if( blowfish_context != NULL )
			{
				libfcrypto_blowfish_context_free(
				 &blowfish_context,
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
			 "blowfish_context",
			 blowfish_context );

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
		/* Test libfcrypto_blowfish_context_initialize with memset failing
		 */
		fcrypto_test_memset_attempts_before_fail = test_number;

		result = libfcrypto_blowfish_context_initialize(
		          &blowfish_context,
		          &error );

		if( fcrypto_test_memset_attempts_before_fail != -1 )
		{
			fcrypto_test_memset_attempts_before_fail = -1;

			if( blowfish_context != NULL )
			{
				libfcrypto_blowfish_context_free(
				 &blowfish_context,
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
			 "blowfish_context",
			 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_blowfish_context_free function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_context_free(
     void )
{
#if defined( HAVE_FCRYPTO_TEST_MEMORY )
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
#endif

	libcerror_error_t *error                        = NULL;
	int result                                      = 0;

	/* Test error cases
	 */
	result = libfcrypto_blowfish_context_free(
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
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test libfcrypto_blowfish_context_free with memset failing
	 */
	fcrypto_test_memset_attempts_before_fail = 0;

	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
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
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
#endif
	return( 0 );
}

#if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT )

/* Tests the libfcrypto_internal_blowfish_context_encrypt_values function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_context_encrypt_values(
     void )
{
	uint8_t key[ 7 ] = { 'T', 'E', 'S', 'T', 'K', 'E', 'Y' };

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;
	uint32_t value_left                             = 0;
	uint32_t value_right                            = 0;

	/* Initialize test
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
	          key,
	          7 * 8,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test encrypting values
	 */
	value_left  = 1;
	value_right = 2;

	result = libfcrypto_internal_blowfish_context_encrypt_values(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          &value_left,
	          &value_right,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	FCRYPTO_TEST_ASSERT_EQUAL_UINT32(
	 "value_left",
	 value_left,
	 (uint32_t) 0xDF333FD2L );

	FCRYPTO_TEST_ASSERT_EQUAL_UINT32(
	 "value_right",
	 value_right,
	 (uint32_t) 0x30A71BB4L );

	/* Test error cases
	 */
	result = libfcrypto_internal_blowfish_context_encrypt_values(
	          NULL,
	          &value_left,
	          &value_right,
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

	result = libfcrypto_internal_blowfish_context_encrypt_values(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          NULL,
	          &value_right,
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

	result = libfcrypto_internal_blowfish_context_encrypt_values(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          &value_left,
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
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
	return( 0 );
}

#endif /* if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT ) */

/* Tests the libfcrypto_blowfish_context_set_key function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_context_set_key(
     void )
{
	uint8_t key[ 5 ] = { 't', 'e', 's', 't', '1' };

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

	/* Initialize test
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular case
	 */
	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
	          key,
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
	result = libfcrypto_blowfish_context_set_key(
	          NULL,
	          key,
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

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
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

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
	          key,
	          24,
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
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
	return( 0 );
}

#if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT )

/* Tests the libfcrypto_internal_blowfish_context_encrypt_block function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_context_encrypt_block(
     void )
{
	uint8_t key[ 5 ]              = { 't', 'e', 's', 't', '1' };
	uint8_t encrypted_data[ 8 ]   = { 0x11, 'q', 'M', 'c', 0xe0, 'm', 0xd7, 0x9e };
	uint8_t unencrypted_data[ 8 ] = { '1', '2', '3', '4', '5', '6', '7', '8' };

	uint8_t output_data[ 8 ];

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

	/* Initialize test
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
	          key,
	          40,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test encrypting a block
	 */
	result = libfcrypto_internal_blowfish_context_encrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          unencrypted_data,
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
	          encrypted_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = libfcrypto_internal_blowfish_context_encrypt_block(
	          NULL,
	          unencrypted_data,
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

	result = libfcrypto_internal_blowfish_context_encrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
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

	result = libfcrypto_internal_blowfish_context_encrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          unencrypted_data,
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

	result = libfcrypto_internal_blowfish_context_encrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          unencrypted_data,
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

	result = libfcrypto_internal_blowfish_context_encrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          unencrypted_data,
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

	/* Clean up
	 */
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_internal_blowfish_context_decrypt_block function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_context_decrypt_block(
     void )
{
	uint8_t key[ 5 ]              = { 't', 'e', 's', 't', '1' };
	uint8_t encrypted_data[ 8 ]   = { 0x11, 'q', 'M', 'c', 0xe0, 'm', 0xd7, 0x9e };
	uint8_t unencrypted_data[ 8 ] = { '1', '2', '3', '4', '5', '6', '7', '8' };

	uint8_t output_data[ 8 ];

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

	/* Initialize test
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
	          key,
	          40,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test decrypting a block
	 */
	result = libfcrypto_internal_blowfish_context_decrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          encrypted_data,
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
	          unencrypted_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = libfcrypto_internal_blowfish_context_decrypt_block(
	          NULL,
	          encrypted_data,
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

	result = libfcrypto_internal_blowfish_context_decrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
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

	result = libfcrypto_internal_blowfish_context_decrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          encrypted_data,
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

	result = libfcrypto_internal_blowfish_context_decrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          encrypted_data,
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

	result = libfcrypto_internal_blowfish_context_decrypt_block(
	          (libfcrypto_internal_blowfish_context_t *) blowfish_context,
	          encrypted_data,
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

	/* Clean up
	 */
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
	return( 0 );
}

#endif /* if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT ) */

/* Tests the libfcrypto_blowfish_crypt_cbc function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_crypt_cbc(
     void )
{
	uint8_t key[ 16 ] = {
		'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 'a', ' ', 'k', 'e', 'y', '1', '2', '3' };

	uint8_t encrypted_data[ 32 ] = {
		'}', 0x00, 0x99, 0xd2, 0xab, 0x1c, 0xcd, 0x80, 'y', 0xef, 0x0b, 0x0f, 0xf7, '2', 'R', 'p',
		0xbb, '\\', 'h', 0x06, 0xff, 0x07, 0x9a, 0xcf, 'E', '\r', 0x8d, 0x18, 0x90, 0x8e, 0xfe, 0xa3 };

	uint8_t unencrypted_data[ 32 ] = {
		'T', 'h', 'i', 's', ' ', 'i', 's', ' ', 's', 'e', 'c', 'r', 'e', 't', ' ', 'e',
		'n', 'c', 'r', 'y', 'p', 't', 'e', 'd', ' ', 't', 'e', 'x', 't', '!', '!', '!' };

	uint8_t initialization_vector[ 8 ] = { 'T' , 'h' , 'i' , 's' , ' ' , 'I' , 'V' , '!' };

	uint8_t output_data[ 32 ];

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

	/* Initialize test
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
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
	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          8,
	          encrypted_data,
	          32,
	          output_data,
	          32,
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
	          unencrypted_data,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test encrypting a buffer of data
	 */
	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_ENCRYPT,
	          initialization_vector,
	          8,
	          unencrypted_data,
	          32,
	          output_data,
	          32,
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
	          encrypted_data,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = libfcrypto_blowfish_crypt_cbc(
	          NULL,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          8,
	          encrypted_data,
	          32,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          -1,
	          initialization_vector,
	          8,
	          encrypted_data,
	          32,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          NULL,
	          8,
	          encrypted_data,
	          32,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          (size_t) SSIZE_MAX + 1,
	          encrypted_data,
	          32,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          8,
	          NULL,
	          32,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          8,
	          encrypted_data,
	          (size_t) SSIZE_MAX + 1,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          8,
	          encrypted_data,
	          32,
	          NULL,
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

	result = libfcrypto_blowfish_crypt_cbc(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          initialization_vector,
	          8,
	          encrypted_data,
	          32,
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

	/* Clean up
	 */
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfcrypto_blowfish_crypt_ecb function
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_crypt_ecb(
     void )
{
	uint8_t key[ 5 ]              = { 't', 'e', 's', 't', '1' };
	uint8_t encrypted_data[ 8 ]   = { 0x11, 'q', 'M', 'c', 0xe0, 'm', 0xd7, 0x9e };
	uint8_t unencrypted_data[ 8 ] = { '1', '2', '3', '4', '5', '6', '7', '8' };

	uint8_t output_data[ 8 ];

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

	/* Initialize test
	 */
	result = libfcrypto_blowfish_context_initialize(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "blowfish_context",
	 blowfish_context );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_context_set_key(
	          blowfish_context,
	          key,
	          40,
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
	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          encrypted_data,
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
	          unencrypted_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test encrypting a buffer of data
	 */
	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_ENCRYPT,
	          unencrypted_data,
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
	          encrypted_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	/* Test error cases
	 */
	result = libfcrypto_blowfish_crypt_ecb(
	          NULL,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          encrypted_data,
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

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          -1,
	          encrypted_data,
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

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
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

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          encrypted_data,
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

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          encrypted_data,
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

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          encrypted_data,
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

	/* Clean up
	 */
	result = libfcrypto_blowfish_context_free(
	          &blowfish_context,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "blowfish_context",
	 blowfish_context );

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
	if( blowfish_context != NULL )
	{
		libfcrypto_blowfish_context_free(
		 &blowfish_context,
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
	 "libfcrypto_blowfish_context_initialize",
	 fcrypto_test_blowfish_context_initialize );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_blowfish_context_free",
	 fcrypto_test_blowfish_context_free );

#if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT )

	FCRYPTO_TEST_RUN(
	 "libfcrypto_internal_blowfish_context_encrypt_values",
	 fcrypto_test_blowfish_context_encrypt_values );

#endif /* if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT ) */

	FCRYPTO_TEST_RUN(
	 "libfcrypto_blowfish_context_set_key",
	 fcrypto_test_blowfish_context_set_key );

#if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT )

	FCRYPTO_TEST_RUN(
	 "libfcrypto_internal_blowfish_context_encrypt_block",
	 fcrypto_test_blowfish_context_encrypt_block );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_internal_blowfish_context_decrypt_block",
	 fcrypto_test_blowfish_context_decrypt_block );

#endif /* if defined( __GNUC__ ) && !defined( LIBFCRYPTO_DLL_IMPORT ) */

	FCRYPTO_TEST_RUN(
	 "libfcrypto_blowfish_crypt_cbc",
	 fcrypto_test_blowfish_crypt_cbc );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_blowfish_crypt_ecb",
	 fcrypto_test_blowfish_crypt_ecb );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

