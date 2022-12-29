/*
 * Library rc4_context type test program
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

	rc4_context = NULL;

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
	uint8_t *key = (uint8_t *) "test1";

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

	/* Test regular case
	 */
	result = libfcrypto_rc4_context_set_key(
	          rc4_context,
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
	result = libfcrypto_rc4_context_set_key(
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
	uint8_t *key = (uint8_t *) "test1";

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

/* Tests the libfcrypto_rc4_crypt function with a RFC6229 test vector
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
     const uint8_t *key, 
     size_t key_size,
     uint8_t *expected_output_data_offset_0000,
     uint8_t *expected_output_data_offset_00f0,
     uint8_t *expected_output_data_offset_01f0,
     uint8_t *expected_output_data_offset_02f0,
     uint8_t *expected_output_data_offset_03f0,
     uint8_t *expected_output_data_offset_05f0,
     uint8_t *expected_output_data_offset_07f0,
     uint8_t *expected_output_data_offset_0bf0,
     uint8_t *expected_output_data_offset_0ff0 )
{
	uint8_t input_data[ 4112 ];
	uint8_t output_data[ 4112 ];

	libcerror_error_t *error              = NULL;
	libfcrypto_rc4_context_t *rc4_context = NULL;
	int result                            = 0;

	/* Initialize test
	 */
	memory_set(
	 input_data,
	 0,
	 sizeof( uint8_t ) * 4112 );

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

	/* Test de- or encrypting a buffer of data
	 */
	result = libfcrypto_rc4_crypt(
	          rc4_context,
	          input_data,
	          4112,
	          output_data,
	          4112,
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
	          expected_output_data_offset_0000,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x00f0 ] ),
	          expected_output_data_offset_00f0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x01f0 ] ),
	          expected_output_data_offset_01f0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x02f0 ] ),
	          expected_output_data_offset_02f0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x03f0 ] ),
	          expected_output_data_offset_03f0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x05f0 ] ),
	          expected_output_data_offset_05f0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x07f0 ] ),
	          expected_output_data_offset_07f0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x0bf0 ] ),
	          expected_output_data_offset_0bf0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = memory_compare(
	          &( output_data[ 0x0ff0 ] ),
	          expected_output_data_offset_0ff0,
	          32 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

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

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 40-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_40bit(
     void )
{
	uint8_t key[ 5 ] = { 0x01, 0x02, 0x03, 0x04, 0x05 };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0xb2, 0x39, 0x63, 0x05, 0xf0, 0x3d, 0xc0, 0x27, 0xcc, 0xc3, 0x52, 0x4a, 0x0a, 0x11, 0x18, 0xa8,
		0x69, 0x82, 0x94, 0x4f, 0x18, 0xfc, 0x82, 0xd5, 0x89, 0xc4, 0x03, 0xa4, 0x7a, 0x0d, 0x09, 0x19 };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0x28, 0xcb, 0x11, 0x32, 0xc9, 0x6c, 0xe2, 0x86, 0x42, 0x1d, 0xca, 0xad, 0xb8, 0xb6, 0x9e, 0xae,
		0x1c, 0xfc, 0xf6, 0x2b, 0x03, 0xed, 0xdb, 0x64, 0x1d, 0x77, 0xdf, 0xcf, 0x7f, 0x8d, 0x8c, 0x93 };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0x42, 0xb7, 0xd0, 0xcd, 0xd9, 0x18, 0xa8, 0xa3, 0x3d, 0xd5, 0x17, 0x81, 0xc8, 0x1f, 0x40, 0x41,
		0x64, 0x59, 0x84, 0x44, 0x32, 0xa7, 0xda, 0x92, 0x3c, 0xfb, 0x3e, 0xb4, 0x98, 0x06, 0x61, 0xf6 };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0xec, 0x10, 0x32, 0x7b, 0xde, 0x2b, 0xee, 0xfd, 0x18, 0xf9, 0x27, 0x76, 0x80, 0x45, 0x7e, 0x22,
		0xeb, 0x62, 0x63, 0x8d, 0x4f, 0x0b, 0xa1, 0xfe, 0x9f, 0xca, 0x20, 0xe0, 0x5b, 0xf8, 0xff, 0x2b };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0x45, 0x12, 0x90, 0x48, 0xe6, 0xa0, 0xed, 0x0b, 0x56, 0xb4, 0x90, 0x33, 0x8f, 0x07, 0x8d, 0xa5,
		0x30, 0xab, 0xbc, 0xc7, 0xc2, 0x0b, 0x01, 0x60, 0x9f, 0x23, 0xee, 0x2d, 0x5f, 0x6b, 0xb7, 0xdf };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0x32, 0x94, 0xf7, 0x44, 0xd8, 0xf9, 0x79, 0x05, 0x07, 0xe7, 0x0f, 0x62, 0xe5, 0xbb, 0xce, 0xea,
		0xd8, 0x72, 0x9d, 0xb4, 0x18, 0x82, 0x25, 0x9b, 0xee, 0x4f, 0x82, 0x53, 0x25, 0xf5, 0xa1, 0x30 };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0x1e, 0xb1, 0x4a, 0x0c, 0x13, 0xb3, 0xbf, 0x47, 0xfa, 0x2a, 0x0b, 0xa9, 0x3a, 0xd4, 0x5b, 0x8b,
		0xcc, 0x58, 0x2f, 0x8b, 0xa9, 0xf2, 0x65, 0xe2, 0xb1, 0xbe, 0x91, 0x12, 0xe9, 0x75, 0xd2, 0xd7 };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0xf2, 0xe3, 0x0f, 0x9b, 0xd1, 0x02, 0xec, 0xbf, 0x75, 0xaa, 0xad, 0xe9, 0xbc, 0x35, 0xc4, 0x3c,
		0xec, 0x0e, 0x11, 0xc4, 0x79, 0xdc, 0x32, 0x9d, 0xc8, 0xda, 0x79, 0x68, 0xfe, 0x96, 0x56, 0x81 };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0x06, 0x83, 0x26, 0xa2, 0x11, 0x84, 0x16, 0xd2, 0x1f, 0x9d, 0x04, 0xb2, 0xcd, 0x1c, 0xa0, 0x50,
		0xff, 0x25, 0xb5, 0x89, 0x95, 0x99, 0x67, 0x07, 0xe5, 0x1f, 0xbd, 0xf0, 0x8b, 0x34, 0xd8, 0x75 };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          40,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 56-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_56bit(
     void )
{
	uint8_t key[ 7 ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0x29, 0x3f, 0x02, 0xd4, 0x7f, 0x37, 0xc9, 0xb6, 0x33, 0xf2, 0xaf, 0x52, 0x85, 0xfe, 0xb4, 0x6b,
		0xe6, 0x20, 0xf1, 0x39, 0x0d, 0x19, 0xbd, 0x84, 0xe2, 0xe0, 0xfd, 0x75, 0x20, 0x31, 0xaf, 0xc1 };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0x91, 0x4f, 0x02, 0x53, 0x1c, 0x92, 0x18, 0x81, 0x0d, 0xf6, 0x0f, 0x67, 0xe3, 0x38, 0x15, 0x4c,
		0xd0, 0xfd, 0xb5, 0x83, 0x07, 0x3c, 0xe8, 0x5a, 0xb8, 0x39, 0x17, 0x74, 0x0e, 0xc0, 0x11, 0xd5 };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0x75, 0xf8, 0x14, 0x11, 0xe8, 0x71, 0xcf, 0xfa, 0x70, 0xb9, 0x0c, 0x74, 0xc5, 0x92, 0xe4, 0x54,
		0x0b, 0xb8, 0x72, 0x02, 0x93, 0x8d, 0xad, 0x60, 0x9e, 0x87, 0xa5, 0xa1, 0xb0, 0x79, 0xe5, 0xe4 };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0xc2, 0x91, 0x12, 0x46, 0xb6, 0x12, 0xe7, 0xe7, 0xb9, 0x03, 0xdf, 0xed, 0xa1, 0xda, 0xd8, 0x66,
		0x32, 0x82, 0x8f, 0x91, 0x50, 0x2b, 0x62, 0x91, 0x36, 0x8d, 0xe8, 0x08, 0x1d, 0xe3, 0x6f, 0xc2 };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0xf3, 0xb9, 0xa7, 0xe3, 0xb2, 0x97, 0xbf, 0x9a, 0xd8, 0x04, 0x51, 0x2f, 0x90, 0x63, 0xef, 0xf1,
		0x8e, 0xcb, 0x67, 0xa9, 0xba, 0x1f, 0x55, 0xa5, 0xa0, 0x67, 0xe2, 0xb0, 0x26, 0xa3, 0x67, 0x6f };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0xd2, 0xaa, 0x90, 0x2b, 0xd4, 0x2d, 0x0d, 0x7c, 0xfd, 0x34, 0x0c, 0xd4, 0x58, 0x10, 0x52, 0x9f,
		0x78, 0xb2, 0x72, 0xc9, 0x6e, 0x42, 0xea, 0xb4, 0xc6, 0x0b, 0xd9, 0x14, 0xe3, 0x9d, 0x06, 0xe3 };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0xf4, 0x33, 0x2f, 0xd3, 0x1a, 0x07, 0x93, 0x96, 0xee, 0x3c, 0xee, 0x3f, 0x2a, 0x4f, 0xf0, 0x49,
		0x05, 0x45, 0x97, 0x81, 0xd4, 0x1f, 0xda, 0x7f, 0x30, 0xc1, 0xbe, 0x7e, 0x12, 0x46, 0xc6, 0x23 };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0xad, 0xfd, 0x38, 0x68, 0xb8, 0xe5, 0x14, 0x85, 0xd5, 0xe6, 0x10, 0x01, 0x7e, 0x3d, 0xd6, 0x09,
		0xad, 0x26, 0x58, 0x1c, 0x0c, 0x5b, 0xe4, 0x5f, 0x4c, 0xea, 0x01, 0xdb, 0x2f, 0x38, 0x05, 0xd5 };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0xf3, 0x17, 0x2c, 0xef, 0xfc, 0x3b, 0x3d, 0x99, 0x7c, 0x85, 0xcc, 0xd5, 0xaf, 0x1a, 0x95, 0x0c,
		0xe7, 0x4b, 0x0b, 0x97, 0x31, 0x22, 0x7f, 0xd3, 0x7c, 0x0e, 0xc0, 0x8a, 0x47, 0xdd, 0xd8, 0xb8 };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          56,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 64-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_64bit(
     void )
{
	uint8_t key[ 8 ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0x97, 0xab, 0x8a, 0x1b, 0xf0, 0xaf, 0xb9, 0x61, 0x32, 0xf2, 0xf6, 0x72, 0x58, 0xda, 0x15, 0xa8,
		0x82, 0x63, 0xef, 0xdb, 0x45, 0xc4, 0xa1, 0x86, 0x84, 0xef, 0x87, 0xe6, 0xb1, 0x9e, 0x5b, 0x09 };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0x96, 0x36, 0xeb, 0xc9, 0x84, 0x19, 0x26, 0xf4, 0xf7, 0xd1, 0xf3, 0x62, 0xbd, 0xdf, 0x6e, 0x18,
		0xd0, 0xa9, 0x90, 0xff, 0x2c, 0x05, 0xfe, 0xf5, 0xb9, 0x03, 0x73, 0xc9, 0xff, 0x4b, 0x87, 0x0a };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0x73, 0x23, 0x9f, 0x1d, 0xb7, 0xf4, 0x1d, 0x80, 0xb6, 0x43, 0xc0, 0xc5, 0x25, 0x18, 0xec, 0x63,
		0x16, 0x3b, 0x31, 0x99, 0x23, 0xa6, 0xbd, 0xb4, 0x52, 0x7c, 0x62, 0x61, 0x26, 0x70, 0x3c, 0x0f };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0x49, 0xd6, 0xc8, 0xaf, 0x0f, 0x97, 0x14, 0x4a, 0x87, 0xdf, 0x21, 0xd9, 0x14, 0x72, 0xf9, 0x66,
		0x44, 0x17, 0x3a, 0x10, 0x3b, 0x66, 0x16, 0xc5, 0xd5, 0xad, 0x1c, 0xee, 0x40, 0xc8, 0x63, 0xd0 };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0x27, 0x3c, 0x9c, 0x4b, 0x27, 0xf3, 0x22, 0xe4, 0xe7, 0x16, 0xef, 0x53, 0xa4, 0x7d, 0xe7, 0xa4,
		0xc6, 0xd0, 0xe7, 0xb2, 0x26, 0x25, 0x9f, 0xa9, 0x02, 0x34, 0x90, 0xb2, 0x61, 0x67, 0xad, 0x1d };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0x1f, 0xe8, 0x98, 0x67, 0x13, 0xf0, 0x7c, 0x3d, 0x9a, 0xe1, 0xc1, 0x63, 0xff, 0x8c, 0xf9, 0xd3,
		0x83, 0x69, 0xe1, 0xa9, 0x65, 0x61, 0x0b, 0xe8, 0x87, 0xfb, 0xd0, 0xc7, 0x91, 0x62, 0xaa, 0xfb };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0x0a, 0x01, 0x27, 0xab, 0xb4, 0x44, 0x84, 0xb9, 0xfb, 0xef, 0x5a, 0xbc, 0xae, 0x1b, 0x57, 0x9f,
		0xc2, 0xcd, 0xad, 0xc6, 0x40, 0x2e, 0x8e, 0xe8, 0x66, 0xe1, 0xf3, 0x7b, 0xdb, 0x47, 0xe4, 0x2c };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0x26, 0xb5, 0x1e, 0xa3, 0x7d, 0xf8, 0xe1, 0xd6, 0xf7, 0x6f, 0xc3, 0xb6, 0x6a, 0x74, 0x29, 0xb3,
		0xbc, 0x76, 0x83, 0x20, 0x5d, 0x4f, 0x44, 0x3d, 0xc1, 0xf2, 0x9d, 0xda, 0x33, 0x15, 0xc8, 0x7b };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0xd5, 0xfa, 0x5a, 0x34, 0x69, 0xd2, 0x9a, 0xaa, 0xf8, 0x3d, 0x23, 0x58, 0x9d, 0xb8, 0xc8, 0x5b,
		0x3f, 0xb4, 0x6e, 0x2c, 0x8f, 0x0f, 0x06, 0x8e, 0xdc, 0xe8, 0xcd, 0xcd, 0x7d, 0xfc, 0x58, 0x62 };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          64,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 80-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_80bit(
     void )
{
	uint8_t key[ 10 ] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0xed, 0xe3, 0xb0, 0x46, 0x43, 0xe5, 0x86, 0xcc, 0x90, 0x7d, 0xc2, 0x18, 0x51, 0x70, 0x99, 0x02,
		0x03, 0x51, 0x6b, 0xa7, 0x8f, 0x41, 0x3b, 0xeb, 0x22, 0x3a, 0xa5, 0xd4, 0xd2, 0xdf, 0x67, 0x11 };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0x3c, 0xfd, 0x6c, 0xb5, 0x8e, 0xe0, 0xfd, 0xde, 0x64, 0x01, 0x76, 0xad, 0x00, 0x00, 0x04, 0x4d,
		0x48, 0x53, 0x2b, 0x21, 0xfb, 0x60, 0x79, 0xc9, 0x11, 0x4c, 0x0f, 0xfd, 0x9c, 0x04, 0xa1, 0xad };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0x3e, 0x8c, 0xea, 0x98, 0x01, 0x71, 0x09, 0x97, 0x90, 0x84, 0xb1, 0xef, 0x92, 0xf9, 0x9d, 0x86,
		0xe2, 0x0f, 0xb4, 0x9b, 0xdb, 0x33, 0x7e, 0xe4, 0x8b, 0x8d, 0x8d, 0xc0, 0xf4, 0xaf, 0xef, 0xfe };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0x5c, 0x25, 0x21, 0xea, 0xcd, 0x79, 0x66, 0xf1, 0x5e, 0x05, 0x65, 0x44, 0xbe, 0xa0, 0xd3, 0x15,
		0xe0, 0x67, 0xa7, 0x03, 0x19, 0x31, 0xa2, 0x46, 0xa6, 0xc3, 0x87, 0x5d, 0x2f, 0x67, 0x8a, 0xcb };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0xa6, 0x4f, 0x70, 0xaf, 0x88, 0xae, 0x56, 0xb6, 0xf8, 0x75, 0x81, 0xc0, 0xe2, 0x3e, 0x6b, 0x08,
		0xf4, 0x49, 0x03, 0x1d, 0xe3, 0x12, 0x81, 0x4e, 0xc6, 0xf3, 0x19, 0x29, 0x1f, 0x4a, 0x05, 0x16 };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0xbd, 0xae, 0x85, 0x92, 0x4b, 0x3c, 0xb1, 0xd0, 0xa2, 0xe3, 0x3a, 0x30, 0xc6, 0xd7, 0x95, 0x99,
		0x8a, 0x0f, 0xed, 0xdb, 0xac, 0x86, 0x5a, 0x09, 0xbc, 0xd1, 0x27, 0xfb, 0x56, 0x2e, 0xd6, 0x0a };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0xb5, 0x5a, 0x0a, 0x5b, 0x51, 0xa1, 0x2a, 0x8b, 0xe3, 0x48, 0x99, 0xc3, 0xe0, 0x47, 0x51, 0x1a,
		0xd9, 0xa0, 0x9c, 0xea, 0x3c, 0xe7, 0x5f, 0xe3, 0x96, 0x98, 0x07, 0x03, 0x17, 0xa7, 0x13, 0x39 };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0x55, 0x22, 0x25, 0xed, 0x11, 0x77, 0xf4, 0x45, 0x84, 0xac, 0x8c, 0xfa, 0x6c, 0x4e, 0xb5, 0xfc,
		0x7e, 0x82, 0xcb, 0xab, 0xfc, 0x95, 0x38, 0x1b, 0x08, 0x09, 0x98, 0x44, 0x21, 0x29, 0xc2, 0xf8 };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0x1f, 0x13, 0x5e, 0xd1, 0x4c, 0xe6, 0x0a, 0x91, 0x36, 0x9d, 0x23, 0x22, 0xbe, 0xf2, 0x5e, 0x3c,
		0x08, 0xb6, 0xbe, 0x45, 0x12, 0x4a, 0x43, 0xe2, 0xeb, 0x77, 0x95, 0x3f, 0x84, 0xdc, 0x85, 0x53 };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          80,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 128-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_128bit(
     void )
{
	uint8_t key[ 16 ] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0x9a, 0xc7, 0xcc, 0x9a, 0x60, 0x9d, 0x1e, 0xf7, 0xb2, 0x93, 0x28, 0x99, 0xcd, 0xe4, 0x1b, 0x97,
		0x52, 0x48, 0xc4, 0x95, 0x90, 0x14, 0x12, 0x6a, 0x6e, 0x8a, 0x84, 0xf1, 0x1d, 0x1a, 0x9e, 0x1c };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0x06, 0x59, 0x02, 0xe4, 0xb6, 0x20, 0xf6, 0xcc, 0x36, 0xc8, 0x58, 0x9f, 0x66, 0x43, 0x2f, 0x2b,
		0xd3, 0x9d, 0x56, 0x6b, 0xc6, 0xbc, 0xe3, 0x01, 0x07, 0x68, 0x15, 0x15, 0x49, 0xf3, 0x87, 0x3f };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0xb6, 0xd1, 0xe6, 0xc4, 0xa5, 0xe4, 0x77, 0x1c, 0xad, 0x79, 0x53, 0x8d, 0xf2, 0x95, 0xfb, 0x11,
		0xc6, 0x8c, 0x1d, 0x5c, 0x55, 0x9a, 0x97, 0x41, 0x23, 0xdf, 0x1d, 0xbc, 0x52, 0xa4, 0x3b, 0x89 };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0xc5, 0xec, 0xf8, 0x8d, 0xe8, 0x97, 0xfd, 0x57, 0xfe, 0xd3, 0x01, 0x70, 0x1b, 0x82, 0xa2, 0x59,
		0xec, 0xcb, 0xe1, 0x3d, 0xe1, 0xfc, 0xc9, 0x1c, 0x11, 0xa0, 0xb2, 0x6c, 0x0b, 0xc8, 0xfa, 0x4d };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0xe7, 0xa7, 0x25, 0x74, 0xf8, 0x78, 0x2a, 0xe2, 0x6a, 0xab, 0xcf, 0x9e, 0xbc, 0xd6, 0x60, 0x65,
		0xbd, 0xf0, 0x32, 0x4e, 0x60, 0x83, 0xdc, 0xc6, 0xd3, 0xce, 0xdd, 0x3c, 0xa8, 0xc5, 0x3c, 0x16 };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0xb4, 0x01, 0x10, 0xc4, 0x19, 0x0b, 0x56, 0x22, 0xa9, 0x61, 0x16, 0xb0, 0x01, 0x7e, 0xd2, 0x97,
		0xff, 0xa0, 0xb5, 0x14, 0x64, 0x7e, 0xc0, 0x4f, 0x63, 0x06, 0xb8, 0x92, 0xae, 0x66, 0x11, 0x81 };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0xd0, 0x3d, 0x1b, 0xc0, 0x3c, 0xd3, 0x3d, 0x70, 0xdf, 0xf9, 0xfa, 0x5d, 0x71, 0x96, 0x3e, 0xbd,
		0x8a, 0x44, 0x12, 0x64, 0x11, 0xea, 0xa7, 0x8b, 0xd5, 0x1e, 0x8d, 0x87, 0xa8, 0x87, 0x9b, 0xf5 };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0xfa, 0xbe, 0xb7, 0x60, 0x28, 0xad, 0xe2, 0xd0, 0xe4, 0x87, 0x22, 0xe4, 0x6c, 0x46, 0x15, 0xa3,
		0xc0, 0x5d, 0x88, 0xab, 0xd5, 0x03, 0x57, 0xf9, 0x35, 0xa6, 0x3c, 0x59, 0xee, 0x53, 0x76, 0x23 };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0xff, 0x38, 0x26, 0x5c, 0x16, 0x42, 0xc1, 0xab, 0xe8, 0xd3, 0xc2, 0xfe, 0x5e, 0x57, 0x2b, 0xf8,
		0xa3, 0x6a, 0x4c, 0x30, 0x1a, 0xe8, 0xac, 0x13, 0x61, 0x0c, 0xcb, 0xc1, 0x22, 0x56, 0xca, 0xcc };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          128,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 192-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_192bit(
     void )
{
	uint8_t key[ 24 ] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0x05, 0x95, 0xe5, 0x7f, 0xe5, 0xf0, 0xbb, 0x3c, 0x70, 0x6e, 0xda, 0xc8, 0xa4, 0xb2, 0xdb, 0x11,
		0xdf, 0xde, 0x31, 0x34, 0x4a, 0x1a, 0xf7, 0x69, 0xc7, 0x4f, 0x07, 0x0a, 0xee, 0x9e, 0x23, 0x26 };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0xb0, 0x6b, 0x9b, 0x1e, 0x19, 0x5d, 0x13, 0xd8, 0xf4, 0xa7, 0x99, 0x5c, 0x45, 0x53, 0xac, 0x05,
		0x6b, 0xd2, 0x37, 0x8e, 0xc3, 0x41, 0xc9, 0xa4, 0x2f, 0x37, 0xba, 0x79, 0xf8, 0x8a, 0x32, 0xff };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0xe7, 0x0b, 0xce, 0x1d, 0xf7, 0x64, 0x5a, 0xdb, 0x5d, 0x2c, 0x41, 0x30, 0x21, 0x5c, 0x35, 0x22,
		0x9a, 0x57, 0x30, 0xc7, 0xfc, 0xb4, 0xc9, 0xaf, 0x51, 0xff, 0xda, 0x89, 0xc7, 0xf1, 0xad, 0x22 };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0x04, 0x85, 0x05, 0x5f, 0xd4, 0xf6, 0xf0, 0xd9, 0x63, 0xef, 0x5a, 0xb9, 0xa5, 0x47, 0x69, 0x82,
		0x59, 0x1f, 0xc6, 0x6b, 0xcd, 0xa1, 0x0e, 0x45, 0x2b, 0x03, 0xd4, 0x55, 0x1f, 0x6b, 0x62, 0xac };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0x27, 0x53, 0xcc, 0x83, 0x98, 0x8a, 0xfa, 0x3e, 0x16, 0x88, 0xa1, 0xd3, 0xb4, 0x2c, 0x9a, 0x02,
		0x93, 0x61, 0x0d, 0x52, 0x3d, 0x1d, 0x3f, 0x00, 0x62, 0xb3, 0xc2, 0xa3, 0xbb, 0xc7, 0xc7, 0xf0 };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0x96, 0xc2, 0x48, 0x61, 0x0a, 0xad, 0xed, 0xfe, 0xaf, 0x89, 0x78, 0xc0, 0x3d, 0xe8, 0x20, 0x5a,
		0x0e, 0x31, 0x7b, 0x3d, 0x1c, 0x73, 0xb9, 0xe9, 0xa4, 0x68, 0x8f, 0x29, 0x6d, 0x13, 0x3a, 0x19 };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0xbd, 0xf0, 0xe6, 0xc3, 0xcc, 0xa5, 0xb5, 0xb9, 0xd5, 0x33, 0xb6, 0x9c, 0x56, 0xad, 0xa1, 0x20,
		0x88, 0xa2, 0x18, 0xb6, 0xe2, 0xec, 0xe1, 0xe6, 0x24, 0x6d, 0x44, 0xc7, 0x59, 0xd1, 0x9b, 0x10 };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0x68, 0x66, 0x39, 0x7e, 0x95, 0xc1, 0x40, 0x53, 0x4f, 0x94, 0x26, 0x34, 0x21, 0x00, 0x6e, 0x40,
		0x32, 0xcb, 0x0a, 0x1e, 0x95, 0x42, 0xc6, 0xb3, 0xb8, 0xb3, 0x98, 0xab, 0xc3, 0xb0, 0xf1, 0xd5 };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0x29, 0xa0, 0xb8, 0xae, 0xd5, 0x4a, 0x13, 0x23, 0x24, 0xc6, 0x2e, 0x42, 0x3f, 0x54, 0xb4, 0xc8,
		0x3c, 0xb0, 0xf3, 0xb5, 0x02, 0x0a, 0x98, 0xb8, 0x2a, 0xf9, 0xfe, 0x15, 0x44, 0x84, 0xa1, 0x68 };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          192,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* Tests the libfcrypto_rc4_crypt function with the RFC6229 test vector for a 256-bit key
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_rc4_crypt_rfc6229_256bit(
     void )
{
	uint8_t key[ 32 ] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };

	uint8_t expected_output_data_offset_0000[ 32 ] = {
		0xea, 0xa6, 0xbd, 0x25, 0x88, 0x0b, 0xf9, 0x3d, 0x3f, 0x5d, 0x1e, 0x4c, 0xa2, 0x61, 0x1d, 0x91,
		0xcf, 0xa4, 0x5c, 0x9f, 0x7e, 0x71, 0x4b, 0x54, 0xbd, 0xfa, 0x80, 0x02, 0x7c, 0xb1, 0x43, 0x80 };

	uint8_t expected_output_data_offset_00f0[ 32 ] = {
		0x11, 0x4a, 0xe3, 0x44, 0xde, 0xd7, 0x1b, 0x35, 0xf2, 0xe6, 0x0f, 0xeb, 0xad, 0x72, 0x7f, 0xd8,
		0x02, 0xe1, 0xe7, 0x05, 0x6b, 0x0f, 0x62, 0x39, 0x00, 0x49, 0x64, 0x22, 0x94, 0x3e, 0x97, 0xb6 };

	uint8_t expected_output_data_offset_01f0[ 32 ] = {
		0x91, 0xcb, 0x93, 0xc7, 0x87, 0x96, 0x4e, 0x10, 0xd9, 0x52, 0x7d, 0x99, 0x9c, 0x6f, 0x93, 0x6b,
		0x49, 0xb1, 0x8b, 0x42, 0xf8, 0xe8, 0x36, 0x7c, 0xbe, 0xb5, 0xef, 0x10, 0x4b, 0xa1, 0xc7, 0xcd };

	uint8_t expected_output_data_offset_02f0[ 32 ] = {
		0x87, 0x08, 0x4b, 0x3b, 0xa7, 0x00, 0xba, 0xde, 0x95, 0x56, 0x10, 0x67, 0x27, 0x45, 0xb3, 0x74,
		0xe7, 0xa7, 0xb9, 0xe9, 0xec, 0x54, 0x0d, 0x5f, 0xf4, 0x3b, 0xdb, 0x12, 0x79, 0x2d, 0x1b, 0x35 };

	uint8_t expected_output_data_offset_03f0[ 32 ] = {
		0xc7, 0x99, 0xb5, 0x96, 0x73, 0x8f, 0x6b, 0x01, 0x8c, 0x76, 0xc7, 0x4b, 0x17, 0x59, 0xbd, 0x90,
		0x7f, 0xec, 0x5b, 0xfd, 0x9f, 0x9b, 0x89, 0xce, 0x65, 0x48, 0x30, 0x90, 0x92, 0xd7, 0xe9, 0x58 };

	uint8_t expected_output_data_offset_05f0[ 32 ] = {
		0x40, 0xf2, 0x50, 0xb2, 0x6d, 0x1f, 0x09, 0x6a, 0x4a, 0xfd, 0x4c, 0x34, 0x0a, 0x58, 0x88, 0x15,
		0x3e, 0x34, 0x13, 0x5c, 0x79, 0xdb, 0x01, 0x02, 0x00, 0x76, 0x76, 0x51, 0xcf, 0x26, 0x30, 0x73 };

	uint8_t expected_output_data_offset_07f0[ 32 ] = {
		0xf6, 0x56, 0xab, 0xcc, 0xf8, 0x8d, 0xd8, 0x27, 0x02, 0x7b, 0x2c, 0xe9, 0x17, 0xd4, 0x64, 0xec,
		0x18, 0xb6, 0x25, 0x03, 0xbf, 0xbc, 0x07, 0x7f, 0xba, 0xbb, 0x98, 0xf2, 0x0d, 0x98, 0xab, 0x34 };

	uint8_t expected_output_data_offset_0bf0[ 32 ] = {
		0x8a, 0xed, 0x95, 0xee, 0x5b, 0x0d, 0xcb, 0xfb, 0xef, 0x4e, 0xb2, 0x1d, 0x3a, 0x3f, 0x52, 0xf9,
		0x62, 0x5a, 0x1a, 0xb0, 0x0e, 0xe3, 0x9a, 0x53, 0x27, 0x34, 0x6b, 0xdd, 0xb0, 0x1a, 0x9c, 0x18 };

	uint8_t expected_output_data_offset_0ff0[ 32 ] = {
		0xa1, 0x3a, 0x7c, 0x79, 0xc7, 0xe1, 0x19, 0xb5, 0xab, 0x02, 0x96, 0xab, 0x28, 0xc3, 0x00, 0xb9,
		0xf3, 0xe4, 0xc0, 0xa2, 0xe0, 0x2d, 0x1d, 0x01, 0xf7, 0xf0, 0xa7, 0x46, 0x18, 0xaf, 0x2b, 0x48 };

	int result = 0;

	result = fcrypto_test_rc4_crypt_with_rfc6229_test_vector(
	          key,
	          256,
	          expected_output_data_offset_0000,
	          expected_output_data_offset_00f0,
	          expected_output_data_offset_01f0,
	          expected_output_data_offset_02f0,
	          expected_output_data_offset_03f0,
	          expected_output_data_offset_05f0,
	          expected_output_data_offset_07f0,
	          expected_output_data_offset_0bf0,
	          expected_output_data_offset_0ff0 );

	return( result );
}

/* TODO implement test vectors

 Key length: 40 bits.
 key: 0x833222772a

 DEC    0 HEX    0:  80 ad 97 bd  c9 73 df 8a   2e 87 9e 92  a4 97 ef da
 DEC   16 HEX   10:  20 f0 60 c2  f2 e5 12 65   01 d3 d4 fe  a1 0d 5f c0
 DEC  240 HEX   f0:  fa a1 48 e9  90 46 18 1f   ec 6b 20 85  f3 b2 0e d9
 DEC  256 HEX  100:  f0 da f5 ba  b3 d5 96 83   98 57 84 6f  73 fb fe 5a
 DEC  496 HEX  1f0:  1c 7e 2f c4  63 92 32 fe   29 75 84 b2  96 99 6b c8
 DEC  512 HEX  200:  3d b9 b2 49  40 6c c8 ed   ff ac 55 cc  d3 22 ba 12
 DEC  752 HEX  2f0:  e4 f9 f7 e0  06 61 54 bb   d1 25 b7 45  56 9b c8 97
 DEC  768 HEX  300:  75 d5 ef 26  2b 44 c4 1a   9c f6 3a e1  45 68 e1 b9
 DEC 1008 HEX  3f0:  6d a4 53 db  f8 1e 82 33   4a 3d 88 66  cb 50 a1 e3
 DEC 1024 HEX  400:  78 28 d0 74  11 9c ab 5c   22 b2 94 d7  a9 bf a0 bb
 DEC 1520 HEX  5f0:  ad b8 9c ea  9a 15 fb e6   17 29 5b d0  4b 8c a0 5c
 DEC 1536 HEX  600:  62 51 d8 7f  d4 aa ae 9a   7e 4a d5 c2  17 d3 f3 00
 DEC 2032 HEX  7f0:  e7 11 9b d6  dd 9b 22 af   e8 f8 95 85  43 28 81 e2
 DEC 2048 HEX  800:  78 5b 60 fd  7e c4 e9 fc   b6 54 5f 35  0d 66 0f ab
 DEC 3056 HEX  bf0:  af ec c0 37  fd b7 b0 83   8e b3 d7 0b  cd 26 83 82
 DEC 3072 HEX  c00:  db c1 a7 b4  9d 57 35 8c   c9 fa 6d 61  d7 3b 7c f0
 DEC 4080 HEX  ff0:  63 49 d1 26  a3 7a fc ba   89 79 4f 98  04 91 4f dc
 DEC 4096 HEX 1000:  bf 42 c3 01  8c 2f 7c 66   bf de 52 49  75 76 81 15

 Key length: 56 bits.
 key: 0x1910833222772a

 DEC    0 HEX    0:  bc 92 22 db  d3 27 4d 8f   c6 6d 14 cc  bd a6 69 0b
 DEC   16 HEX   10:  7a e6 27 41  0c 9a 2b e6   93 df 5b b7  48 5a 63 e3
 DEC  240 HEX   f0:  3f 09 31 aa  03 de fb 30   0f 06 01 03  82 6f 2a 64
 DEC  256 HEX  100:  be aa 9e c8  d5 9b b6 81   29 f3 02 7c  96 36 11 81
 DEC  496 HEX  1f0:  74 e0 4d b4  6d 28 64 8d   7d ee 8a 00  64 b0 6c fe
 DEC  512 HEX  200:  9b 5e 81 c6  2f e0 23 c5   5b e4 2f 87  bb f9 32 b8
 DEC  752 HEX  2f0:  ce 17 8f c1  82 6e fe cb   c1 82 f5 79  99 a4 61 40
 DEC  768 HEX  300:  8b df 55 cd  55 06 1c 06   db a6 be 11  de 4a 57 8a
 DEC 1008 HEX  3f0:  62 6f 5f 4d  ce 65 25 01   f3 08 7d 39  c9 2c c3 49
 DEC 1024 HEX  400:  42 da ac 6a  8f 9a b9 a7   fd 13 7c 60  37 82 56 82
 DEC 1520 HEX  5f0:  cc 03 fd b7  91 92 a2 07   31 2f 53 f5  d4 dc 33 d9
 DEC 1536 HEX  600:  f7 0f 14 12  2a 1c 98 a3   15 5d 28 b8  a0 a8 a4 1d
 DEC 2032 HEX  7f0:  2a 3a 30 7a  b2 70 8a 9c   00 fe 0b 42  f9 c2 d6 a1
 DEC 2048 HEX  800:  86 26 17 62  7d 22 61 ea   b0 b1 24 65  97 ca 0a e9
 DEC 3056 HEX  bf0:  55 f8 77 ce  4f 2e 1d db   bf 8e 13 e2  cd e0 fd c8
 DEC 3072 HEX  c00:  1b 15 56 cb  93 5f 17 33   37 70 5f bb  5d 50 1f c1
 DEC 4080 HEX  ff0:  ec d0 e9 66  02 be 7f 8d   50 92 81 6c  cc f2 c2 e9
 DEC 4096 HEX 1000:  02 78 81 fa  b4 99 3a 1c   26 20 24 a9  4f ff 3f 61

 Key length: 64 bits.
 key: 0x641910833222772a

 DEC    0 HEX    0:  bb f6 09 de  94 13 17 2d   07 66 0c b6  80 71 69 26
 DEC   16 HEX   10:  46 10 1a 6d  ab 43 11 5d   6c 52 2b 4f  e9 36 04 a9
 DEC  240 HEX   f0:  cb e1 ff f2  1c 96 f3 ee   f6 1e 8f e0  54 2c bd f0
 DEC  256 HEX  100:  34 79 38 bf  fa 40 09 c5   12 cf b4 03  4b 0d d1 a7
 DEC  496 HEX  1f0:  78 67 a7 86  d0 0a 71 47   90 4d 76 dd  f1 e5 20 e3
 DEC  512 HEX  200:  8d 3e 9e 1c  ae fc cc b3   fb f8 d1 8f  64 12 0b 32
 DEC  752 HEX  2f0:  94 23 37 f8  fd 76 f0 fa   e8 c5 2d 79  54 81 06 72
 DEC  768 HEX  300:  b8 54 8c 10  f5 16 67 f6   e6 0e 18 2f  a1 9b 30 f7
 DEC 1008 HEX  3f0:  02 11 c7 c6  19 0c 9e fd   12 37 c3 4c  8f 2e 06 c4
 DEC 1024 HEX  400:  bd a6 4f 65  27 6d 2a ac   b8 f9 02 12  20 3a 80 8e
 DEC 1520 HEX  5f0:  bd 38 20 f7  32 ff b5 3e   c1 93 e7 9d  33 e2 7c 73
 DEC 1536 HEX  600:  d0 16 86 16  86 19 07 d4   82 e3 6c da  c8 cf 57 49
 DEC 2032 HEX  7f0:  97 b0 f0 f2  24 b2 d2 31   71 14 80 8f  b0 3a f7 a0
 DEC 2048 HEX  800:  e5 96 16 e4  69 78 79 39   a0 63 ce ea  9a f9 56 d1
 DEC 3056 HEX  bf0:  c4 7e 0d c1  66 09 19 c1   11 01 20 8f  9e 69 aa 1f
 DEC 3072 HEX  c00:  5a e4 f1 28  96 b8 37 9a   2a ad 89 b5  b5 53 d6 b0
 DEC 4080 HEX  ff0:  6b 6b 09 8d  0c 29 3b c2   99 3d 80 bf  05 18 b6 d9
 DEC 4096 HEX 1000:  81 70 cc 3c  cd 92 a6 98   62 1b 93 9d  d3 8f e7 b9

 Key length: 80 bits.
 key: 0x8b37641910833222772a

 DEC    0 HEX    0:  ab 65 c2 6e  dd b2 87 60   0d b2 fd a1  0d 1e 60 5c
 DEC   16 HEX   10:  bb 75 90 10  c2 96 58 f2   c7 2d 93 a2  d1 6d 29 30
 DEC  240 HEX   f0:  b9 01 e8 03  6e d1 c3 83   cd 3c 4c 4d  d0 a6 ab 05
 DEC  256 HEX  100:  3d 25 ce 49  22 92 4c 55   f0 64 94 33  53 d7 8a 6c
 DEC  496 HEX  1f0:  12 c1 aa 44  bb f8 7e 75   e6 11 f6 9b  2c 38 f4 9b
 DEC  512 HEX  200:  28 f2 b3 43  4b 65 c0 98   77 47 00 44  c6 ea 17 0d
 DEC  752 HEX  2f0:  bd 9e f8 22  de 52 88 19   61 34 cf 8a  f7 83 93 04
 DEC  768 HEX  300:  67 55 9c 23  f0 52 15 84   70 a2 96 f7  25 73 5a 32
 DEC 1008 HEX  3f0:  8b ab 26 fb  c2 c1 2b 0f   13 e2 ab 18  5e ab f2 41
 DEC 1024 HEX  400:  31 18 5a 6d  69 6f 0c fa   9b 42 80 8b  38 e1 32 a2
 DEC 1520 HEX  5f0:  56 4d 3d ae  18 3c 52 34   c8 af 1e 51  06 1c 44 b5
 DEC 1536 HEX  600:  3c 07 78 a7  b5 f7 2d 3c   23 a3 13 5c  7d 67 b9 f4
 DEC 2032 HEX  7f0:  f3 43 69 89  0f cf 16 fb   51 7d ca ae  44 63 b2 dd
 DEC 2048 HEX  800:  02 f3 1c 81  e8 20 07 31   b8 99 b0 28  e7 91 bf a7
 DEC 3056 HEX  bf0:  72 da 64 62  83 22 8c 14   30 08 53 70  17 95 61 6f
 DEC 3072 HEX  c00:  4e 0a 8c 6f  79 34 a7 88   e2 26 5e 81  d6 d0 c8 f4
 DEC 4080 HEX  ff0:  43 8d d5 ea  fe a0 11 1b   6f 36 b4 b9  38 da 2a 68
 DEC 4096 HEX 1000:  5f 6b fc 73  81 58 74 d9   71 00 f0 86  97 93 57 d8

 Key length: 128 bits.
 key: 0xebb46227c6cc8b37641910833222772a

 DEC    0 HEX    0:  72 0c 94 b6  3e df 44 e1   31 d9 50 ca  21 1a 5a 30
 DEC   16 HEX   10:  c3 66 fd ea  cf 9c a8 04   36 be 7c 35  84 24 d2 0b
 DEC  240 HEX   f0:  b3 39 4a 40  aa bf 75 cb   a4 22 82 ef  25 a0 05 9f
 DEC  256 HEX  100:  48 47 d8 1d  a4 94 2d bc   24 9d ef c4  8c 92 2b 9f
 DEC  496 HEX  1f0:  08 12 8c 46  9f 27 53 42   ad da 20 2b  2b 58 da 95
 DEC  512 HEX  200:  97 0d ac ef  40 ad 98 72   3b ac 5d 69  55 b8 17 61
 DEC  752 HEX  2f0:  3c b8 99 93  b0 7b 0c ed   93 de 13 d2  a1 10 13 ac
 DEC  768 HEX  300:  ef 2d 67 6f  15 45 c2 c1   3d c6 80 a0  2f 4a db fe
 DEC 1008 HEX  3f0:  b6 05 95 51  4f 24 bc 9f   e5 22 a6 ca  d7 39 36 44
 DEC 1024 HEX  400:  b5 15 a8 c5  01 17 54 f5   90 03 05 8b  db 81 51 4e
 DEC 1520 HEX  5f0:  3c 70 04 7e  8c bc 03 8e   3b 98 20 db  60 1d a4 95
 DEC 1536 HEX  600:  11 75 da 6e  e7 56 de 46   a5 3e 2b 07  56 60 b7 70
 DEC 2032 HEX  7f0:  00 a5 42 bb  a0 21 11 cc   2c 65 b3 8e  bd ba 58 7e
 DEC 2048 HEX  800:  58 65 fd bb  5b 48 06 41   04 e8 30 b3  80 f2 ae de
 DEC 3056 HEX  bf0:  34 b2 1a d2  ad 44 e9 99   db 2d 7f 08  63 f0 d9 b6
 DEC 3072 HEX  c00:  84 a9 21 8f  c3 6e 8a 5f   2c cf be ae  53 a2 7d 25
 DEC 4080 HEX  ff0:  a2 22 1a 11  b8 33 cc b4   98 a5 95 40  f0 54 5f 4a
 DEC 4096 HEX 1000:  5b be b4 78  7d 59 e5 37   3f db ea 6c  6f 75 c2 9b

 Key length: 192 bits.
 key: 0xc109163908ebe51debb46227c6cc8b37641910833222772a

 DEC    0 HEX    0:  54 b6 4e 6b  5a 20 b5 e2   ec 84 59 3d  c7 98 9d a7
 DEC   16 HEX   10:  c1 35 ee e2  37 a8 54 65   ff 97 dc 03  92 4f 45 ce
 DEC  240 HEX   f0:  cf cc 92 2f  b4 a1 4a b4   5d 61 75 aa  bb f2 d2 01
 DEC  256 HEX  100:  83 7b 87 e2  a4 46 ad 0e   f7 98 ac d0  2b 94 12 4f
 DEC  496 HEX  1f0:  17 a6 db d6  64 92 6a 06   36 b3 f4 c3  7a 4f 46 94
 DEC  512 HEX  200:  4a 5f 9f 26  ae ee d4 d4   a2 5f 63 2d  30 52 33 d9
 DEC  752 HEX  2f0:  80 a3 d0 1e  f0 0c 8e 9a   42 09 c1 7f  4e eb 35 8c
 DEC  768 HEX  300:  d1 5e 7d 5f  fa aa bc 02   07 bf 20 0a  11 77 93 a2
 DEC 1008 HEX  3f0:  34 96 82 bf  58 8e aa 52   d0 aa 15 60  34 6a ea fa
 DEC 1024 HEX  400:  f5 85 4c db  76 c8 89 e3   ad 63 35 4e  5f 72 75 e3
 DEC 1520 HEX  5f0:  53 2c 7c ec  cb 39 df 32   36 31 84 05  a4 b1 27 9c
 DEC 1536 HEX  600:  ba ef e6 d9  ce b6 51 84   22 60 e0 d1  e0 5e 3b 90
 DEC 2032 HEX  7f0:  e8 2d 8c 6d  b5 4e 3c 63   3f 58 1c 95  2b a0 42 07
 DEC 2048 HEX  800:  4b 16 e5 0a  bd 38 1b d7   09 00 a9 cd  9a 62 cb 23
 DEC 3056 HEX  bf0:  36 82 ee 33  bd 14 8b d9   f5 86 56 cd  8f 30 d9 fb
 DEC 3072 HEX  c00:  1e 5a 0b 84  75 04 5d 9b   20 b2 62 86  24 ed fd 9e
 DEC 4080 HEX  ff0:  63 ed d6 84  fb 82 62 82   fe 52 8f 9c  0e 92 37 bc
 DEC 4096 HEX 1000:  e4 dd 2e 98  d6 96 0f ae   0b 43 54 54  56 74 33 91

 Key length: 256 bits.
 key: 0x1ada31d5cf688221c109163908ebe51debb46227c6cc8b37641910833222772a

 DEC    0 HEX    0:  dd 5b cb 00  18 e9 22 d4   94 75 9d 7c  39 5d 02 d3
 DEC   16 HEX   10:  c8 44 6f 8f  77 ab f7 37   68 53 53 eb  89 a1 c9 eb
 DEC  240 HEX   f0:  af 3e 30 f9  c0 95 04 59   38 15 15 75  c3 fb 90 98
 DEC  256 HEX  100:  f8 cb 62 74  db 99 b8 0b   1d 20 12 a9  8e d4 8f 0e
 DEC  496 HEX  1f0:  25 c3 00 5a  1c b8 5d e0   76 25 98 39  ab 71 98 ab
 DEC  512 HEX  200:  9d cb c1 83  e8 cb 99 4b   72 7b 75 be  31 80 76 9c
 DEC  752 HEX  2f0:  a1 d3 07 8d  fa 91 69 50   3e d9 d4 49  1d ee 4e b2
 DEC  768 HEX  300:  85 14 a5 49  58 58 09 6f   59 6e 4b cd  66 b1 06 65
 DEC 1008 HEX  3f0:  5f 40 d5 9e  c1 b0 3b 33   73 8e fa 60  b2 25 5d 31
 DEC 1024 HEX  400:  34 77 c7 f7  64 a4 1b ac   ef f9 0b f1  4f 92 b7 cc
 DEC 1520 HEX  5f0:  ac 4e 95 36  8d 99 b9 eb   78 b8 da 8f  81 ff a7 95
 DEC 1536 HEX  600:  8c 3c 13 f8  c2 38 8b b7   3f 38 57 6e  65 b7 c4 46
 DEC 2032 HEX  7f0:  13 c4 b9 c1  df b6 65 79   ed dd 8a 28  0b 9f 73 16
 DEC 2048 HEX  800:  dd d2 78 20  55 01 26 69   8e fa ad c6  4b 64 f6 6e
 DEC 3056 HEX  bf0:  f0 8f 2e 66  d2 8e d1 43   f3 a2 37 cf  9d e7 35 59
 DEC 3072 HEX  c00:  9e a3 6c 52  55 31 b8 80   ba 12 43 34  f5 7b 0b 70
 DEC 4080 HEX  ff0:  d5 a3 9e 3d  fc c5 02 80   ba c4 a6 b5  aa 0d ca 7d
 DEC 4096 HEX 1000:  37 0b 1c 1f  e6 55 91 6d   97 fd 0d 47  ca 1d 72 b8

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

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 40-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_40bit );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 56-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_56bit );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 64-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_64bit );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 80-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_80bit );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 128-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_128bit );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 192-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_192bit );

	FCRYPTO_TEST_RUN(
	 "libfcrypto_rc4_crypt with RFC 6229 test vector and 256-bit key",
	 fcrypto_test_rc4_crypt_rfc6229_256bit );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

