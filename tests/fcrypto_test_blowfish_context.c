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

typedef struct fcrypto_test_blowfish_test_vector fcrypto_test_blowfish_test_vector_t;

struct fcrypto_test_blowfish_test_vector
{
        /* The key
         */
        uint8_t key[ 8 ];

        /* The unencrypted data
         */
        uint8_t unencrypted_data[ 8 ];

        /* The encrypted data
         */
        uint8_t encrypted_data[ 8 ];
};

#define FCRYPTO_TEST_BLOWFISH_NUMBER_OF_TEST_VECTORS	34

fcrypto_test_blowfish_test_vector_t fcrypto_test_blowfish_test_vectors[ FCRYPTO_TEST_BLOWFISH_NUMBER_OF_TEST_VECTORS ] = {
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78 } },
	{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	  { 0x51, 0x86, 0x6f, 0xd5, 0xb8, 0x5e, 0xcb, 0x8a } },
	{ { 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  { 0x7d, 0x85, 0x6f, 0x9a, 0x61, 0x30, 0x63, 0xf2 } },
	{ { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	  { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	  { 0x24, 0x66, 0xdd, 0x87, 0x8b, 0x96, 0x3c, 0x9d } },
	{ { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	  { 0x61, 0xf9, 0xc3, 0x80, 0x22, 0x81, 0xb0, 0x96 } },
	{ { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0x7d, 0x0c, 0xc6, 0x30, 0xaf, 0xda, 0x1e, 0xc7 } },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x4e, 0xf9, 0x97, 0x45, 0x61, 0x98, 0xdd, 0x78 } },
	{ { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0x0a, 0xce, 0xab, 0x0f, 0xc6, 0xa0, 0xa2, 0x8d } },
	{ { 0x7c, 0xa1, 0x10, 0x45, 0x4a, 0x1a, 0x6e, 0x57 },
	  { 0x01, 0xa1, 0xd6, 0xd0, 0x39, 0x77, 0x67, 0x42 },
	  { 0x59, 0xc6, 0x82, 0x45, 0xeb, 0x05, 0x28, 0x2b } },
	{ { 0x01, 0x31, 0xd9, 0x61, 0x9d, 0xc1, 0x37, 0x6e },
	  { 0x5c, 0xd5, 0x4c, 0xa8, 0x3d, 0xef, 0x57, 0xda },
	  { 0xb1, 0xb8, 0xcc, 0x0b, 0x25, 0x0f, 0x09, 0xa0 } },
	{ { 0x07, 0xa1, 0x13, 0x3e, 0x4a, 0x0b, 0x26, 0x86 },
	  { 0x02, 0x48, 0xd4, 0x38, 0x06, 0xf6, 0x71, 0x72 },
	  { 0x17, 0x30, 0xe5, 0x77, 0x8b, 0xea, 0x1d, 0xa4 } },
	{ { 0x38, 0x49, 0x67, 0x4c, 0x26, 0x02, 0x31, 0x9e },
	  { 0x51, 0x45, 0x4b, 0x58, 0x2d, 0xdf, 0x44, 0x0a },
	  { 0xa2, 0x5e, 0x78, 0x56, 0xcf, 0x26, 0x51, 0xeb } },
	{ { 0x04, 0xb9, 0x15, 0xba, 0x43, 0xfe, 0xb5, 0xb6 },
	  { 0x42, 0xfd, 0x44, 0x30, 0x59, 0x57, 0x7f, 0xa2 },
	  { 0x35, 0x38, 0x82, 0xb1, 0x09, 0xce, 0x8f, 0x1a } },
	{ { 0x01, 0x13, 0xb9, 0x70, 0xfd, 0x34, 0xf2, 0xce },
	  { 0x05, 0x9b, 0x5e, 0x08, 0x51, 0xcf, 0x14, 0x3a },
	  { 0x48, 0xf4, 0xd0, 0x88, 0x4c, 0x37, 0x99, 0x18 } },
	{ { 0x01, 0x70, 0xf1, 0x75, 0x46, 0x8f, 0xb5, 0xe6 },
	  { 0x07, 0x56, 0xd8, 0xe0, 0x77, 0x47, 0x61, 0xd2 },
	  { 0x43, 0x21, 0x93, 0xb7, 0x89, 0x51, 0xfc, 0x98 } },
	{ { 0x43, 0x29, 0x7f, 0xad, 0x38, 0xe3, 0x73, 0xfe },
	  { 0x76, 0x25, 0x14, 0xb8, 0x29, 0xbf, 0x48, 0x6a },
	  { 0x13, 0xf0, 0x41, 0x54, 0xd6, 0x9d, 0x1a, 0xe5 } },
	{ { 0x07, 0xa7, 0x13, 0x70, 0x45, 0xda, 0x2a, 0x16 },
	  { 0x3b, 0xdd, 0x11, 0x90, 0x49, 0x37, 0x28, 0x02 },
	  { 0x2e, 0xed, 0xda, 0x93, 0xff, 0xd3, 0x9c, 0x79 } },
	{ { 0x04, 0x68, 0x91, 0x04, 0xc2, 0xfd, 0x3b, 0x2f },
	  { 0x26, 0x95, 0x5f, 0x68, 0x35, 0xaf, 0x60, 0x9a },
	  { 0xd8, 0x87, 0xe0, 0x39, 0x3c, 0x2d, 0xa6, 0xe3 } },
	{ { 0x37, 0xd0, 0x6b, 0xb5, 0x16, 0xcb, 0x75, 0x46 },
	  { 0x16, 0x4d, 0x5e, 0x40, 0x4f, 0x27, 0x52, 0x32 },
	  { 0x5f, 0x99, 0xd0, 0x4f, 0x5b, 0x16, 0x39, 0x69 } },
	{ { 0x1f, 0x08, 0x26, 0x0d, 0x1a, 0xc2, 0x46, 0x5e },
	  { 0x6b, 0x05, 0x6e, 0x18, 0x75, 0x9f, 0x5c, 0xca },
	  { 0x4a, 0x05, 0x7a, 0x3b, 0x24, 0xd3, 0x97, 0x7b } },
	{ { 0x58, 0x40, 0x23, 0x64, 0x1a, 0xba, 0x61, 0x76 },
	  { 0x00, 0x4b, 0xd6, 0xef, 0x09, 0x17, 0x60, 0x62 },
	  { 0x45, 0x20, 0x31, 0xc1, 0xe4, 0xfa, 0xda, 0x8e } },
	{ { 0x02, 0x58, 0x16, 0x16, 0x46, 0x29, 0xb0, 0x07 },
	  { 0x48, 0x0d, 0x39, 0x00, 0x6e, 0xe7, 0x62, 0xf2 },
	  { 0x75, 0x55, 0xae, 0x39, 0xf5, 0x9b, 0x87, 0xbd } },
	{ { 0x49, 0x79, 0x3e, 0xbc, 0x79, 0xb3, 0x25, 0x8f },
	  { 0x43, 0x75, 0x40, 0xc8, 0x69, 0x8f, 0x3c, 0xfa },
	  { 0x53, 0xc5, 0x5f, 0x9c, 0xb4, 0x9f, 0xc0, 0x19 } },
	{ { 0x4f, 0xb0, 0x5e, 0x15, 0x15, 0xab, 0x73, 0xa7 },
	  { 0x07, 0x2d, 0x43, 0xa0, 0x77, 0x07, 0x52, 0x92 },
	  { 0x7a, 0x8e, 0x7b, 0xfa, 0x93, 0x7e, 0x89, 0xa3 } },
	{ { 0x49, 0xe9, 0x5d, 0x6d, 0x4c, 0xa2, 0x29, 0xbf },
	  { 0x02, 0xfe, 0x55, 0x77, 0x81, 0x17, 0xf1, 0x2a },
	  { 0xcf, 0x9c, 0x5d, 0x7a, 0x49, 0x86, 0xad, 0xb5 } },
	{ { 0x01, 0x83, 0x10, 0xdc, 0x40, 0x9b, 0x26, 0xd6 },
	  { 0x1d, 0x9d, 0x5c, 0x50, 0x18, 0xf7, 0x28, 0xc2 },
	  { 0xd1, 0xab, 0xb2, 0x90, 0x65, 0x8b, 0xc7, 0x78 } },
	{ { 0x1c, 0x58, 0x7f, 0x1c, 0x13, 0x92, 0x4f, 0xef },
	  { 0x30, 0x55, 0x32, 0x28, 0x6d, 0x6f, 0x29, 0x5a },
	  { 0x55, 0xcb, 0x37, 0x74, 0xd1, 0x3e, 0xf2, 0x01 } },
	{ { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0xfa, 0x34, 0xec, 0x48, 0x47, 0xb2, 0x68, 0xb2 } },
	{ { 0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0xa7, 0x90, 0x79, 0x51, 0x08, 0xea, 0x3c, 0xae } },
	{ { 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe },
	  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0xc3, 0x9e, 0x07, 0x2d, 0x9f, 0xac, 0x63, 0x1d } },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	  { 0x01, 0x49, 0x33, 0xe0, 0xcd, 0xaf, 0xf6, 0xe4 } },
	{ { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0xf2, 0x1e, 0x9a, 0x77, 0xb7, 0x1c, 0x49, 0xbc } },
	{ { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
	  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	  { 0x24, 0x59, 0x46, 0x88, 0x57, 0x54, 0x36, 0x9a } },
	{ { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 },
	  { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
	  { 0x6b, 0x5c, 0x5a, 0x9c, 0x5d, 0x9e, 0x0a, 0x5a } }
};

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

/* Tests the libfcrypto_blowfish_crypt function with a test vector
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_crypt_with_test_vector(
     fcrypto_test_blowfish_test_vector_t *test_vector )
{
	uint8_t output_data[ 8 ];

	libcerror_error_t *error                        = NULL;
	libfcrypto_blowfish_context_t *blowfish_context = NULL;
	int result                                      = 0;

	FCRYPTO_TEST_ASSERT_IS_NOT_NULL(
	 "test_vector",
	 test_vector );

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
	          test_vector->key,
	          64,
	          &error );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FCRYPTO_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_DECRYPT,
	          test_vector->encrypted_data,
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
	          test_vector->unencrypted_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

	result = libfcrypto_blowfish_crypt_ecb(
	          blowfish_context,
	          LIBFCRYPTO_BLOWFISH_CRYPT_MODE_ENCRYPT,
	          test_vector->unencrypted_data,
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
	          test_vector->encrypted_data,
	          8 );

	FCRYPTO_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 0 );

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

/* Tests the libfcrypto_blowfish_crypt function with test vectors
 * See: https://www.schneier.com/wp-content/uploads/2015/12/vectors-2.txt
 * Returns 1 if successful or 0 if not
 */
int fcrypto_test_blowfish_crypt_with_test_vectors(
     void )
{
	int result      = 0;
	int test_vector = 0;

	while( test_vector < FCRYPTO_TEST_BLOWFISH_NUMBER_OF_TEST_VECTORS )
	{
		result = fcrypto_test_blowfish_crypt_with_test_vector(
		          &( fcrypto_test_blowfish_test_vectors[ test_vector++ ] ) );

		if( result == 0 )
		{
			break;
		}
	}
	return( result );
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

	FCRYPTO_TEST_RUN(
	 "libfcrypto_blowfish_crypt_with_test_vectors",
	 fcrypto_test_blowfish_crypt_with_test_vectors );

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

