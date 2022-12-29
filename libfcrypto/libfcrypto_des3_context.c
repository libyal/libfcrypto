/*
 * DES3 (de/en)crypt functions
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
#include <byte_stream.h>
#include <memory.h>
#include <types.h>

#include "libfcrypto_des3_context.h"
#include "libfcrypto_definitions.h"
#include "libfcrypto_libcerror.h"

static uint8_t libfcrypto_des3_permutation_table[ 64 ] = {
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };

static uint8_t libfcrypto_des3_inverse_permutation_table[ 64 ] = {
	40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 
	38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 
	36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 
	34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };

static uint8_t libfcrypto_des3_expansion_table[ 48 ] = {
	32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
	12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
	22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };

static uint8_t libfcrypto_des3_post_sbox_permulation[ 32 ] = {
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };

static uint8_t libfcrypto_des3_sboxes[ 8 ][ 64 ] = {
	{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 
	  0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 
	  4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 
	  15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 
	  3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 
	  0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 
	  13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
	{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 
	  13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 
	  13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
	  1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
	{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 
	  13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 
	  10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
	  3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 
	  14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 
	  4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 
	  11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
	  10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
	  9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
	  4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
	{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
	  13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
	  1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
	  6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
	  1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
	  7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
	  2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

static uint8_t libfcrypto_des3_permuted_choice_table1[ 56 ] = {
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
	31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
	29, 21, 13, 5, 28, 20, 12, 4 };

static uint8_t libfcrypto_des3_permuted_choice_table2[ 48 ] = {
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };

static uint8_t libfcrypto_des3_iteration_shift[ 16 ] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

/* Creates a DES3 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_des3_context_initialize(
     libfcrypto_des3_context_t **context,
     libcerror_error_t **error )
{
	libfcrypto_internal_des3_context_t *internal_context = NULL;
	static char *function                                = "libfcrypto_des3_context_initialize";

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_ALREADY_SET,
		 "%s: invalid context value already set.",
		 function );

		return( -1 );
	}
	internal_context = memory_allocate_structure(
	                    libfcrypto_internal_des3_context_t );

	if( internal_context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_INSUFFICIENT,
		 "%s: unable to create context.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_context,
	     0,
	     sizeof( libfcrypto_internal_des3_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		goto on_error;
	}
	*context = (libfcrypto_des3_context_t *) internal_context;

	return( 1 );

on_error:
	if( internal_context != NULL )
	{
		memory_free(
		 internal_context );
	}
	return( -1 );
}

/* Frees a DES3 context
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_des3_context_free(
     libfcrypto_des3_context_t **context,
     libcerror_error_t **error )
{
	libfcrypto_internal_des3_context_t *internal_context = NULL;
	static char *function                                = "libfcrypto_des3_context_free";
	int result                                           = 1;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( *context != NULL )
	{
		internal_context = (libfcrypto_internal_des3_context_t *) *context;
		*context         = NULL;

		if( memory_set(
		     internal_context,
		     0,
		     sizeof( libfcrypto_internal_des3_context_t ) ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_SET_FAILED,
			 "%s: unable to clear context.",
			 function );

			result = -1;
		}
		memory_free(
		 internal_context );
	}
	return( result );
}

/* Sets the key
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_des3_context_set_key(
     libfcrypto_des3_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error )
{
	libfcrypto_internal_des3_context_t *internal_context = NULL;
	static char *function                                = "libfcrypto_des3_context_set_key";
	uint64_t value_64bit                                 = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libfcrypto_internal_des3_context_t *) context;

	if( key == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid key.",
		 function );

		return( -1 );
	}
	/* 56, 112 and 168 are sizes of keys without odd-parity bits
	 * 64, 128 and 192 are sizes of keys with odd-parity bits
	 */
	if( ( key_bit_size != 56 )
	 && ( key_bit_size != 64 )
	 && ( key_bit_size != 112 )
	 && ( key_bit_size != 128 )
	 && ( key_bit_size != 168 )
	 && ( key_bit_size != 192 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported key bit size.",
		 function );

		return( -1 );
	}
	byte_stream_copy_to_uint64_big_endian(
	 &( key[ 0 ] ),
	 value_64bit );

	if( ( key_bit_size == 56 )
	 || ( key_bit_size == 112 )
	 || ( key_bit_size == 168 ) )
	{
		value_64bit >>= 8;
	}
	internal_context->keys[ 0 ] = value_64bit;

	if( ( key_bit_size == 56 )
	 || ( key_bit_size == 64 ) )
	{
		value_64bit = internal_context->keys[ 0 ];
	}
	else if( ( key_bit_size == 112 )
	      || ( key_bit_size == 168 ) )
	{
		byte_stream_copy_to_uint64_big_endian(
		 &( key[ 7 ] ),
		 value_64bit );

		value_64bit >>= 8;
	}
	else
	{
		byte_stream_copy_to_uint64_big_endian(
		 &( key[ 8 ] ),
		 value_64bit );
	}
	internal_context->keys[ 1 ] = value_64bit;

	if( ( key_bit_size == 56 )
	 || ( key_bit_size == 64 )
	 || ( key_bit_size == 112 )
	 || ( key_bit_size == 128 ) )
	{
		value_64bit = internal_context->keys[ 0 ];
	}
	else if( key_bit_size == 168 )
	{
		byte_stream_copy_to_uint48_big_endian(
		 &( key[ 14 ] ),
		 value_64bit );

		value_64bit <<= 8;
		value_64bit  |= key[ 20 ];
	}
	else
	{
		byte_stream_copy_to_uint64_big_endian(
		 &( key[ 16 ] ),
		 value_64bit );
	}
	internal_context->keys[ 2 ] = value_64bit;

	return( 1 );
}

/* De- or encrypts a block of data using DES3
 * The size must be a multitude of the DES3 block size (8 byte)
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_internal_des3_context_crypt_block(
     libfcrypto_internal_des3_context_t *internal_context,
     uint64_t key_value,
     int mode,
     uint64_t input_value,
     uint64_t *output_value,
     libcerror_error_t **error )
{
	uint64_t sub_keys[ 16 ];

	static char *function                = "libfcrypto_internal_des3_context_crypt_block";
	uint64_t bit_mask                    = 0;
	uint64_t permuted_output_value       = 0;
	uint64_t value_64bit                 = 0;
	uint32_t function_result             = 0;
	uint32_t permutation_lower_32bit     = 0;
	uint32_t permutation_upper_32bit     = 0;
	uint32_t permuted_choice_lower_32bit = 0;
	uint32_t permuted_choice_upper_32bit = 0;
	uint32_t sbox_output                 = 0;
	uint32_t value_32bit                 = 0;
	uint8_t bit_shift                    = 0;
	uint8_t column_bit_mask              = 0;
	uint8_t crypt_key_index              = 0;
	uint8_t iteration_shift              = 0;
	uint8_t row_bit_mask                 = 0;
	uint8_t sbox_index                   = 0;
	uint8_t sub_key_index                = 0;
	uint8_t table_index                  = 0;

	if( internal_context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	if( ( mode != LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT )
	 && ( mode != LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported mode.",
		 function );

		return( -1 );
	}
	if( output_value == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid output value.",
		 function );

		return( -1 );
	}
	/* Calculate the permutation
	 */
	value_64bit = 0;

	for( table_index = 0;
	     table_index < 64;
	     table_index++ )
	{
		bit_shift = 64 - libfcrypto_des3_permutation_table[ table_index ];

		value_64bit <<= 1;
		value_64bit  |= ( input_value >> bit_shift ) & 1ULL;
	}
	permutation_upper_32bit = (uint32_t) ( ( value_64bit >> 32 ) & 0xffffffffUL );
	permutation_lower_32bit = (uint32_t) ( value_64bit & 0xffffffffUL );

	/* Calculate the key schedule
	 */
	value_64bit = 0;

	for( table_index = 0;
	     table_index < 56;
	     table_index++ )
	{
		bit_shift = 64 - libfcrypto_des3_permuted_choice_table1[ table_index ];

		value_64bit <<= 1;
		value_64bit  |= ( key_value >> bit_shift ) & 1ULL;
	}
	permuted_choice_upper_32bit = (uint32_t) ( ( value_64bit >> 28 ) & 0x0fffffffUL );
	permuted_choice_lower_32bit = (uint32_t) ( value_64bit & 0x0fffffffUL );

	/* Calculate the 16 sub keys
	 */
	for( sub_key_index = 0;
	     sub_key_index < 16;
	     sub_key_index++ )
	{
		iteration_shift = libfcrypto_des3_iteration_shift[ sub_key_index ];

		permuted_choice_upper_32bit = ( ( permuted_choice_upper_32bit << 1 ) & 0x0fffffffUL ) | ( ( permuted_choice_upper_32bit >> 27 ) & 0x00000001UL );
		permuted_choice_lower_32bit = ( ( permuted_choice_lower_32bit << 1 ) & 0x0fffffffUL ) | ( ( permuted_choice_lower_32bit >> 27 ) & 0x00000001UL );

		if( iteration_shift == 2 )
		{
			permuted_choice_upper_32bit = ( ( permuted_choice_upper_32bit << 1 ) & 0x0fffffffUL ) | ( ( permuted_choice_upper_32bit >> 27 ) & 0x00000001UL );
			permuted_choice_lower_32bit = ( ( permuted_choice_lower_32bit << 1 ) & 0x0fffffffUL ) | ( ( permuted_choice_lower_32bit >> 27 ) & 0x00000001UL );
		}
		value_64bit = ( (uint64_t) permuted_choice_upper_32bit << 28 ) | permuted_choice_lower_32bit;
        
		sub_keys[ sub_key_index ] = 0;
        
		for( table_index = 0;
		     table_index < 48;
		     table_index++ )
		{
			bit_shift = 56 - libfcrypto_des3_permuted_choice_table2[ table_index ];

			sub_keys[ sub_key_index ] <<= 1;
			sub_keys[ sub_key_index ]  |= ( value_64bit >> bit_shift ) & 1ULL;
		}
	}
	sbox_output = 0;

	for( sub_key_index = 0;
	     sub_key_index < 16;
	     sub_key_index++ )
	{
		if( mode == LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT )
		{
			crypt_key_index = sub_key_index;
		}
		else
		{
			crypt_key_index = 15 - sub_key_index;
		}
		value_64bit = 0;
        
		for( table_index = 0;
		     table_index < 48;
		     table_index++ )
		{
			bit_shift = 32 - libfcrypto_des3_expansion_table[ table_index ];

			value_64bit <<= 1;
			value_64bit  |= ( permutation_lower_32bit >> bit_shift ) & 1ULL;
		}
		value_64bit ^= sub_keys[ crypt_key_index ];

		for( table_index = 0;
		     table_index < 8;
		     table_index++ )
		{
			sbox_index = table_index * 6;

			bit_mask  = 0x0000840000000000ULL >> sbox_index;
			bit_shift = 42 - sbox_index;

			row_bit_mask = (uint8_t) ( ( value_64bit & bit_mask ) >> bit_shift );
			row_bit_mask = ( row_bit_mask >> 4 ) | ( row_bit_mask & 0x01 );

			bit_mask  = 0x0000780000000000ULL >> sbox_index;
			bit_shift = 43 - sbox_index;

			column_bit_mask = (uint8_t) ( ( value_64bit & bit_mask ) >> bit_shift );

			sbox_index = ( row_bit_mask << 4 ) | column_bit_mask;
            
			sbox_output <<= 4;
			sbox_output  |= libfcrypto_des3_sboxes[ table_index ][ sbox_index ] & 0x0f;
		}
		function_result = 0;

		for( table_index = 0;
		     table_index < 32;
		     table_index++ )
		{
			bit_shift = 32 - libfcrypto_des3_post_sbox_permulation[ table_index ];

			function_result <<= 1;
			function_result  |= ( sbox_output >> bit_shift ) & 1UL;
		}
		value_32bit             = permutation_lower_32bit;
		permutation_lower_32bit = permutation_upper_32bit ^ function_result;
		permutation_upper_32bit = value_32bit;
	}
	permuted_output_value = ( (uint64_t) permutation_lower_32bit << 32 ) | permutation_upper_32bit;

	/* Calculate the inverse permutation
	 */
	value_64bit = 0;

	for( table_index = 0;
	     table_index < 64;
	     table_index++ )
	{
		bit_shift = 64 - libfcrypto_des3_inverse_permutation_table[ table_index ];

		value_64bit <<= 1;
		value_64bit  |= ( permuted_output_value >> bit_shift ) & 1ULL;
	}
	*output_value = value_64bit;

	return( 1 );
}

/* De- or encrypts a buffer of data using DES3
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_des3_crypt(
     libfcrypto_des3_context_t *context,
     int mode,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error )
{
	libfcrypto_internal_des3_context_t *internal_context = NULL;
	static char *function                                = "libfcrypto_des3_crypt";
	size_t data_offset                                   = 0;
	uint64_t value_64bit                                 = 0;

	if( context == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid context.",
		 function );

		return( -1 );
	}
	internal_context = (libfcrypto_internal_des3_context_t *) context;

	if( ( mode != LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT )
	 && ( mode != LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported mode.",
		 function );

		return( -1 );
	}
	if( input_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid input data.",
		 function );

		return( -1 );
	}
	if( ( input_data_size < 8 )
	 || ( input_data_size > (size_t) SSIZE_MAX ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid input data size value out of bounds.",
		 function );

		return( -1 );
	}
	/* Check if the input data size is a multitude of 8-byte
	 */
	if( ( input_data_size & (size_t) 0x07 ) != 0 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid input data size value out of bounds.",
		 function );

		return( -1 );
	}
	if( output_data == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid output data.",
		 function );

		return( -1 );
	}
	if( output_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid output data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( output_data_size < input_data_size )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_RUNTIME,
		 LIBCERROR_RUNTIME_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid ouput data size smaller than input data size.",
		 function );

		return( -1 );
	}
	while( data_offset < input_data_size )
	{
		byte_stream_copy_to_uint64_big_endian(
		 &( input_data[ data_offset ] ),
		 value_64bit );

		if( mode == LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT )
		{
			if( libfcrypto_internal_des3_context_crypt_block(
			     internal_context,
			     internal_context->keys[ 0 ],
			     LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT,
			     value_64bit,
			     &value_64bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to encrypt input data with first key.",
				 function );

				return( -1 );
			}
			if( libfcrypto_internal_des3_context_crypt_block(
			     internal_context,
			     internal_context->keys[ 1 ],
			     LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
			     value_64bit,
			     &value_64bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to decrypt input data with second key.",
				 function );

				return( -1 );
			}
			if( libfcrypto_internal_des3_context_crypt_block(
			     internal_context,
			     internal_context->keys[ 2 ],
			     LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT,
			     value_64bit,
			     &value_64bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to encrypt input data with third key.",
				 function );

				return( -1 );
			}
		}
		else
		{
			if( libfcrypto_internal_des3_context_crypt_block(
			     internal_context,
			     internal_context->keys[ 2 ],
			     LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
			     value_64bit,
			     &value_64bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to decrypt input data with third key.",
				 function );

				return( -1 );
			}
			if( libfcrypto_internal_des3_context_crypt_block(
			     internal_context,
			     internal_context->keys[ 1 ],
			     LIBFCRYPTO_DES3_CRYPT_MODE_ENCRYPT,
			     value_64bit,
			     &value_64bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to endrypt input data with second key.",
				 function );

				return( -1 );
			}
			if( libfcrypto_internal_des3_context_crypt_block(
			     internal_context,
			     internal_context->keys[ 0 ],
			     LIBFCRYPTO_DES3_CRYPT_MODE_DECRYPT,
			     value_64bit,
			     &value_64bit,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to decrypt input data with first key.",
				 function );

				return( -1 );
			}
		}
		byte_stream_copy_from_uint64_big_endian(
		 &( output_data[ data_offset ] ),
		 value_64bit );

		data_offset += 8;
	}
	return( 1 );
}

