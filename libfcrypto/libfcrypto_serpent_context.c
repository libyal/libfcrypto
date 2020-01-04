/*
 * Serpent (de/en)crypt functions
 *
 * Copyright (C) 2017-2020, Joachim Metz <joachim.metz@gmail.com>
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

#include "libfcrypto_definitions.h"
#include "libfcrypto_serpent_context.h"

/* Serpent
 *
 * http://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
 */
#define libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	value0  = byte_stream_bit_rotate_left_32bit( value0, 13 ); \
	value2  = byte_stream_bit_rotate_left_32bit( value2, 3 ); \
	value1 ^= value0; \
	value4  = value0 << 3; \
	value3 ^= value2; \
	value1 ^= value2; \
	value1  = byte_stream_bit_rotate_left_32bit( value1, 1 ); \
	value3 ^= value4; \
	value3  = byte_stream_bit_rotate_left_32bit( value3, 7 ); \
	value4  = value1; \
	value0 ^= value1; \
	value4 <<= 7; \
	value2 ^= value3; \
	value0 ^= value3; \
	value2 ^= value4; \
	value3 ^= expanded_key_values[ expanded_key_index + 3 ]; \
	value1 ^= expanded_key_values[ expanded_key_index + 1 ]; \
	value0  = byte_stream_bit_rotate_left_32bit( value0, 5 ); \
	value2  = byte_stream_bit_rotate_left_32bit( value2, 22 ); \
	value0 ^= expanded_key_values[ expanded_key_index ]; \
	value2 ^= expanded_key_values[ expanded_key_index + 2 ];

#define libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	value0 ^= expanded_key_values[ expanded_key_index ]; \
	value1 ^= expanded_key_values[ expanded_key_index + 1 ]; \
	value2 ^= expanded_key_values[ expanded_key_index + 2 ]; \
	\
	value3 ^= expanded_key_values[ expanded_key_index + 3 ];	 \
	value0 = byte_stream_bit_rotate_right_32bit( value0, 5 ); \
	value2 = byte_stream_bit_rotate_right_32bit( value2, 22 ); \
	\
	value4 =  value1; \
	value2 ^= value3; \
	value0 ^= value3; \
	\
	value4 <<= 7; \
	value0 ^= value1; \
	value1 = byte_stream_bit_rotate_right_32bit( value1, 1 ); 	\
	value2 ^= value4; \
	value3 = byte_stream_bit_rotate_right_32bit( value3, 7 ); \
	value4 = value0 << 3; \
	\
	value1 ^= value0; \
	value3 ^= value4; \
	value0 = byte_stream_bit_rotate_right_32bit( value0, 13 );	\
	value1 ^= value2; \
	value3 ^= value2; \
	value2 = byte_stream_bit_rotate_right_32bit( value2, 3 );

#define libfcrypto_serpent_calculate_forward_substitution0( value0, value1, value2, value3, value4 ) \
	value4  = value3; \
	value3 |= value0; \
	value0 ^= value4; \
	value4 ^= value2; \
	value4  = ~value4; \
	value3 ^= value1; \
	value1 &= value0; \
	value1 ^= value4; \
	value2 ^= value0; \
	value0 ^= value3; \
	value4 |= value0; \
	value0 ^= value2; \
	value2 &= value1; \
	value3 ^= value2; \
	value1  = ~value1; \
	value2 ^= value4; \
	value1 ^= value2;

#define libfcrypto_serpent_calculate_forward_substitution1( value0, value1, value2, value3, value4 ) \
	value4  = value1; \
	value1 ^= value0; \
	value0 ^= value3; \
	value3  = ~value3; \
	value4 &= value1; \
	value0 |= value1; \
	value3 ^= value2; \
	value0 ^= value3; \
	value1 ^= value3; \
	value3 ^= value4; \
	value1 |= value4; \
	value4 ^= value2; \
	value2 &= value0; \
	value2 ^= value1; \
	value1 |= value0; \
	value0  = ~value0; \
	value0 ^= value2; \
	value4 ^= value1;

#define libfcrypto_serpent_calculate_forward_substitution2( value0, value1, value2, value3, value4 ) \
	value3  = ~value3; \
	value1 ^= value0; \
	value4  = value0; \
	value0 &= value2; \
	value0 ^= value3; \
	value3 |= value4; \
	value2 ^= value1; \
	value3 ^= value1; \
	value1 &= value0; \
	value0 ^= value2; \
	value2 &= value3; \
	value3 |= value1; \
	value0  = ~value0; \
	value3 ^= value0; \
	value4 ^= value0; \
	value0 ^= value2; \
	value1 |= value2;

#define libfcrypto_serpent_calculate_forward_substitution3( value0, value1, value2, value3, value4 ) \
	value4 	= value1; \
	value1 ^= value3; \
	value3 |= value0; \
	value4 &= value0; \
	value0 ^= value2; \
	value2 ^= value1; \
	value1 &= value3; \
	value2 ^= value3; \
	value0 |= value4; \
	value4 ^= value3; \
	value1 ^= value0; \
	value0 &= value3; \
	value3 &= value4; \
	value3 ^= value2; \
	value4 |= value1; \
	value2 &= value1; \
	value4 ^= value3; \
	value0 ^= value3; \
	value3 ^= value2;

#define libfcrypto_serpent_calculate_forward_substitution4( value0, value1, value2, value3, value4 ) \
	value4  = value3; \
	value3 &= value0; \
	value0 ^= value4; \
	value3 ^= value2; \
	value2 |= value4; \
	value0 ^= value1; \
	value4 ^= value3; \
	value2 |= value0; \
	value2 ^= value1; \
	value1 &= value0; \
	value1 ^= value4; \
	value4 &= value2; \
	value2 ^= value3; \
	value4 ^= value0; \
	value3 |= value1; \
	value1  = ~value1; \
	value3 ^= value0;

#define libfcrypto_serpent_calculate_forward_substitution5( value0, value1, value2, value3, value4 ) \
	value4  = value1; \
	value1 |= value0; \
	value2 ^= value1; \
	value3  = ~value3; \
	value4 ^= value0; \
	value0 ^= value2; \
	value1 &= value4; \
	value4 |= value3; \
	value4 ^= value0; \
	value0 &= value3; \
	value1 ^= value3; \
	value3 ^= value2; \
	value0 ^= value1; \
	value2 &= value4; \
	value1 ^= value2; \
	value2 &= value0; \
	value3 ^= value2;

#define libfcrypto_serpent_calculate_forward_substitution6( value0, value1, value2, value3, value4 ) \
	value4  = value1; \
	value3 ^= value0; \
	value1 ^= value2; \
	value2 ^= value0; \
	value0 &= value3; \
	value1 |= value3; \
	value4  = ~value4; \
	value0 ^= value1; \
	value1 ^= value2; \
	value3 ^= value4; \
	value4 ^= value0; \
	value2 &= value0; \
	value4 ^= value1; \
	value2 ^= value3; \
	value3 &= value1; \
	value3 ^= value0; \
	value1 ^= value2;

#define libfcrypto_serpent_calculate_forward_substitution7( value0, value1, value2, value3, value4 ) \
	value1  = ~value1; \
	value4  = value1; \
	value0  = ~value0; \
	value1 &= value2; \
	value1 ^= value3; \
	value3 |= value4; \
	value4 ^= value2; \
	value2 ^= value3; \
	value3 ^= value0; \
	value0 |= value1; \
	value2 &= value0; \
	value0 ^= value4; \
	value4 ^= value3; \
	value3 &= value0; \
	value4 ^= value1; \
	value2 ^= value4; \
	value3 ^= value1; \
	value4 |= value0; \
	value4 ^= value1;

#define libfcrypto_serpent_calculate_reverse_substitution0( value0, value1, value2, value3, value4 ) \
	value4  = value3; \
	value1 ^= value0; \
	value3 |= value1; \
	value4 ^= value1; \
	value0  = ~value0; \
	value2 ^= value3; \
	value3 ^= value0; \
	value0 &= value1; \
	value0 ^= value2; \
	value2 &= value3; \
	value3 ^= value4; \
	value2 ^= value3; \
	value1 ^= value3; \
	value3 &= value0; \
	value1 ^= value0; \
	value0 ^= value2; \
	value4 ^= value3;

#define libfcrypto_serpent_calculate_reverse_substitution1( value0, value1, value2, value3, value4 ) \
	value1 ^= value3; \
	value4  = value0; \
	value0 ^= value2; \
	value2  = ~value2; \
	value4 |= value1; \
	value4 ^= value3; \
	value3 &= value1; \
	value1 ^= value2; \
	value2 &= value4; \
	value4 ^= value1; \
	value1 |= value3; \
	value3 ^= value0; \
	value2 ^= value0; \
	value0 |= value4; \
	value2 ^= value4; \
	value1 ^= value0; \
	value4 ^= value1;

#define libfcrypto_serpent_calculate_reverse_substitution2( value0, value1, value2, value3, value4 ) \
	value2 ^= value1; \
	value4  = value3; \
	value3  = ~value3; \
	value3 |= value2; \
	value2 ^= value4; \
	value4 ^= value0; \
	value3 ^= value1; \
	value1 |= value2; \
	value2 ^= value0; \
	value1 ^= value4; \
	value4 |= value3; \
	value2 ^= value3; \
	value4 ^= value2; \
	value2 &= value1; \
	value2 ^= value3; \
	value3 ^= value4; \
	value4 ^= value0;

#define libfcrypto_serpent_calculate_reverse_substitution3( value0, value1, value2, value3, value4 ) \
	value2 ^= value1; \
	value4  = value1; \
	value1 &= value2; \
	value1 ^= value0; \
	value0 |= value4; \
	value4 ^= value3; \
	value0 ^= value3; \
	value3 |= value1; \
	value1 ^= value2; \
	value1 ^= value3; \
	value0 ^= value2; \
	value2 ^= value3; \
	value3 &= value1; \
	value1 ^= value0; \
	value0 &= value2; \
	value4 ^= value3; \
	value3 ^= value0; \
	value0 ^= value1;

#define libfcrypto_serpent_calculate_reverse_substitution4( value0, value1, value2, value3, value4 ) \
	value2 ^= value3; \
	value4  = value0; \
	value0 &= value1; \
	value0 ^= value2; \
	value2 |= value3; \
	value4  = ~value4; \
	value1 ^= value0; \
	value0 ^= value2; \
	value2 &= value4; \
	value2 ^= value0; \
	value0 |= value4; \
	value0 ^= value3; \
	value3 &= value2; \
	value4 ^= value3; \
	value3 ^= value1; \
	value1 &= value0; \
	value4 ^= value1; \
	value0 ^= value3;

#define libfcrypto_serpent_calculate_reverse_substitution5( value0, value1, value2, value3, value4 ) \
	value4  = value1; \
	value1 |= value2; \
	value2 ^= value4; \
	value1 ^= value3; \
	value3 &= value4; \
	value2 ^= value3; \
	value3 |= value0; \
	value0  = ~value0; \
	value3 ^= value2; \
	value2 |= value0; \
	value4 ^= value1; \
	value2 ^= value4; \
	value4 &= value0; \
	value0 ^= value1; \
	value1 ^= value3; \
	value0 &= value2; \
	value2 ^= value3; \
	value0 ^= value2; \
	value2 ^= value4; \
	value4 ^= value3;

#define libfcrypto_serpent_calculate_reverse_substitution6( value0, value1, value2, value3, value4 ) \
	value0 ^= value2; \
	value4  = value0; \
	value0 &= value3; \
	value2 ^= value3; \
	value0 ^= value2; \
	value3 ^= value1; \
	value2 |= value4; \
	value2 ^= value3; \
	value3 &= value0; \
	value0  = ~value0; \
	value3 ^= value1; \
	value1 &= value2; \
	value4 ^= value0; \
	value3 ^= value4; \
	value4 ^= value2; \
	value0 ^= value1; \
	value2 ^= value0;

#define libfcrypto_serpent_calculate_reverse_substitution7( value0, value1, value2, value3, value4 ) \
	value4  = value3; \
	value3 &= value0; \
	value0 ^= value2; \
	value2 |= value4; \
	value4 ^= value1; \
	value0  = ~value0; \
	value1 |= value3; \
	value4 ^= value0; \
	value0 &= value2; \
	value0 ^= value1; \
	value1 &= value2; \
	value3 ^= value2; \
	value4 ^= value3; \
	value2 &= value3; \
	value3 |= value0; \
	value1 ^= value4; \
	value3 ^= value4; \
	value4 &= value0; \
	value4 ^= value2;

#define GOLDEN_RATIO_FRACTION	0x9e3779b9UL

#define libfcrypto_serpent_calculate_expanded_key( expanded_key_values, expanded_key_index, value0, value1, value2, value3 ) \
	value1 ^= value3; \
	value1 ^= value2; \
	value1 ^= value0; \
	value1 ^= GOLDEN_RATIO_FRACTION ^ expanded_key_index; \
	value1 = byte_stream_bit_rotate_left_32bit( value1, 11 ); \
	expanded_key_values[ expanded_key_index ] = value1;

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution0( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution0( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution1( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution1( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution2( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution2( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution3( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution3( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution4( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution4( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution5( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution5( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution6( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution6( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_expanded_key_with_forward_substitution7( expanded_key_value0, expanded_key_value1, expanded_key_value2, expanded_key_value3, expanded_key_value4, expanded_key_value5, expanded_key_value6, expanded_key_value7, value0, value1, value2, value3, value4 ) \
	expanded_key_value0 = value0; \
	expanded_key_value1 = value1; \
	expanded_key_value2 = value2; \
	expanded_key_value3 = value3; \
	value0 = expanded_key_value4; \
	value1 = expanded_key_value5; \
	value2 = expanded_key_value6; \
	value3 = expanded_key_value7; \
	libfcrypto_serpent_calculate_forward_substitution7( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution0( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution0( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution1( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution1( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution2( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution2( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution3( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution3( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution4( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution4( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution5( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution5( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution6( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution6( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution7( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_forward_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_forward_substitution7( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution0( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution0( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution1( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution1( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution2( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution2( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution3( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution3( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution4( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution4( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution5( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution5( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution6( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution6( value0, value1, value2, value3, value4 );

#define libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution7( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ) \
	libfcrypto_serpent_calculate_reverse_linear_transformation( expanded_key_values, expanded_key_index, value0, value1, value2, value3, value4 ); \
	libfcrypto_serpent_calculate_reverse_substitution7( value0, value1, value2, value3, value4 );

/* Creates a context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_serpent_context_initialize(
     libfcrypto_serpent_context_t **context,
     libcerror_error_t **error )
{
	libfcrypto_internal_serpent_context_t *internal_context = NULL;
	static char *function                                   = "libfcrypto_serpent_context_initialize";

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
	                    libfcrypto_internal_serpent_context_t );

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
	     sizeof( libfcrypto_internal_serpent_context_t ) ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear context.",
		 function );

		goto on_error;
	}
	*context = (libfcrypto_serpent_context_t *) internal_context;

	return( 1 );

on_error:
	if( internal_context != NULL )
	{
		memory_free(
		 internal_context );
	}
	return( -1 );
}

/* Frees a context
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_serpent_context_free(
     libfcrypto_serpent_context_t **context,
     libcerror_error_t **error )
{
	libfcrypto_internal_serpent_context_t *internal_context = NULL;
	static char *function                                   = "libfcrypto_serpent_context_free";
	int result                                              = 1;

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
		internal_context = (libfcrypto_internal_serpent_context_t *) *context;
		*context         = NULL;

		if( memory_set(
		     internal_context,
		     0,
		     sizeof( libfcrypto_internal_serpent_context_t ) ) == NULL )
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
int libfcrypto_serpent_context_set_key(
     libfcrypto_serpent_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error )
{
	uint8_t key_data[ 32 ];

	libfcrypto_internal_serpent_context_t *internal_context = NULL;
	static char *function                                   = "libfcrypto_serpent_context_set_key";
	size_t key_byte_offset                                  = 0;
	size_t key_byte_size                                    = 0;
	uint32_t value0                                         = 0;
	uint32_t value1                                         = 0;
	uint32_t value2                                         = 0;
	uint32_t value3                                         = 0;
	uint32_t value4                                         = 0;
	uint8_t expanded_key_index                              = 0;
	uint8_t previous_expanded_key_index                     = 0;

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
	internal_context = (libfcrypto_internal_serpent_context_t *) context;

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
	if( ( key_bit_size != 128 )
	 && ( key_bit_size != 192 )
	 && ( key_bit_size != 256 ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported key bit size.",
		 function );

		return( -1 );
	}
	if( memory_set(
	     key_data,
	     0,
	     32  ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear key data.",
		 function );

		goto on_error;
	}
	if( memory_set(
	     internal_context->expanded_key,
	     0,
	     sizeof( uint32_t ) * LIBFCRYPTO_SERPENT_NUMBER_OF_EXPANDED_KEY_ELEMENTS ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear expanded key.",
		 function );

		goto on_error;
	}
	/* 1. Copy and pad the provided key
	 */
	key_byte_size = key_bit_size / 8;

	if( memory_copy(
	     key_data,
	     key,
	     key_byte_size ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy key to key data.",
		 function );

		goto on_error;
	}
	if( key_byte_size < 32 )
	{
		key_data[ key_byte_size ] = 1;
	}
	for( key_byte_offset = 0;
	     key_byte_offset < 32;
	     key_byte_offset += 4 )
	{
		byte_stream_copy_to_uint32_little_endian(
		 &( key_data[ key_byte_offset ] ),
		 value0 );

		internal_context->expanded_key[ expanded_key_index++ ] = value0;
	}
	/* 2. Calculate the prekeys
	 */
	value0 = internal_context->expanded_key[ 3 ];
	value1 = internal_context->expanded_key[ 4 ];
	value2 = internal_context->expanded_key[ 5 ];
	value3 = internal_context->expanded_key[ 6 ];
	value4 = internal_context->expanded_key[ 7 ];

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 0,
	 internal_context->expanded_key[ 0 ],
	 value0,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 1,
	 internal_context->expanded_key[ 1 ],
	 value1,
	 value0,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 2,
	 ( internal_context->expanded_key )[ 2 ],
	 value2,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 3,
	 ( internal_context->expanded_key )[ 3 ],
	 value3,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 4,
	 ( internal_context->expanded_key )[ 4 ],
	 value4,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 5,
	 ( internal_context->expanded_key )[ 5 ],
	 value0,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 6,
	 ( internal_context->expanded_key )[ 6 ],
	 value1,
	 value0,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 7,
	 ( internal_context->expanded_key )[ 7 ],
	 value2,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 8,
	 ( internal_context->expanded_key )[ 0 ],
	 value3,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 9,
	 ( internal_context->expanded_key )[ 1 ],
	 value4,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 10,
	 ( internal_context->expanded_key )[ 2 ],
	 value0,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key(
	 internal_context->expanded_key,
	 11,
	 ( internal_context->expanded_key )[ 3 ],
	 value1,
	 value0,
	 value3 );

	previous_expanded_key_index = 4;
	expanded_key_index          = 12;

	while( expanded_key_index < 128 )
	{
		libfcrypto_serpent_calculate_expanded_key(
		 internal_context->expanded_key,
		 expanded_key_index,
		 ( internal_context->expanded_key )[ previous_expanded_key_index ],
		 value2,
		 value1,
		 value4 );

		expanded_key_index++;
		previous_expanded_key_index++;

		libfcrypto_serpent_calculate_expanded_key(
		 internal_context->expanded_key,
		 expanded_key_index,
		 ( internal_context->expanded_key )[ previous_expanded_key_index ],
		 value3,
		 value2,
		 value0 );

		expanded_key_index++;
		previous_expanded_key_index++;

		libfcrypto_serpent_calculate_expanded_key(
		 internal_context->expanded_key,
		 expanded_key_index,
		 ( internal_context->expanded_key )[ previous_expanded_key_index ],
		 value4,
		 value3,
		 value1 );

		expanded_key_index++;
		previous_expanded_key_index++;

		libfcrypto_serpent_calculate_expanded_key(
		 internal_context->expanded_key,
		 expanded_key_index,
		 ( internal_context->expanded_key )[ previous_expanded_key_index ],
		 value0,
		 value4,
		 value2 );

		expanded_key_index++;
		previous_expanded_key_index++;

		libfcrypto_serpent_calculate_expanded_key(
		 internal_context->expanded_key,
		 expanded_key_index,
		 ( internal_context->expanded_key )[ previous_expanded_key_index ],
		 value1,
		 value0,
		 value3 );

		expanded_key_index++;
		previous_expanded_key_index++;
	}
	/* 3. Calculate the round keys
	 */
	libfcrypto_serpent_calculate_forward_substitution3(
	 value3,
	 value4,
	 value0,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution4(
	 internal_context->expanded_key[ 128 ],
	 internal_context->expanded_key[ 129 ],
	 internal_context->expanded_key[ 130 ],
	 internal_context->expanded_key[ 131 ],
	 internal_context->expanded_key[ 124 ],
	 internal_context->expanded_key[ 125 ],
	 internal_context->expanded_key[ 126 ],
	 internal_context->expanded_key[ 127 ],
	 value1,
	 value2,
	 value4,
	 value3,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution5(
	 internal_context->expanded_key[ 124 ],
	 internal_context->expanded_key[ 125 ],
	 internal_context->expanded_key[ 126 ],
	 internal_context->expanded_key[ 127 ],
	 internal_context->expanded_key[ 120 ],
	 internal_context->expanded_key[ 121 ],
	 internal_context->expanded_key[ 122 ],
	 internal_context->expanded_key[ 123 ],
	 value2,
	 value4,
	 value3,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution6(
	 internal_context->expanded_key[ 120 ],
	 internal_context->expanded_key[ 121 ],
	 internal_context->expanded_key[ 122 ],
	 internal_context->expanded_key[ 123 ],
	 internal_context->expanded_key[ 116 ],
	 internal_context->expanded_key[ 117 ],
	 internal_context->expanded_key[ 118 ],
	 internal_context->expanded_key[ 119 ],
	 value1,
	 value2,
	 value4,
	 value0,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution7(
	 internal_context->expanded_key[ 116 ],
	 internal_context->expanded_key[ 117 ],
	 internal_context->expanded_key[ 118 ],
	 internal_context->expanded_key[ 119 ],
	 internal_context->expanded_key[ 112 ],
	 internal_context->expanded_key[ 113 ],
	 internal_context->expanded_key[ 114 ],
	 internal_context->expanded_key[ 115 ],
	 value4,
	 value3,
	 value2,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution0(
	 internal_context->expanded_key[ 112 ],
	 internal_context->expanded_key[ 113 ],
	 internal_context->expanded_key[ 114 ],
	 internal_context->expanded_key[ 115 ],
	 internal_context->expanded_key[ 108 ],
	 internal_context->expanded_key[ 109 ],
	 internal_context->expanded_key[ 110 ],
	 internal_context->expanded_key[ 111 ],
	 value1,
	 value2,
	 value0,
	 value4,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution1(
	 internal_context->expanded_key[ 108 ],
	 internal_context->expanded_key[ 109 ],
	 internal_context->expanded_key[ 110 ],
	 internal_context->expanded_key[ 111 ],
	 internal_context->expanded_key[ 104 ],
	 internal_context->expanded_key[ 105 ],
	 internal_context->expanded_key[ 106 ],
	 internal_context->expanded_key[ 107 ],
	 value0,
	 value2,
	 value4,
	 value1,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution2(
	 internal_context->expanded_key[ 104 ],
	 internal_context->expanded_key[ 105 ],
	 internal_context->expanded_key[ 106 ],
	 internal_context->expanded_key[ 107 ],
	 internal_context->expanded_key[ 100 ],
	 internal_context->expanded_key[ 101 ],
	 internal_context->expanded_key[ 102 ],
	 internal_context->expanded_key[ 103 ],
	 value3,
	 value4,
	 value1,
	 value0,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution3(
	 internal_context->expanded_key[ 100 ],
	 internal_context->expanded_key[ 101 ],
	 internal_context->expanded_key[ 102 ],
	 internal_context->expanded_key[ 103 ],
	 internal_context->expanded_key[ 96 ],
	 internal_context->expanded_key[ 97 ],
	 internal_context->expanded_key[ 98 ],
	 internal_context->expanded_key[ 99 ],
	 value2,
	 value4,
	 value3,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution4(
	 internal_context->expanded_key[ 96 ],
	 internal_context->expanded_key[ 97 ],
	 internal_context->expanded_key[ 98 ],
	 internal_context->expanded_key[ 99 ],
	 internal_context->expanded_key[ 92 ],
	 internal_context->expanded_key[ 93 ],
	 internal_context->expanded_key[ 94 ],
	 internal_context->expanded_key[ 95 ],
	 value0,
	 value1,
	 value4,
	 value2,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution5(
	 internal_context->expanded_key[ 92 ],
	 internal_context->expanded_key[ 93 ],
	 internal_context->expanded_key[ 94 ],
	 internal_context->expanded_key[ 95 ],
	 internal_context->expanded_key[ 88 ],
	 internal_context->expanded_key[ 89 ],
	 internal_context->expanded_key[ 90 ],
	 internal_context->expanded_key[ 91 ],
	 value1,
	 value4,
	 value2,
	 value3,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution6(
	 internal_context->expanded_key[ 88 ],
	 internal_context->expanded_key[ 89 ],
	 internal_context->expanded_key[ 90 ],
	 internal_context->expanded_key[ 91 ],
	 internal_context->expanded_key[ 84 ],
	 internal_context->expanded_key[ 85 ],
	 internal_context->expanded_key[ 86 ],
	 internal_context->expanded_key[ 87 ],
	 value0,
	 value1,
	 value4,
	 value3,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution7(
	 internal_context->expanded_key[ 84 ],
	 internal_context->expanded_key[ 85 ],
	 internal_context->expanded_key[ 86 ],
	 internal_context->expanded_key[ 87 ],
	 internal_context->expanded_key[ 80 ],
	 internal_context->expanded_key[ 81 ],
	 internal_context->expanded_key[ 82 ],
	 internal_context->expanded_key[ 83 ],
	 value4,
	 value2,
	 value1,
	 value3,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution0(
	 internal_context->expanded_key[ 80 ],
	 internal_context->expanded_key[ 81 ],
	 internal_context->expanded_key[ 82 ],
	 internal_context->expanded_key[ 83 ],
	 internal_context->expanded_key[ 76 ],
	 internal_context->expanded_key[ 77 ],
	 internal_context->expanded_key[ 78 ],
	 internal_context->expanded_key[ 79 ],
	 value0,
	 value1,
	 value3,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution1(
	 internal_context->expanded_key[ 76 ],
	 internal_context->expanded_key[ 77 ],
	 internal_context->expanded_key[ 78 ],
	 internal_context->expanded_key[ 79 ],
	 internal_context->expanded_key[ 72 ],
	 internal_context->expanded_key[ 73 ],
	 internal_context->expanded_key[ 74 ],
	 internal_context->expanded_key[ 75 ],
	 value3,
	 value1,
	 value4,
	 value0,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution2(
	 internal_context->expanded_key[ 72 ],
	 internal_context->expanded_key[ 73 ],
	 internal_context->expanded_key[ 74 ],
	 internal_context->expanded_key[ 75 ],
	 internal_context->expanded_key[ 68 ],
	 internal_context->expanded_key[ 69 ],
	 internal_context->expanded_key[ 70 ],
	 internal_context->expanded_key[ 71 ],
	 value2,
	 value4,
	 value0,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution3(
	 internal_context->expanded_key[ 68 ],
	 internal_context->expanded_key[ 69 ],
	 internal_context->expanded_key[ 70 ],
	 internal_context->expanded_key[ 71 ],
	 internal_context->expanded_key[ 64 ],
	 internal_context->expanded_key[ 65 ],
	 internal_context->expanded_key[ 66 ],
	 internal_context->expanded_key[ 67 ],
	 value1,
	 value4,
	 value2,
	 value3,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution4(
	 internal_context->expanded_key[ 64 ],
	 internal_context->expanded_key[ 65 ],
	 internal_context->expanded_key[ 66 ],
	 internal_context->expanded_key[ 67 ],
	 internal_context->expanded_key[ 60 ],
	 internal_context->expanded_key[ 61 ],
	 internal_context->expanded_key[ 62 ],
	 internal_context->expanded_key[ 63 ],
	 value3,
	 value0,
	 value4,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution5(
	 internal_context->expanded_key[ 60 ],
	 internal_context->expanded_key[ 61 ],
	 internal_context->expanded_key[ 62 ],
	 internal_context->expanded_key[ 63 ],
	 internal_context->expanded_key[ 56 ],
	 internal_context->expanded_key[ 57 ],
	 internal_context->expanded_key[ 58 ],
	 internal_context->expanded_key[ 59 ],
	 value0,
	 value4,
	 value1,
	 value2,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution6(
	 internal_context->expanded_key[ 56 ],
	 internal_context->expanded_key[ 57 ],
	 internal_context->expanded_key[ 58 ],
	 internal_context->expanded_key[ 59 ],
	 internal_context->expanded_key[ 52 ],
	 internal_context->expanded_key[ 53 ],
	 internal_context->expanded_key[ 54 ],
	 internal_context->expanded_key[ 55 ],
	 value3,
	 value0,
	 value4,
	 value2,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution7(
	 internal_context->expanded_key[ 52 ],
	 internal_context->expanded_key[ 53 ],
	 internal_context->expanded_key[ 54 ],
	 internal_context->expanded_key[ 55 ],
	 internal_context->expanded_key[ 48 ],
	 internal_context->expanded_key[ 49 ],
	 internal_context->expanded_key[ 50 ],
	 internal_context->expanded_key[ 51 ],
	 value4,
	 value1,
	 value0,
	 value2,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution0(
	 internal_context->expanded_key[ 48 ],
	 internal_context->expanded_key[ 49 ],
	 internal_context->expanded_key[ 50 ],
	 internal_context->expanded_key[ 51 ],
	 internal_context->expanded_key[ 44 ],
	 internal_context->expanded_key[ 45 ],
	 internal_context->expanded_key[ 46 ],
	 internal_context->expanded_key[ 47 ],
	 value3,
	 value0,
	 value2,
	 value4,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution1(
	 internal_context->expanded_key[ 44 ],
	 internal_context->expanded_key[ 45 ],
	 internal_context->expanded_key[ 46 ],
	 internal_context->expanded_key[ 47 ],
	 internal_context->expanded_key[ 40 ],
	 internal_context->expanded_key[ 41 ],
	 internal_context->expanded_key[ 42 ],
	 internal_context->expanded_key[ 43 ],
	 value2,
	 value0,
	 value4,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution2(
	 internal_context->expanded_key[ 40 ],
	 internal_context->expanded_key[ 41 ],
	 internal_context->expanded_key[ 42 ],
	 internal_context->expanded_key[ 43 ],
	 internal_context->expanded_key[ 36 ],
	 internal_context->expanded_key[ 37 ],
	 internal_context->expanded_key[ 38 ],
	 internal_context->expanded_key[ 39 ],
	 value1,
	 value4,
	 value3,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution3(
	 internal_context->expanded_key[ 36 ],
	 internal_context->expanded_key[ 37 ],
	 internal_context->expanded_key[ 38 ],
	 internal_context->expanded_key[ 39 ],
	 internal_context->expanded_key[ 32 ],
	 internal_context->expanded_key[ 33 ],
	 internal_context->expanded_key[ 34 ],
	 internal_context->expanded_key[ 35 ],
	 value0,
	 value4,
	 value1,
	 value2,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution4(
	 internal_context->expanded_key[ 32 ],
	 internal_context->expanded_key[ 33 ],
	 internal_context->expanded_key[ 34 ],
	 internal_context->expanded_key[ 35 ],
	 internal_context->expanded_key[ 28 ],
	 internal_context->expanded_key[ 29 ],
	 internal_context->expanded_key[ 30 ],
	 internal_context->expanded_key[ 31 ],
	 value2,
	 value3,
	 value4,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution5(
	 internal_context->expanded_key[ 28 ],
	 internal_context->expanded_key[ 29 ],
	 internal_context->expanded_key[ 30 ],
	 internal_context->expanded_key[ 31 ],
	 internal_context->expanded_key[ 24 ],
	 internal_context->expanded_key[ 25 ],
	 internal_context->expanded_key[ 26 ],
	 internal_context->expanded_key[ 27 ],
	 value3,
	 value4,
	 value0,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution6(
	 internal_context->expanded_key[ 24 ],
	 internal_context->expanded_key[ 25 ],
	 internal_context->expanded_key[ 26 ],
	 internal_context->expanded_key[ 27 ],
	 internal_context->expanded_key[ 20 ],
	 internal_context->expanded_key[ 21 ],
	 internal_context->expanded_key[ 22 ],
	 internal_context->expanded_key[ 23 ],
	 value2,
	 value3,
	 value4,
	 value1,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution7(
	 internal_context->expanded_key[ 20 ],
	 internal_context->expanded_key[ 21 ],
	 internal_context->expanded_key[ 22 ],
	 internal_context->expanded_key[ 23 ],
	 internal_context->expanded_key[ 16 ],
	 internal_context->expanded_key[ 17 ],
	 internal_context->expanded_key[ 18 ],
	 internal_context->expanded_key[ 19 ],
	 value4,
	 value0,
	 value3,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution0(
	 internal_context->expanded_key[ 16 ],
	 internal_context->expanded_key[ 17 ],
	 internal_context->expanded_key[ 18 ],
	 internal_context->expanded_key[ 19 ],
	 internal_context->expanded_key[ 12 ],
	 internal_context->expanded_key[ 13 ],
	 internal_context->expanded_key[ 14 ],
	 internal_context->expanded_key[ 15 ],
	 value2,
	 value3,
	 value1,
	 value4,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution1(
	 internal_context->expanded_key[ 12 ],
	 internal_context->expanded_key[ 13 ],
	 internal_context->expanded_key[ 14 ],
	 internal_context->expanded_key[ 15 ],
	 internal_context->expanded_key[ 8 ],
	 internal_context->expanded_key[ 9 ],
	 internal_context->expanded_key[ 10 ],
	 internal_context->expanded_key[ 11 ],
	 value1,
	 value3,
	 value4,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution2(
	 internal_context->expanded_key[ 8 ],
	 internal_context->expanded_key[ 9 ],
	 internal_context->expanded_key[ 10 ],
	 internal_context->expanded_key[ 11 ],
	 internal_context->expanded_key[ 4 ],
	 internal_context->expanded_key[ 5 ],
	 internal_context->expanded_key[ 6 ],
	 internal_context->expanded_key[ 7 ],
	 value0,
	 value4,
	 value2,
	 value1,
	 value3 );

	libfcrypto_serpent_calculate_expanded_key_with_forward_substitution3(
	 internal_context->expanded_key[ 4 ],
	 internal_context->expanded_key[ 5 ],
	 internal_context->expanded_key[ 6 ],
	 internal_context->expanded_key[ 7 ],
	 internal_context->expanded_key[ 0 ],
	 internal_context->expanded_key[ 1 ],
	 internal_context->expanded_key[ 2 ],
	 internal_context->expanded_key[ 3 ],
	 value3,
	 value4,
	 value0,
	 value1,
	 value2 );

	internal_context->expanded_key[ 0 ] = value1;
	internal_context->expanded_key[ 1 ] = value2;
	internal_context->expanded_key[ 2 ] = value4;
	internal_context->expanded_key[ 3 ] = value3;

	return( 1 );

on_error:
	memory_set(
	 key_data,
	 0,
	 32 );

	memory_set(
	 internal_context->expanded_key,
	 0,
	 sizeof( uint32_t ) * LIBFCRYPTO_SERPENT_NUMBER_OF_EXPANDED_KEY_ELEMENTS );

	return( -1 );
}

/* Encrypts a block of data using Serpent
 * The size must be a multitude of the Serpent block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_internal_serpent_context_encrypt_block(
     libfcrypto_internal_serpent_context_t *internal_context,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error )
{
	static char *function = "libfcrypto_internal_serpent_context_encrypt_block";
	uint32_t value0       = 0;
	uint32_t value1       = 0;
	uint32_t value2       = 0;
	uint32_t value3       = 0;
	uint32_t value4       = 0;

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
	if( input_data_size < 16 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid input data size value too small.",
		 function );

		return( -1 );
	}
	if( input_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid input data size value exceeds maximum.",
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
	if( output_data_size < 16 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid output data size value too small.",
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
	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 0 ] ),
	 value0 );

	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 4 ] ),
	 value1 );

	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 8 ] ),
	 value2 );

	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 12 ] ),
	 value3 );

	value0 ^= internal_context->expanded_key[ 0 ];
	value1 ^= internal_context->expanded_key[ 1 ];
	value2 ^= internal_context->expanded_key[ 2 ];
	value3 ^= internal_context->expanded_key[ 3 ];

	libfcrypto_serpent_calculate_forward_substitution0(
	 value0,
	 value1,
	 value2,
	 value3,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 4,
	 value2,
	 value1,
	 value3,
	 value0,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 8,
	 value4,
	 value3,
	 value0,
	 value2,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 12,
	 value1,
	 value3,
	 value4,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 16,
	 value2,
	 value0,
	 value3,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 20,
	 value0,
	 value3,
	 value1,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 24,
	 value2,
	 value0,
	 value3,
	 value4,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 28,
	 value3,
	 value1,
	 value0,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 32,
	 value2,
	 value0,
	 value4,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 36,
	 value4,
	 value0,
	 value3,
	 value2,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 40,
	 value1,
	 value3,
	 value2,
	 value4,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 44,
	 value0,
	 value3,
	 value1,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 48,
	 value4,
	 value2,
	 value3,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 52,
	 value2,
	 value3,
	 value0,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 56,
	 value4,
	 value2,
	 value3,
	 value1,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 60,
	 value3,
	 value0,
	 value2,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 64,
	 value4,
	 value2,
	 value1,
	 value3,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 68,
	 value1,
	 value2,
	 value3,
	 value4,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 72,
	 value0,
	 value3,
	 value4,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 76,
	 value2,
	 value3,
	 value0,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 80,
	 value1,
	 value4,
	 value3,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 84,
	 value4,
	 value3,
	 value2,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 88,
	 value1,
	 value4,
	 value3,
	 value0,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 92,
	 value3,
	 value2,
	 value4,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 96,
	 value1,
	 value4,
	 value0,
	 value3,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 100,
	 value0,
	 value4,
	 value3,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 104,
	 value2,
	 value3,
	 value1,
	 value0,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 108,
	 value4,
	 value3,
	 value2,
	 value0,
	 value1 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 112,
	 value0,
	 value1,
	 value3,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 116,
	 value1,
	 value3,
	 value4,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 120,
	 value0,
	 value1,
	 value3,
	 value2,
	 value4 );

	libfcrypto_serpent_calculate_forward_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 124,
	 value3,
	 value4,
	 value1,
	 value2,
	 value0 );

	value0 ^= internal_context->expanded_key[ 128 ];
	value1 ^= internal_context->expanded_key[ 129 ];
	value2 ^= internal_context->expanded_key[ 130 ];
	value3 ^= internal_context->expanded_key[ 131 ];

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 0 ] ),
	 value0 );

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 4 ] ),
	 value1 );

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 8 ] ),
	 value2 );

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 12 ] ),
	 value3 );

	return( 1 );
}

/* Decrypts a block of data using Serpent
 * The size must be a multitude of the Serpent block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_internal_serpent_context_decrypt_block(
     libfcrypto_internal_serpent_context_t *internal_context,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error  )
{
	static char *function = "libfcrypto_internal_serpent_context_decrypt_block";
	uint32_t value0       = 0;
	uint32_t value1       = 0;
	uint32_t value2       = 0;
	uint32_t value3       = 0;
	uint32_t value4       = 0;

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
	if( input_data_size < 16 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid input data size value too small.",
		 function );

		return( -1 );
	}
	if( input_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid input data size value exceeds maximum.",
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
	if( output_data_size < 16 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid output data size value too small.",
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
	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 0 ] ),
	 value0 );

	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 4 ] ),
	 value1 );

	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 8 ] ),
	 value2 );

	byte_stream_copy_to_uint32_little_endian(
	 &( input_data[ 12 ] ),
	 value3 );

	value0 ^= internal_context->expanded_key[ 128 ];
	value1 ^= internal_context->expanded_key[ 129 ];
	value2 ^= internal_context->expanded_key[ 130 ];
	value3 ^= internal_context->expanded_key[ 131 ];

	libfcrypto_serpent_calculate_reverse_substitution7(
	 value0,
	 value1,
	 value2,
	 value3,
	 value4 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 4 * 31,
	 value1,
	 value3,
	 value0,
	 value4,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 4 * 30,
	 value0,
	 value2,
	 value4,
	 value1,
	 value3 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 4 * 29,
	 value2,
	 value3,
	 value0,
	 value4,
	 value1 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 4 * 28,
	 value2,
	 value0,
	 value1,
	 value4,
	 value3 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 4 * 27,
	 value1,
	 value2,
	 value3,
	 value4,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 4 * 26,
	 value2,
	 value0,
	 value4,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 4 * 25,
	 value1,
	 value0,
	 value4,
	 value3,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 4 * 24,
	 value4,
	 value2,
	 value0,
	 value1,
	 value3 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 4 * 23,
	 value2,
	 value1,
	 value4,
	 value3,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 4 * 22,
	 value4,
	 value0,
	 value3,
	 value2,
	 value1 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 4 * 21,
	 value0,
	 value1,
	 value4,
	 value3,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 4 * 20,
	 value0,
	 value4,
	 value2,
	 value3,
	 value1 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 4 * 19,
	 value2,
	 value0,
	 value1,
	 value3,
	 value4 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 4 * 18,
	 value0,
	 value4,
	 value3,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 4 * 17,
	 value2,
	 value4,
	 value3,
	 value1,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 4 * 16,
	 value3,
	 value0,
	 value4,
	 value2,
	 value1 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 4 * 15,
	 value0,
	 value2,
	 value3,
	 value1,
	 value4 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 4 * 14,
	 value3,
	 value4,
	 value1,
	 value0,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 4 * 13,
	 value4,
	 value2,
	 value3,
	 value1,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 4 * 12,
	 value4,
	 value3,
	 value0,
	 value1,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 4 * 11,
	 value0,
	 value4,
	 value2,
	 value1,
	 value3 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 4 * 10,
	 value4,
	 value3,
	 value1,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 4 * 9,
	 value0,
	 value3,
	 value1,
	 value2,
	 value4 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution7(
	 internal_context->expanded_key,
	 4 * 8,
	 value1,
	 value4,
	 value3,
	 value0,
	 value2 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution6(
	 internal_context->expanded_key,
	 4 * 7,
	 value4,
	 value0,
	 value1,
	 value2,
	 value3 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution5(
	 internal_context->expanded_key,
	 4 * 6,
	 value1,
	 value3,
	 value2,
	 value4,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution4(
	 internal_context->expanded_key,
	 4 * 5,
	 value3,
	 value0,
	 value1,
	 value2,
	 value4 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution3(
	 internal_context->expanded_key,
	 4 * 4,
	 value3,
	 value1,
	 value4,
	 value2,
	 value0 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution2(
	 internal_context->expanded_key,
	 4 * 3,
	 value4,
	 value3,
	 value0,
	 value2,
	 value1 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution1(
	 internal_context->expanded_key,
	 4 * 2,
	 value3,
	 value1,
	 value2,
	 value0,
	 value4 );

	libfcrypto_serpent_calculate_reverse_linear_transformation_and_substitution0(
	 internal_context->expanded_key,
	 4 * 1,
	 value4,
	 value1,
	 value2,
	 value0,
	 value3 );

	value2 ^= internal_context->expanded_key[ 0 ];
	value3 ^= internal_context->expanded_key[ 1 ];
	value1 ^= internal_context->expanded_key[ 2 ];
	value4 ^= internal_context->expanded_key[ 3 ];

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 0 ] ),
	 value2 );

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 4 ] ),
	 value3 );

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 8 ] ),
	 value1 );

	byte_stream_copy_from_uint32_little_endian(
	 &( output_data[ 12 ] ),
	 value4 );

	return( 1 );
}

/* De- or encrypts a block of data using Serpent-CBC (Cipher Block Chaining)
 * The size must be a multitude of the Serpent block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_serpent_crypt_cbc(
     libfcrypto_serpent_context_t *context,
     int mode,
     const uint8_t *initialization_vector,
     size_t initialization_vector_size,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error )
{
	uint8_t internal_initialization_vector[ 16 ];

	static char *function = "libfcrypto_serpent_context_crypt_cbc";
	size_t data_offset    = 0;

#if !defined( LIBFCRYPTO_UNFOLLED_LOOPS )
	uint8_t block_index   = 0;
#endif

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
	if( initialization_vector == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_INVALID_VALUE,
		 "%s: invalid initialization vector.",
		 function );

		return( -1 );
	}
	if( initialization_vector_size != 16 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_OUT_OF_BOUNDS,
		 "%s: invalid initialization vector size value out of bounds.",
		 function );

		return( -1 );
	}
	if( ( mode != LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT )
	 && ( mode != LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT ) )
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
	if( input_data_size > (size_t) SSIZE_MAX )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_EXCEEDS_MAXIMUM,
		 "%s: invalid input data size value exceeds maximum.",
		 function );

		return( -1 );
	}
	if( input_data_size < 16 )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_VALUE_TOO_SMALL,
		 "%s: invalid input data size value too small.",
		 function );

		return( -1 );
	}
	/* Check if the input data size is a multitude of 16-byte
	 */
	if( ( input_data_size & (size_t) 0x0f ) != 0 )
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
	if( memory_copy(
	     internal_initialization_vector,
	     initialization_vector,
	     16 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
		 "%s: unable to copy initialization vector.",
		 function );

		goto on_error;
	}
	if( ( mode == LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT )
	 && ( output_data != input_data ) )
	{
		if( memory_copy(
		     output_data,
		     input_data,
		     input_data_size ) == NULL )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_MEMORY,
			 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
			 "%s: unable to copy input data to output data.",
			 function );

			goto on_error;
		}
	}
	while( data_offset <= ( input_data_size - 16 ) )
	{
		if( mode == LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT )
		{
#if defined( LIBFCRYPTO_UNFOLLED_LOOPS )
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 0 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 1 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 2 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 3 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 4 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 5 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 6 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 7 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 8 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 9 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 10 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 11 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 12 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 13 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 14 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 15 ];
#else
			for( block_index = 0;
			     block_index < 16;
			     block_index++ )
			{
				output_data[ data_offset++ ] ^= internal_initialization_vector[ block_index ];
			}
#endif
			data_offset -= 16;

			if( libfcrypto_internal_serpent_context_encrypt_block(
			     (libfcrypto_internal_serpent_context_t *) context,
			     &( input_data[ data_offset ] ),
			     16,
			     &( output_data[ data_offset ] ),
			     16,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to encrypt input data.",
				 function );

				goto on_error;
			}
			if( memory_copy(
			     internal_initialization_vector,
			     &( output_data[ data_offset ] ),
			     16 ) == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
				 "%s: unable to copy enrypted output data to initialization vector.",
				 function );

				goto on_error;
			}
		}
		else
		{
			if( libfcrypto_internal_serpent_context_decrypt_block(
			     (libfcrypto_internal_serpent_context_t *) context,
			     &( input_data[ data_offset ] ),
			     16,
			     &( output_data[ data_offset ] ),
			     16,
			     error ) != 1 )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
				 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
				 "%s: unable to decrypt input data.",
				 function );

				goto on_error;
			}
#if defined( LIBFCRYPTO_UNFOLLED_LOOPS )
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 0 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 1 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 2 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 3 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 4 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 5 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 6 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 7 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 8 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 9 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 10 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 11 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 12 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 13 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 14 ];
			output_data[ data_offset++ ] ^= internal_initialization_vector[ 15 ];
#else
			for( block_index = 0;
			     block_index < 16;
			     block_index++ )
			{
				output_data[ data_offset++ ] ^= internal_initialization_vector[ block_index ];
			}
#endif
			data_offset -= 16;

			if( memory_copy(
			     internal_initialization_vector,
			     &( input_data[ data_offset ] ),
			     16 ) == NULL )
			{
				libcerror_error_set(
				 error,
				 LIBCERROR_ERROR_DOMAIN_MEMORY,
				 LIBCERROR_MEMORY_ERROR_COPY_FAILED,
				 "%s: unable to copy enrypted input data to initialization vector.",
				 function );

				goto on_error;
			}
		}
		data_offset += 16;
	}
	if( memory_set(
	     internal_initialization_vector,
	     0,
	     16 ) == NULL )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_MEMORY,
		 LIBCERROR_MEMORY_ERROR_SET_FAILED,
		 "%s: unable to clear initialization vector.",
		 function );

		goto on_error;
	}
	return( 1 );

on_error:
	memory_set(
	 internal_initialization_vector,
	 0,
	 16 );

	return( -1 );
}

/* De- or encrypts a block of data using Serpent-ECB (Electronic CodeBook)
 * The size must be a multitude of the Serpent block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
int libfcrypto_serpent_crypt_ecb(
     libfcrypto_serpent_context_t *context,
     int mode,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error )
{
	static char *function = "libfcrypto_serpent_context_crypt_ecb";

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
	if( ( mode != LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT )
	 && ( mode != LIBFCRYPTO_SERPENT_CRYPT_MODE_DECRYPT ) )
	{
		libcerror_error_set(
		 error,
		 LIBCERROR_ERROR_DOMAIN_ARGUMENTS,
		 LIBCERROR_ARGUMENT_ERROR_UNSUPPORTED_VALUE,
		 "%s: unsupported mode.",
		 function );

		return( -1 );
	}
	if( mode == LIBFCRYPTO_SERPENT_CRYPT_MODE_ENCRYPT )
	{
		if( libfcrypto_internal_serpent_context_encrypt_block(
		     (libfcrypto_internal_serpent_context_t *) context,
		     input_data,
		     input_data_size,
		     output_data,
		     output_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
			 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
			 "%s: unable to encrypt input data.",
			 function );

			return( -1 );
		}
	}
	else
	{
		if( libfcrypto_internal_serpent_context_decrypt_block(
		     (libfcrypto_internal_serpent_context_t *) context,
		     input_data,
		     input_data_size,
		     output_data,
		     output_data_size,
		     error ) != 1 )
		{
			libcerror_error_set(
			 error,
			 LIBCERROR_ERROR_DOMAIN_ENCRYPTION,
			 LIBCERROR_ENCRYPTION_ERROR_GENERIC,
			 "%s: unable to decrypt input data.",
			 function );

			return( -1 );
		}
	}
	return( 1 );
}

