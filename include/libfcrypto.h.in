/*
 * Library to support the GUID/UUID format
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

#if !defined( _LIBFCRYPTO_H )
#define _LIBFCRYPTO_H

#include <libfcrypto/definitions.h>
#include <libfcrypto/error.h>
#include <libfcrypto/extern.h>
#include <libfcrypto/features.h>
#include <libfcrypto/types.h>

#include <stdio.h>

#if defined( __cplusplus )
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * Support functions
 * ------------------------------------------------------------------------- */

/* Returns the library version
 */
LIBFCRYPTO_EXTERN \
const char *libfcrypto_get_version(
             void );

/* -------------------------------------------------------------------------
 * Error functions
 * ------------------------------------------------------------------------- */

/* Frees an error
 */
LIBFCRYPTO_EXTERN \
void libfcrypto_error_free(
      libfcrypto_error_t **error );

/* Prints a descriptive string of the error to the stream
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_error_fprint(
     libfcrypto_error_t *error,
     FILE *stream );

/* Prints a descriptive string of the error to the string
 * The end-of-string character is not included in the return value
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_error_sprint(
     libfcrypto_error_t *error,
     char *string,
     size_t size );

/* Prints a backtrace of the error to the stream
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_error_backtrace_fprint(
     libfcrypto_error_t *error,
     FILE *stream );

/* Prints a backtrace of the error to the string
 * The end-of-string character is not included in the return value
 * Returns the amount of printed characters if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_error_backtrace_sprint(
     libfcrypto_error_t *error,
     char *string,
     size_t size );

/* -------------------------------------------------------------------------
 * DES3 context functions
 * ------------------------------------------------------------------------- */

/* Creates a DES3 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_des3_context_initialize(
     libfcrypto_des3_context_t **context,
     libfcrypto_error_t **error );

/* Frees a DES3 context
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_des3_context_free(
     libfcrypto_des3_context_t **context,
     libfcrypto_error_t **error );

/* Sets the key
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_des3_context_set_key(
     libfcrypto_des3_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libfcrypto_error_t **error );

/* De- or encrypts a buffer of data using DES3
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_des3_crypt(
     libfcrypto_des3_context_t *context,
     int mode,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libfcrypto_error_t **error );

/* -------------------------------------------------------------------------
 * RC4 context functions
 * ------------------------------------------------------------------------- */

/* Creates a RC4 context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_context_initialize(
     libfcrypto_rc4_context_t **context,
     libfcrypto_error_t **error );

/* Frees a RC4 context
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_context_free(
     libfcrypto_rc4_context_t **context,
     libfcrypto_error_t **error );

/* Sets the key
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_context_set_key(
     libfcrypto_rc4_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libfcrypto_error_t **error );

/* De- or encrypts a buffer of data using RC4
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_crypt(
     libfcrypto_rc4_context_t *context,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libfcrypto_error_t **error );

/* -------------------------------------------------------------------------
 * Serpent context functions
 * ------------------------------------------------------------------------- */

/* Creates a Serpent context
 * Make sure the value context is referencing, is set to NULL
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_serpent_context_initialize(
     libfcrypto_serpent_context_t **context,
     libfcrypto_error_t **error );

/* Frees a Serpent context
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_serpent_context_free(
     libfcrypto_serpent_context_t **context,
     libfcrypto_error_t **error );

/* Sets the key
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_serpent_context_set_key(
     libfcrypto_serpent_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libfcrypto_error_t **error );

/* De- or encrypts a block of data using Serpent-CBC (Cipher Block Chaining)
 * The size must be a multitude of the Serpent block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_serpent_crypt_cbc(
     libfcrypto_serpent_context_t *context,
     int mode,
     const uint8_t *initialization_vector,
     size_t initialization_vector_size,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libfcrypto_error_t **error );

/* De- or encrypts a block of data using Serpent-ECB (Electronic CodeBook)
 * The size must be a multitude of the Serpent block size (16 byte)
 * Returns 1 if successful or -1 on error
 */
LIBFCRYPTO_EXTERN \
int libfcrypto_serpent_crypt_ecb(
     libfcrypto_serpent_context_t *context,
     int mode,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libfcrypto_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFCRYPTO_H ) */

