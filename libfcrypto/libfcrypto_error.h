/*
 * Error functions
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

#if !defined( _LIBFCRYPTO_INTERNAL_ERROR_H )
#define _LIBFCRYPTO_INTERNAL_ERROR_H

#include <common.h>
#include <file_stream.h>
#include <types.h>

#if !defined( HAVE_LOCAL_LIBFCRYPTO )
#include <libfcrypto/error.h>
#endif

#include "libfcrypto_extern.h"

#if defined( __cplusplus )
extern "C" {
#endif

#if !defined( HAVE_LOCAL_LIBFCRYPTO )

LIBFCRYPTO_EXTERN \
void libfcrypto_error_free(
      libfcrypto_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_error_fprint(
     libfcrypto_error_t *error,
     FILE *stream );

LIBFCRYPTO_EXTERN \
int libfcrypto_error_sprint(
     libfcrypto_error_t *error,
     char *string,
     size_t size );

LIBFCRYPTO_EXTERN \
int libfcrypto_error_backtrace_fprint(
     libfcrypto_error_t *error,
     FILE *stream );

LIBFCRYPTO_EXTERN \
int libfcrypto_error_backtrace_sprint(
     libfcrypto_error_t *error,
     char *string,
     size_t size );

#endif /* !defined( HAVE_LOCAL_LIBFCRYPTO ) */

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFCRYPTO_INTERNAL_ERROR_H ) */

