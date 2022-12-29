/*
 * Python object definition of the libfcrypto crypt modes
 *
 * Copyright (C) 2011-2022, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _PYFCRYPTO_CRYPT_MODES_H )
#define _PYFCRYPTO_CRYPT_MODES_H

#include <common.h>
#include <types.h>

#include "pyfcrypto_libfcrypto.h"
#include "pyfcrypto_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pyfcrypto_crypt_modes pyfcrypto_crypt_modes_t;

struct pyfcrypto_crypt_modes
{
	/* Python object initialization
	 */
	PyObject_HEAD
};

extern PyTypeObject pyfcrypto_crypt_modes_type_object;

int pyfcrypto_crypt_modes_init_type(
     PyTypeObject *type_object );

PyObject *pyfcrypto_crypt_modes_new(
           void );

int pyfcrypto_crypt_modes_init(
     pyfcrypto_crypt_modes_t *definitions_object );

void pyfcrypto_crypt_modes_free(
      pyfcrypto_crypt_modes_t *definitions_object );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYFCRYPTO_CRYPT_MODES_H ) */

