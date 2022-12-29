/*
 * Python object wrapper of libfcrypto_des3_context_t
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

#if !defined( _PYFCRYPTO_DES3_CONTEXT_H )
#define _PYFCRYPTO_DES3_CONTEXT_H

#include <common.h>
#include <types.h>

#include "pyfcrypto_libfcrypto.h"
#include "pyfcrypto_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pyfcrypto_des3_context pyfcrypto_des3_context_t;

struct pyfcrypto_des3_context
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libfcrypto des3 context
	 */
	libfcrypto_des3_context_t *des3_context;
};

extern PyMethodDef pyfcrypto_des3_context_object_methods[];
extern PyTypeObject pyfcrypto_des3_context_type_object;

PyObject *pyfcrypto_des3_context_new(
           void );

int pyfcrypto_des3_context_init(
     pyfcrypto_des3_context_t *pyfcrypto_des3_context );

void pyfcrypto_des3_context_free(
      pyfcrypto_des3_context_t *pyfcrypto_des3_context );

PyObject *pyfcrypto_des3_context_set_key(
           pyfcrypto_des3_context_t *pyfcrypto_des3_context,
           PyObject *arguments,
           PyObject *keywords );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYFCRYPTO_DES3_CONTEXT_H ) */

