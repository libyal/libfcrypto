/*
 * Python object wrapper of libfcrypto_serpent_context_t
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

#if !defined( _PYFCRYPTO_SERPENT_CONTEXT_H )
#define _PYFCRYPTO_SERPENT_CONTEXT_H

#include <common.h>
#include <types.h>

#include "pyfcrypto_libfcrypto.h"
#include "pyfcrypto_python.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct pyfcrypto_serpent_context pyfcrypto_serpent_context_t;

struct pyfcrypto_serpent_context
{
	/* Python object initialization
	 */
	PyObject_HEAD

	/* The libfcrypto Serpent context
	 */
	libfcrypto_serpent_context_t *serpent_context;
};

extern PyMethodDef pyfcrypto_serpent_context_object_methods[];
extern PyTypeObject pyfcrypto_serpent_context_type_object;

PyObject *pyfcrypto_serpent_context_new(
           void );

int pyfcrypto_serpent_context_init(
     pyfcrypto_serpent_context_t *pyfcrypto_serpent_context );

void pyfcrypto_serpent_context_free(
      pyfcrypto_serpent_context_t *pyfcrypto_serpent_context );

PyObject *pyfcrypto_serpent_context_set_key(
           pyfcrypto_serpent_context_t *pyfcrypto_serpent_context,
           PyObject *arguments,
           PyObject *keywords );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _PYFCRYPTO_SERPENT_CONTEXT_H ) */

