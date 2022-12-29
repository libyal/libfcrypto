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

#include <common.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pyfcrypto_error.h"
#include "pyfcrypto_libfcrypto.h"
#include "pyfcrypto_libcerror.h"
#include "pyfcrypto_python.h"
#include "pyfcrypto_des3_context.h"
#include "pyfcrypto_unused.h"

PyMethodDef pyfcrypto_des3_context_object_methods[] = {

	{ "set_key",
	  (PyCFunction) pyfcrypto_des3_context_set_key,
	  METH_VARARGS | METH_KEYWORDS,
	  "set_key(key) -> None\n"
	  "\n"
	  "Sets the key." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

PyGetSetDef pyfcrypto_des3_context_object_get_set_definitions[] = {

	/* Sentinel */
	{ NULL, NULL, NULL, NULL, NULL }
};

PyTypeObject pyfcrypto_des3_context_type_object = {
	PyVarObject_HEAD_INIT( NULL, 0 )

	/* tp_name */
	"pyfcrypto.des3_context",
	/* tp_basicsize */
	sizeof( pyfcrypto_des3_context_t ),
	/* tp_itemsize */
	0,
	/* tp_dealloc */
	(destructor) pyfcrypto_des3_context_free,
	/* tp_print */
	0,
	/* tp_getattr */
	0,
	/* tp_setattr */
	0,
	/* tp_compare */
	0,
	/* tp_repr */
	0,
	/* tp_as_number */
	0,
	/* tp_as_sequence */
	0,
	/* tp_as_mapping */
	0,
	/* tp_hash */
	0,
	/* tp_call */
	0,
	/* tp_str */
	0,
	/* tp_getattro */
	0,
	/* tp_setattro */
	0,
	/* tp_as_buffer */
	0,
	/* tp_flags */
	Py_TPFLAGS_DEFAULT,
	/* tp_doc */
	"pyfcrypto des3 context object (wraps libfcrypto_des3_context_t)",
	/* tp_traverse */
	0,
	/* tp_clear */
	0,
	/* tp_richcompare */
	0,
	/* tp_weaklistoffset */
	0,
	/* tp_iter */
	0,
	/* tp_iternext */
	0,
	/* tp_methods */
	pyfcrypto_des3_context_object_methods,
	/* tp_members */
	0,
	/* tp_getset */
	pyfcrypto_des3_context_object_get_set_definitions,
	/* tp_base */
	0,
	/* tp_dict */
	0,
	/* tp_descr_get */
	0,
	/* tp_descr_set */
	0,
	/* tp_dictoffset */
	0,
	/* tp_init */
	(initproc) pyfcrypto_des3_context_init,
	/* tp_alloc */
	0,
	/* tp_new */
	0,
	/* tp_free */
	0,
	/* tp_is_gc */
	0,
	/* tp_bases */
	NULL,
	/* tp_mro */
	NULL,
	/* tp_cache */
	NULL,
	/* tp_subclasses */
	NULL,
	/* tp_weaklist */
	NULL,
	/* tp_del */
	0
};

/* Creates a new des3 context object
 * Returns a Python object if successful or NULL on error
 */
PyObject *pyfcrypto_des3_context_new(
           void )
{
	pyfcrypto_des3_context_t *pyfcrypto_des3_context = NULL;
	static char *function                            = "pyfcrypto_des3_context_new";

	pyfcrypto_des3_context = PyObject_New(
	                          struct pyfcrypto_des3_context,
	                          &pyfcrypto_des3_context_type_object );

	if( pyfcrypto_des3_context == NULL )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize des3 context.",
		 function );

		goto on_error;
	}
	if( pyfcrypto_des3_context_init(
	     pyfcrypto_des3_context ) != 0 )
	{
		PyErr_Format(
		 PyExc_MemoryError,
		 "%s: unable to initialize des3 context.",
		 function );

		goto on_error;
	}
	return( (PyObject *) pyfcrypto_des3_context );

on_error:
	if( pyfcrypto_des3_context != NULL )
	{
		Py_DecRef(
		 (PyObject *) pyfcrypto_des3_context );
	}
	return( NULL );
}

/* Initializes a des3 context object
 * Returns 0 if successful or -1 on error
 */
int pyfcrypto_des3_context_init(
     pyfcrypto_des3_context_t *pyfcrypto_des3_context )
{
	libcerror_error_t *error = NULL;
	static char *function    = "pyfcrypto_des3_context_init";

	if( pyfcrypto_des3_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid des3 context.",
		 function );

		return( -1 );
	}
	pyfcrypto_des3_context->des3_context = NULL;

	if( libfcrypto_des3_context_initialize(
	     &( pyfcrypto_des3_context->des3_context ),
	     &error ) != 1 )
	{
		pyfcrypto_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to initialize des3 context.",
		 function );

		libcerror_error_free(
		 &error );

		return( -1 );
	}
	return( 0 );
}

/* Frees a des3 context object
 */
void pyfcrypto_des3_context_free(
      pyfcrypto_des3_context_t *pyfcrypto_des3_context )
{
	struct _typeobject *ob_type = NULL;
	libcerror_error_t *error    = NULL;
	static char *function       = "pyfcrypto_des3_context_free";
	int result                  = 0;

	if( pyfcrypto_des3_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid des3 context.",
		 function );

		return;
	}
	if( pyfcrypto_des3_context->des3_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid des3 context - missing libfcrypto des3 context.",
		 function );

		return;
	}
	ob_type = Py_TYPE(
	           pyfcrypto_des3_context );

	if( ob_type == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: missing ob_type.",
		 function );

		return;
	}
	if( ob_type->tp_free == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid ob_type - missing tp_free.",
		 function );

		return;
	}
	Py_BEGIN_ALLOW_THREADS

	result = libfcrypto_des3_context_free(
	          &( pyfcrypto_des3_context->des3_context ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyfcrypto_error_raise(
		 error,
		 PyExc_MemoryError,
		 "%s: unable to free libfcrypto des3 context.",
		 function );

		libcerror_error_free(
		 &error );
	}
	ob_type->tp_free(
	 (PyObject*) pyfcrypto_des3_context );
}

/* Sets the key
 * Returns a Python object if successful or NULL on error
 */
PyObject *pyfcrypto_des3_context_set_key(
           pyfcrypto_des3_context_t *pyfcrypto_des3_context,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *key_string_object = NULL;
	libcerror_error_t *error    = NULL;
	static char *function       = "pyfcrypto_des3_context_set_key";
	char *key_data              = NULL;
	static char *keyword_list[] = { "key", NULL };
	Py_ssize_t key_data_size    = 0;
	int result                  = 0;

	if( pyfcrypto_des3_context == NULL )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid des3 context.",
		 function );

		return( NULL );
	}
	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "O",
	     keyword_list,
	     &key_string_object ) == 0 )
	{
		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	key_data = PyBytes_AsString(
	            key_string_object );

	key_data_size = PyBytes_Size(
	                 key_string_object );
#else
	key_data = PyString_AsString(
	            key_string_object );

	key_data_size = PyString_Size(
	                 key_string_object );
#endif
	if( ( key_data_size < 0 )
	 || ( key_data_size > (Py_ssize_t) ( SSIZE_MAX / 8 ) ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid key data size value out of bounds.",
		 function );

		return( NULL );
	}
	Py_BEGIN_ALLOW_THREADS

	result = libfcrypto_des3_context_set_key(
	          pyfcrypto_des3_context->des3_context,
	          (uint8_t *) key_data,
	          (size_t) ( key_data_size * 8 ),
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyfcrypto_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to set key.",
		 function );

		libcerror_error_free(
		 &error );

		return( NULL );
	}
	Py_IncRef(
	 Py_None );

	return( Py_None );
}

