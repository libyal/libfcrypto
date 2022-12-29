/*
 * Python definition of the libfcrypto crypt functions
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

#include "pyfcrypto_des3_context.h"
#include "pyfcrypto_crypt.h"
#include "pyfcrypto_error.h"
#include "pyfcrypto_libfcrypto.h"
#include "pyfcrypto_python.h"
#include "pyfcrypto_rc4_context.h"
#include "pyfcrypto_unused.h"

/* De- or encrypts a block of data using DES3
 * Returns 1 if successful or -1 on error
 */
PyObject *pyfcrypto_crypt_des3(
           PyObject *self PYFCRYPTO_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *context_object                         = NULL;
	PyObject *input_data_string_object               = NULL;
	PyObject *output_data_string_object              = NULL;
	libcerror_error_t *error                         = NULL;
	pyfcrypto_des3_context_t *pyfcrypto_des3_context = NULL;
	static char *function                            = "pyfcrypto_crypt_des3";
	char *input_data                                 = NULL;
	static char *keyword_list[]                      = { "context", "mode", "data", NULL };
	char *output_data                                = NULL;
        Py_ssize_t input_data_size                       = 0;
	int mode                                         = 0;
	int result                                       = 0;

	PYFCRYPTO_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OiO",
	     keyword_list,
	     &context_object,
	     &mode,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pyfcrypto_des3_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pyfcrypto_des3_context = (pyfcrypto_des3_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libfcrypto_des3_crypt(
	          pyfcrypto_des3_context->des3_context,
	          mode,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyfcrypto_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

/* De- or encrypts a block of data using RC4
 * Returns 1 if successful or -1 on error
 */
PyObject *pyfcrypto_crypt_rc4(
           PyObject *self PYFCRYPTO_ATTRIBUTE_UNUSED,
           PyObject *arguments,
           PyObject *keywords )
{
	PyObject *context_object                       = NULL;
	PyObject *input_data_string_object             = NULL;
	PyObject *output_data_string_object            = NULL;
	libcerror_error_t *error                       = NULL;
	pyfcrypto_rc4_context_t *pyfcrypto_rc4_context = NULL;
	static char *function                          = "pyfcrypto_crypt_rc4";
	char *input_data                               = NULL;
	static char *keyword_list[]                    = { "context", "data", NULL };
	char *output_data                              = NULL;
        Py_ssize_t input_data_size                     = 0;
	int result                                     = 0;

	PYFCRYPTO_UNREFERENCED_PARAMETER( self )

	if( PyArg_ParseTupleAndKeywords(
	     arguments,
	     keywords,
	     "OO",
	     keyword_list,
	     &context_object,
	     &input_data_string_object ) == 0 )
	{
		return( NULL );
	}
	result = PyObject_IsInstance(
	          context_object,
	          (PyObject *) &pyfcrypto_rc4_context_type_object );

	if( result == -1 )
	{
		return( NULL );
	}
	else if( result != 1 )
	{
		PyErr_Format(
		 PyExc_TypeError,
		 "%s: unsupported type of argument context value.",
		 function );

		return( NULL );
	}
	pyfcrypto_rc4_context = (pyfcrypto_rc4_context_t *) context_object;

#if PY_MAJOR_VERSION >= 3
	input_data = PyBytes_AsString(
	              input_data_string_object );

	input_data_size = PyBytes_Size(
	                   input_data_string_object );
#else
	input_data = PyString_AsString(
	              input_data_string_object );

	input_data_size = PyString_Size(
	                   input_data_string_object );
#endif
	if( ( input_data_size < 0 )
	 || ( input_data_size > (Py_ssize_t) SSIZE_MAX ) )
	{
		PyErr_Format(
		 PyExc_ValueError,
		 "%s: invalid argument input data size value out of bounds.",
		 function );

		return( NULL );
	}
#if PY_MAJOR_VERSION >= 3
	output_data_string_object = PyBytes_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyBytes_AsString(
	               output_data_string_object );
#else
	output_data_string_object = PyString_FromStringAndSize(
	                             NULL,
	                             input_data_size );

	output_data = PyString_AsString(
	               output_data_string_object );
#endif
	Py_BEGIN_ALLOW_THREADS

	result = libfcrypto_rc4_crypt(
	          pyfcrypto_rc4_context->rc4_context,
	          (uint8_t *) input_data,
	          (size_t) input_data_size,
	          (uint8_t *) output_data,
	          (size_t) input_data_size,
	          &error );

	Py_END_ALLOW_THREADS

	if( result != 1 )
	{
		pyfcrypto_error_raise(
		 error,
		 PyExc_IOError,
		 "%s: unable to crypt data.",
		 function );

		libcerror_error_free(
		 &error );

		Py_DecRef(
		 (PyObject *) output_data_string_object );

		return( NULL );
	}
	return( output_data_string_object );
}

