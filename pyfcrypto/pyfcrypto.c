/*
 * Python bindings module for libfcrypto (pyfcrypto)
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
#include <narrow_string.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( HAVE_WINAPI )
#include <stdlib.h>
#endif

#include "pyfcrypto.h"
#include "pyfcrypto_des3_context.h"
#include "pyfcrypto_crypt.h"
#include "pyfcrypto_crypt_modes.h"
#include "pyfcrypto_error.h"
#include "pyfcrypto_libcerror.h"
#include "pyfcrypto_libfcrypto.h"
#include "pyfcrypto_python.h"
#include "pyfcrypto_rc4_context.h"
#include "pyfcrypto_unused.h"

/* The pyfcrypto module methods
 */
PyMethodDef pyfcrypto_module_methods[] = {
	{ "get_version",
	  (PyCFunction) pyfcrypto_get_version,
	  METH_NOARGS,
	  "get_version() -> String\n"
	  "\n"
	  "Retrieves the version." },

	{ "crypt_des3",
	  (PyCFunction) pyfcrypto_crypt_des3,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_des3(context, mode, data) -> Bytes\n"
	  "\n"
	  "De- or encrypts a block of data using 3DES." },

	{ "crypt_rc4",
	  (PyCFunction) pyfcrypto_crypt_rc4,
	  METH_VARARGS | METH_KEYWORDS,
	  "crypt_rc4(context, data) -> Bytes\n"
	  "\n"
	  "De- or encrypts a block of data using RC4." },

	/* Sentinel */
	{ NULL, NULL, 0, NULL }
};

/* Retrieves the pyfcrypto/libfcrypto version
 * Returns a Python object if successful or NULL on error
 */
PyObject *pyfcrypto_get_version(
           PyObject *self PYFCRYPTO_ATTRIBUTE_UNUSED,
           PyObject *arguments PYFCRYPTO_ATTRIBUTE_UNUSED )
{
	const char *errors           = NULL;
	const char *version_string   = NULL;
	size_t version_string_length = 0;

	PYFCRYPTO_UNREFERENCED_PARAMETER( self )
	PYFCRYPTO_UNREFERENCED_PARAMETER( arguments )

	Py_BEGIN_ALLOW_THREADS

	version_string = libfcrypto_get_version();

	Py_END_ALLOW_THREADS

	version_string_length = narrow_string_length(
	                         version_string );

	/* Pass the string length to PyUnicode_DecodeUTF8
	 * otherwise it makes the end of string character is part
	 * of the string
	 */
	return( PyUnicode_DecodeUTF8(
	         version_string,
	         (Py_ssize_t) version_string_length,
	         errors ) );
}

#if PY_MAJOR_VERSION >= 3

/* The pyfcrypto module definition
 */
PyModuleDef pyfcrypto_module_definition = {
	PyModuleDef_HEAD_INIT,

	/* m_name */
	"pyfcrypto",
	/* m_doc */
	"Python libfcrypto module (pyfcrypto).",
	/* m_size */
	-1,
	/* m_methods */
	pyfcrypto_module_methods,
	/* m_reload */
	NULL,
	/* m_traverse */
	NULL,
	/* m_clear */
	NULL,
	/* m_free */
	NULL,
};

#endif /* PY_MAJOR_VERSION >= 3 */

/* Initializes the pyfcrypto module
 */
#if PY_MAJOR_VERSION >= 3
PyMODINIT_FUNC PyInit_pyfcrypto(
                void )
#else
PyMODINIT_FUNC initpyfcrypto(
                void )
#endif
{
	PyObject *module           = NULL;
	PyGILState_STATE gil_state = 0;

#if defined( HAVE_DEBUG_OUTPUT )
	libfcrypto_notify_set_stream(
	 stderr,
	 NULL );
	libfcrypto_notify_set_verbose(
	 1 );
#endif

	/* Create the module
	 * This function must be called before grabbing the GIL
	 * otherwise the module will segfault on a version mismatch
	 */
#if PY_MAJOR_VERSION >= 3
	module = PyModule_Create(
	          &pyfcrypto_module_definition );
#else
	module = Py_InitModule3(
	          "pyfcrypto",
	          pyfcrypto_module_methods,
	          "Python libfcrypto module (pyfcrypto)." );
#endif
	if( module == NULL )
	{
#if PY_MAJOR_VERSION >= 3
		return( NULL );
#else
		return;
#endif
	}
#if PY_VERSION_HEX < 0x03070000
	PyEval_InitThreads();
#endif
	gil_state = PyGILState_Ensure();

	/* Setup the crypt modes type object
	 */
	pyfcrypto_crypt_modes_type_object.tp_new = PyType_GenericNew;

	if( pyfcrypto_crypt_modes_init_type(
	     &pyfcrypto_crypt_modes_type_object ) != 1 )
	{
		goto on_error;
	}
	if( PyType_Ready(
	     &pyfcrypto_crypt_modes_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pyfcrypto_crypt_modes_type_object );

	PyModule_AddObject(
	 module,
	 "crypt_modes",
	 (PyObject *) &pyfcrypto_crypt_modes_type_object );

	/* Setup the DES3 context type object
	 */
	pyfcrypto_des3_context_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pyfcrypto_des3_context_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pyfcrypto_des3_context_type_object );

	PyModule_AddObject(
	 module,
	 "des3_context",
	 (PyObject *) &pyfcrypto_des3_context_type_object );

	/* Setup the RC4 context type object
	 */
	pyfcrypto_rc4_context_type_object.tp_new = PyType_GenericNew;

	if( PyType_Ready(
	     &pyfcrypto_rc4_context_type_object ) < 0 )
	{
		goto on_error;
	}
	Py_IncRef(
	 (PyObject *) &pyfcrypto_rc4_context_type_object );

	PyModule_AddObject(
	 module,
	 "rc4_context",
	 (PyObject *) &pyfcrypto_rc4_context_type_object );

	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( module );
#else
	return;
#endif

on_error:
	PyGILState_Release(
	 gil_state );

#if PY_MAJOR_VERSION >= 3
	return( NULL );
#else
	return;
#endif
}

