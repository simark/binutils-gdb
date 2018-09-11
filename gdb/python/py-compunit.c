/* Python interface to compilation units (compunit_symtab).

   Copyright (C) 2018 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "python-internal.h"
#include "block.h"
#include "objfiles.h"

struct compunit_object
{
  PyObject_HEAD
  /* The corresponding GDB compilation unit.  */
  compunit_symtab *cu;
  /* A compunit_symtab object is associated with an objfile, so keep track with
     a doubly-linked list, rooted in the objfile.  This allows invalidation of
     the underlying compunit when the objfile is deleted.  */
  struct compunit_object *prev;
  struct compunit_object *next;
};

extern PyTypeObject compunit_object_type;
static const struct objfile_data *cupy_objfile_data_key;

/* Require a valid symbol table.  All access to compunit_object->cu
   should be gated by this call.  */
#define CUPY_REQUIRE_VALID(compunit_obj, compunit)		  \
  do {								  \
    compunit = compunit_object_to_compunit_symtab (compunit_obj); \
    if (compunit == NULL)					  \
      {								  \
	PyErr_SetString (PyExc_RuntimeError,			  \
			 _("Compilation Unit is invalid."));	  \
	return NULL;						  \
      }								  \
  } while (0)

/* Return the compunit_symtab that is wrapped by this object.  */
static compunit_symtab *
compunit_object_to_compunit_symtab (PyObject *obj)
{
  if (!PyObject_TypeCheck (obj, &compunit_object_type))
    return NULL;
  return ((compunit_object *) obj)->cu;
}

/* Create a new gdb.CompilationUnit object that encapsulates the
   compunit_symtab structure from GDB.  */
gdbpy_ref<>
compunit_symtab_to_compunit_object (compunit_symtab *cu)
{
  struct objfile *objfile = COMPUNIT_OBJFILE (cu);
  compunit_object *cu_head = (compunit_object *) objfile_data (objfile, cupy_objfile_data_key);

  for (compunit_object *cu_obj = cu_head; cu_obj != nullptr; cu_obj = cu_obj->next)
    {
      if (cu_obj->cu == cu)
	return gdbpy_ref<>::new_reference ((PyObject *) cu_obj);
    }

  compunit_object *cu_obj = PyObject_New (compunit_object, &compunit_object_type);
  if (cu_obj == nullptr)
    return nullptr;

  cu_obj->cu = cu;


  cu_obj->next = cu_head;
  if (cu_head != nullptr)
    cu_head->prev = cu_obj;

  set_objfile_data (objfile, cupy_objfile_data_key, cu_obj);

  return gdbpy_ref<>::new_reference ((PyObject *) cu_obj);
}

static PyObject *
cupy_get_objfile (PyObject *self, void *closure)
{
  compunit_symtab *cu = NULL;

  CUPY_REQUIRE_VALID (self, cu);

  return objfile_to_objfile_object (COMPUNIT_OBJFILE (cu)).release ();
}

/* Getter function for symtab.producer.  */

static PyObject *
cupy_get_producer (PyObject *self, void *closure)
{
  struct compunit_symtab *cu;

  CUPY_REQUIRE_VALID (self, cu);

  if (COMPUNIT_PRODUCER (cu) != nullptr)
    {
      const char *producer = COMPUNIT_PRODUCER (cu);

      return host_string_to_python_string (producer);
    }

  Py_RETURN_NONE;
}

static PyObject *
cupy_get_symtabs (PyObject *self, PyObject *args)
{
  struct compunit_symtab *cu;

  CUPY_REQUIRE_VALID (self, cu);

  gdbpy_ref<> list (PyList_New (0));

  symtab *s;
  ALL_COMPUNIT_FILETABS (cu, s)
    {
      PyObject *s_obj = symtab_to_symtab_object (s);
      if (s_obj == nullptr)
	return nullptr;

      PyList_Append (list.get (), s_obj);
    }

  return list.release ();
}

/* Implementation of gdb.Symtab.is_valid (self) -> Boolean.
   Returns True if this Symbol table still exists in GDB.  */

static PyObject *
cupy_is_valid (PyObject *self, PyObject *args)
{
  compunit_symtab *cu = compunit_object_to_compunit_symtab (self);
  if (cu == nullptr)
    Py_RETURN_FALSE;

  Py_RETURN_TRUE;
}

/* Return the GLOBAL_BLOCK of the underlying compunit_symtab.  */

static PyObject *
cupy_global_block (PyObject *self, PyObject *args)
{
  compunit_symtab *cu;

  CUPY_REQUIRE_VALID (self, cu);

  const blockvector *bv = COMPUNIT_BLOCKVECTOR (cu);
  block *b = BLOCKVECTOR_BLOCK (bv, GLOBAL_BLOCK);
  return block_to_block_object (b, COMPUNIT_OBJFILE (cu));
}

/* Return the STATIC_BLOCK of the underlying compunit_symtab.  */

static PyObject *
cupy_static_block (PyObject *self, PyObject *args)
{
  compunit_symtab *cu;

  CUPY_REQUIRE_VALID (self, cu);

  const blockvector *bv = COMPUNIT_BLOCKVECTOR (cu);
  block *b = BLOCKVECTOR_BLOCK (bv, STATIC_BLOCK);
  return block_to_block_object (b, COMPUNIT_OBJFILE (cu));
}

static PyObject *
cupy_str (PyObject *self)
{
  compunit_symtab *cu = compunit_object_to_compunit_symtab (self);

  if (cu == nullptr)
    return PyString_FromString ("<gdb.CompilationUnit invalid>");

  return PyString_FromFormat ("<gdb.CompilationUnit name=%s>", cu->name);
}

static void
cupy_dealloc (PyObject *self_)
{
  compunit_object *self = (compunit_object *) self_;

  if (self->prev != nullptr)
    self->prev->next = self->next;
  else if (self->cu != nullptr)
    {
      set_objfile_data (COMPUNIT_OBJFILE (self->cu),
			cupy_objfile_data_key, self->next);
    }

  if (self->next != nullptr)
    self->next->prev = self->prev;
  self->cu = nullptr;
}

/* This function is called when an objfile is about to be freed.
   Invalidate the compunit  as further actions on it would result
   in bad data.  All access to cu_obj->cu should be
   gated by CUPY_REQUIRE_VALID which will raise an exception on
   invalid compunits.  */
static void
del_objfile_compunit (struct objfile *objfile, void *datum)
{
  compunit_object *cu_obj = (compunit_object *) datum;

  while (cu_obj != nullptr)
    {
      compunit_object *next = cu_obj->next;

      cu_obj->cu = nullptr;
      cu_obj->next = nullptr;
      cu_obj->prev = nullptr;
      cu_obj = next;
    }
}

int
gdbpy_initialize_compunits (void)
{
  compunit_object_type.tp_new = PyType_GenericNew;
  if (PyType_Ready (&compunit_object_type) < 0)
    return -1;

  /* Register an objfile "free" callback so we can properly
     invalidate compunit objects when an object file is about to be
     deleted.  */
  cupy_objfile_data_key
    = register_objfile_data_with_cleanup (NULL, del_objfile_compunit);

  return gdb_pymodule_addobject (gdb_module, "CompilationUnit",
				 (PyObject *) &compunit_object_type);
}

static gdb_PyGetSetDef compunit_object_getset[] = {
  { "objfile", cupy_get_objfile, NULL, "The compilation unit's objfile.",
    NULL },
  { "producer", cupy_get_producer, NULL,
    "The name/version of the program that compiled this symtab.", NULL },
  {NULL}  /* Sentinel */
};

static PyMethodDef compunit_object_methods[] = {
  { "symtabs", cupy_get_symtabs, METH_NOARGS, "" },
  { "is_valid", cupy_is_valid, METH_NOARGS,
    "is_valid () -> Boolean.\n\
Return true if this compilation unit is valid, false if not." },
  { "global_block", cupy_global_block, METH_NOARGS,
    "global_block () -> gdb.Block.\n\
Return the global block of the symbol table." },
  { "static_block", cupy_static_block, METH_NOARGS,
    "static_block () -> gdb.Block.\n\
Return the static block of the symbol table." },
  {NULL}  /* Sentinel */
};

PyTypeObject compunit_object_type = {
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.CompilationUnit",		  /*tp_name*/
  sizeof (compunit_object),	  /*tp_basicsize*/
  0,				  /*tp_itemsize*/
  cupy_dealloc,			  /*tp_dealloc*/
  0,				  /*tp_print*/
  0,				  /*tp_getattr*/
  0,				  /*tp_setattr*/
  0,				  /*tp_compare*/
  0,				  /*tp_repr*/
  0,				  /*tp_as_number*/
  0,				  /*tp_as_sequence*/
  0,				  /*tp_as_mapping*/
  0,				  /*tp_hash */
  0,				  /*tp_call*/
  cupy_str,			  /*tp_str*/
  0,				  /*tp_getattro*/
  0,				  /*tp_setattro*/
  0,				  /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT,		  /*tp_flags*/
  "GDB compilation unit object",  /*tp_doc */
  0,				  /*tp_traverse */
  0,				  /*tp_clear */
  0,				  /*tp_richcompare */
  0,				  /*tp_weaklistoffset */
  0,				  /*tp_iter */
  0,				  /*tp_iternext */
  compunit_object_methods,	  /*tp_methods */
  0,				  /*tp_members */
  compunit_object_getset	  /*tp_getset */
};
