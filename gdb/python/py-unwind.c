/* Python frame unwinder interface

   Copyright (C) 2013-2014 Free Software Foundation, Inc.

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
#include "arch-utils.h"
#include "frame-unwind.h"
#include "gdb_obstack.h"
#include "gdbcmd.h"
#include "language.h"
#include "observer.h"
#include "python-internal.h"
#include "regcache.h"
#include "user-regs.h"

#define TRACE_PY_UNWIND(level, args...) if (pyuw_debug >= level)  \
  { fprintf_unfiltered (gdb_stdlog, args); }

typedef struct
{
  PyObject_HEAD
  struct frame_info *frame_info;
} sniffer_info_object;

/* The data we keep for a frame we can unwind: frame_id and an array of
   (register_number, register_value) pairs.  */

typedef struct
{
  struct frame_id frame_id;
  struct gdbarch *gdbarch;
  int reg_count;
  struct reg_info
  {
    int number;
    gdb_byte *data;
  } reg[];
} cached_frame_info;

static PyTypeObject sniffer_info_object_type
    CPYCHECKER_TYPE_OBJECT_FOR_TYPEDEF ("sniffer_info_object");

static unsigned int pyuw_debug = 0;

static struct gdbarch_data *pyuw_gdbarch_data;

/* Called by the Python interpreter to obtain string representation
   of the SnifferInfo object.  */

static PyObject *
sniffer_infopy_str (PyObject *self)
{
  char *s;
  PyObject *result;
  struct frame_info *frame = ((sniffer_info_object *)self)->frame_info;

  s = xstrprintf ("SP=%s,PC=%s", core_addr_to_string_nz (get_frame_sp (frame)),
        core_addr_to_string_nz (get_frame_pc (frame)));
  result = PyString_FromString (s);
  xfree (s);

  return result;
}

/* Implementation of gdb.SnifferInfo.read_register (self, regnum) -> gdb.Value.
   Returns the value of a register as pointer.  */

static PyObject *
sniffer_infopy_read_register (PyObject *self, PyObject *args)
{
  volatile struct gdb_exception except;
  int regnum;
  struct value *val = NULL;

  if (!PyArg_ParseTuple (args, "i", &regnum))
    return NULL;

  TRY_CATCH (except, RETURN_MASK_ALL)
    {
      /* Cannot call `value_of_register' as frame_info is not ready yet, so
         use deprecated call instead.  */
      struct frame_info *frame = ((sniffer_info_object *)self)->frame_info;
      struct gdbarch *gdbarch = get_frame_arch (frame);
      gdb_byte buffer[sizeof (CORE_ADDR)];

      gdb_assert (register_size (gdbarch, regnum) <= ARRAY_SIZE (buffer));
      if (deprecated_frame_register_read (frame, regnum, buffer))
        {
          struct type *ptr_type = builtin_type (gdbarch)->builtin_data_ptr;

          val = value_from_pointer (ptr_type, unpack_pointer (ptr_type, buffer));
        }

      if (val == NULL)
        PyErr_SetString (PyExc_ValueError, _("Unknown register."));
    }
  GDB_PY_HANDLE_EXCEPTION (except);

  return val == NULL ? NULL : value_to_value_object (val);
}

/* Create Python SnifferInfo object.  */

static PyObject *
frame_info_to_sniffer_info_object (struct frame_info *frame)
{
  sniffer_info_object *sniffer_info
      = PyObject_New (sniffer_info_object, &sniffer_info_object_type);

  if (sniffer_info != NULL)
    sniffer_info->frame_info = frame;

  return (PyObject *) sniffer_info;
}

/* Parse given tuple of Python Ints into an array. Returns the number of
   items in the tuple, or -1 if it is not a tuple. If tuple has
   more elements than array size, these elements are ignored.  */

static Py_ssize_t
pyuw_parse_ints (PyObject *pyo_sequence, int *values, Py_ssize_t max_values)
{
  Py_ssize_t size;
  Py_ssize_t i;

  if (! PyTuple_Check (pyo_sequence))
    return -1;
  size = PyTuple_Size (pyo_sequence);
  if (size < 0)
    return -1;
  if (size < max_values)
    max_values = size;
  for (i = 0; i < max_values; ++i)
    {
      PyObject *pyo_item = PyTuple_GetItem (pyo_sequence, i);

      if (pyo_item == NULL || !PyInt_Check (pyo_item))
        return -1;
      values[i] = (int)PyInt_AsLong (pyo_item);
    }
  return i;
}

/* Retrieve register value for the cached unwind info as target pointer.
   Return 1 on success, 0 on failure.  */

static int
pyuw_reg_value (cached_frame_info *cached_frame, int regnum, CORE_ADDR *value)
{
  struct reg_info *reg_info = cached_frame->reg;
  struct reg_info *reg_info_end = reg_info + cached_frame->reg_count;

  for (; reg_info < reg_info_end; ++reg_info)
    {
      if (reg_info->number == regnum)
        {
          *value = unpack_pointer
              (register_type (cached_frame->gdbarch, regnum), reg_info->data);
          return 1;
        }
    }

  error (_("Python sniffer uses register #%d for this_id, "
           "but this register is not available"), regnum);
}

/* frame_unwind.this_id method.  */

static void
pyuw_this_id (struct frame_info *this_frame, void **cache_ptr,
              struct frame_id *this_id)
{
  *this_id = ((cached_frame_info *)*cache_ptr)->frame_id;
  if (pyuw_debug >= 1)
    {
      fprintf_unfiltered (gdb_stdlog, "%s: frame_id: ", __FUNCTION__);
      fprint_frame_id (gdb_stdlog, *this_id);
      fprintf_unfiltered (gdb_stdlog, "\n");
    }
}

/* Register unwind shim.  */

static struct value *
pyuw_prev_register (struct frame_info *this_frame, void **cache_ptr, int regnum)
{
  cached_frame_info *cached_frame = *cache_ptr;
  struct reg_info *reg_info = cached_frame->reg;
  struct reg_info *reg_info_end = reg_info + cached_frame->reg_count;

  TRACE_PY_UNWIND (1, "%s(frame=%p,...,reg=%d)\n", __FUNCTION__, this_frame,
                   regnum);
  for (; reg_info < reg_info_end; ++reg_info)
    if (regnum == reg_info->number)
      return frame_unwind_got_bytes (this_frame, regnum, reg_info->data);

  return frame_unwind_got_optimized (this_frame, regnum);
}

/* Parse frame ID tuple returned by the sniffer info GDB's frame_id and
   saved it in the cached frame.  */

static void
pyuw_parse_frame_id (cached_frame_info *cached_frame, 
                     PyObject *pyo_frame_id_regs)
{
  int regno[3];
  CORE_ADDR sp, pc, special;

  if (!PyTuple_Check (pyo_frame_id_regs))
    error (_("The second element of the pair returned by a Python "
             "sniffer should be a tuple"));

  switch (pyuw_parse_ints (pyo_frame_id_regs, regno, ARRAY_SIZE (regno))) {
  case 1:
    if (pyuw_reg_value (cached_frame, regno[0], &sp))
      {
        cached_frame->frame_id = frame_id_build_wild (sp);
        return;
      }
  case 2:
    if (pyuw_reg_value (cached_frame, regno[0], &sp)
        || pyuw_reg_value (cached_frame, regno[1], &pc))
      {
        cached_frame->frame_id = frame_id_build (sp, pc); 
        return;
      }
  case 3:
    if (pyuw_reg_value (cached_frame, regno[0], &sp)
        || pyuw_reg_value (cached_frame, regno[1], &pc)
        || pyuw_reg_value (cached_frame, regno[2], &special))
      {
        cached_frame->frame_id = frame_id_build_special (sp, pc, special);
        return;
      }
  }
  error (_("Unwinder should return a tuple of ints in the second item"));
}

/* Frame sniffer dispatch.  */

static int
pyuw_sniffer (const struct frame_unwind *self, struct frame_info *this_frame,
              void **cache_ptr)
{
  struct gdbarch *gdbarch;
  struct cleanup *cleanups;
  struct cleanup *cached_frame_cleanups;
  PyObject *pyo_module;
  PyObject *pyo_execute;
  PyObject *pyo_sniffer_info;
  PyObject *pyo_unwind_info;
  cached_frame_info *cached_frame = NULL;

  gdb_assert (*cache_ptr == NULL);
  gdbarch = (void *)(self->unwind_data);
  cleanups = ensure_python_env (gdbarch, current_language);
  TRACE_PY_UNWIND (3, "%s(SP=%lx, PC=%lx)\n", __FUNCTION__,
      get_frame_sp (this_frame), get_frame_pc (this_frame));
  pyo_sniffer_info = frame_info_to_sniffer_info_object (this_frame);
  if (pyo_sniffer_info == NULL)
    goto error;
  make_cleanup_py_decref (pyo_sniffer_info);

  if ((pyo_module = PyImport_ImportModule ("gdb.sniffers")) == NULL)
    goto error;
  make_cleanup_py_decref (pyo_module);

  pyo_execute = PyObject_GetAttrString (pyo_module, "execute_sniffers");
  if (pyo_execute == NULL)
    goto error;
  make_cleanup_py_decref (pyo_execute);

  pyo_unwind_info
      = PyObject_CallFunctionObjArgs (pyo_execute, pyo_sniffer_info, NULL);
  if (pyo_unwind_info == NULL)
    goto error;
  if (pyo_unwind_info == Py_None)
    goto error;
  make_cleanup_py_decref (pyo_unwind_info);

  /* Unwind_info is a pair (REGISTERS, FRAME_ID_REGNUMS).  REGISTERS
   * is a list of the (REG_NR, REG_VALUE) pairs. FRAME_ID_REGNUMS is
   * the list of REGNO values.  */
  if (!(PyTuple_Check (pyo_unwind_info) && PyTuple_Size (pyo_unwind_info) == 2))
    error (_("Sniffer should return a pair (REGISTERS, FRAME_ID_REGNUMS)"));

  {
    PyObject *pyo_registers = PyTuple_GetItem (pyo_unwind_info, 0);
    int i;
    int reg_count;
    size_t cached_frame_size;
    size_t gdb_bytes_count;
    gdb_byte *gdb_data_free, *gdb_data_end;

    if (pyo_registers == NULL)
      goto error;
    if (!PyTuple_Check (pyo_registers))
      error (_("The first element of the returned pair should be a tuple"));

    /* Figure out how much space we need to allocate.  */
    reg_count = PyTuple_Size (pyo_registers);
    if (reg_count <= 0)
      error (_("Register list should not be empty"));
    gdb_bytes_count = reg_count * sizeof (CORE_ADDR);
    cached_frame_size = sizeof (*cached_frame) +
        reg_count * sizeof (cached_frame->reg[0]) +
        gdb_bytes_count * sizeof (gdb_byte);

    cached_frame = xmalloc (cached_frame_size);
    cached_frame_cleanups = make_cleanup (xfree, cached_frame);
    gdb_data_end = (gdb_byte *)((char *)cached_frame + cached_frame_size);
    gdb_data_free = gdb_data_end - gdb_bytes_count;

    cached_frame->gdbarch = gdbarch;
    cached_frame->reg_count = reg_count;

    /* Populate registers array.  */
    for (i = 0; i < reg_count; i++)
    {
      PyObject *pyo_reg = PyTuple_GetItem (pyo_registers, i);
      struct reg_info *reg = &(cached_frame->reg[i]);

      if (pyo_reg == NULL)
        goto error;

      if (!(PyTuple_Check (pyo_reg) && PyTuple_Size (pyo_reg) == 2))
        error (_("Python sniffer returned bad register list: "
                 "item #%d is not a (reg_no, reg_data) pair"), i);

      {
        PyObject *pyo_reg_number =  PyTuple_GetItem (pyo_reg, 0);

        if (pyo_reg_number == NULL)
          goto error;
        if (!PyInt_Check (pyo_reg_number))
          error (_("Python sniffer returned bad register list: "
                   "item #%d contains non-integer register number"), i);
        reg->number = (int)PyInt_AsLong (pyo_reg_number);
      }

      {
        PyObject *pyo_reg_value = PyTuple_GetItem (pyo_reg, 1);
        struct value *value;
        size_t data_size;

        if (pyo_reg_value == NULL)
          goto error;

        if ((value = value_object_to_value (pyo_reg_value)) == NULL)
          error (_("Python sniffer returned bad register list: item #%d, "
                   "register value should have type gdb.Value type"), i);
        data_size = register_size (gdbarch, reg->number);
        gdb_assert ((gdb_data_free + data_size) <= gdb_data_end);
        memcpy (gdb_data_free, value_contents (value), data_size);
        cached_frame->reg[i].data = gdb_data_free;
        gdb_data_free += data_size;
      }
    }
  }

  {
    PyObject *pyo_frame_id_regs = PyTuple_GetItem (pyo_unwind_info, 1);
    if (pyo_frame_id_regs == NULL)
      goto error;
    pyuw_parse_frame_id (cached_frame, pyo_frame_id_regs);
  }

  *cache_ptr = cached_frame;
  discard_cleanups (cached_frame_cleanups);
  do_cleanups (cleanups);
  return 1;

error:
  do_cleanups (cleanups);
  xfree (cached_frame);
  return 0;
}

/* Frame cache release shim.  */

static void
pyuw_dealloc_cache (struct frame_info *this_frame, void *cache)
{
  TRACE_PY_UNWIND (3, "%s: enter", __FUNCTION__);
  xfree (cache);
}

struct pyuw_gdbarch_data_type
{
  /* Has the unwinder shim been prepended? */
  int unwinder_registered;
};

static void *
pyuw_gdbarch_data_init (struct gdbarch *gdbarch)
{
  return GDBARCH_OBSTACK_ZALLOC (gdbarch, struct pyuw_gdbarch_data_type);
}

/* New inferior architecture callback: register the Python sniffers
   intermediary.  */

static void
pyuw_on_new_gdbarch (struct gdbarch *newarch)
{
  struct pyuw_gdbarch_data_type *data =
      gdbarch_data (newarch, pyuw_gdbarch_data);

  if (!data->unwinder_registered)
    {
      struct frame_unwind *unwinder
          = GDBARCH_OBSTACK_ZALLOC (newarch, struct frame_unwind);

      unwinder->type =  NORMAL_FRAME;
      unwinder->stop_reason = default_frame_unwind_stop_reason;
      unwinder->this_id = pyuw_this_id;
      unwinder->prev_register = pyuw_prev_register;
      unwinder->unwind_data = (void *)newarch;
      unwinder->sniffer = pyuw_sniffer;
      unwinder->dealloc_cache = pyuw_dealloc_cache;
      frame_unwind_prepend_unwinder (newarch, unwinder);
      TRACE_PY_UNWIND (1, "%s: registered unwinder for %s\n", __FUNCTION__,
                       gdbarch_bfd_arch_info (newarch)->printable_name);
      data->unwinder_registered = 1;
    }
}

/* Initialize unwind machinery.  */

int
gdbpy_initialize_unwind (void)
{
  add_setshow_zuinteger_cmd
      ("py-unwind", class_maintenance, &pyuw_debug,
        _("Set Python unwinder debugging."),
        _("Show Python unwinder debugging."),
        _("When non-zero, Pythin unwinder debugging is enabled."),
        NULL,
        NULL,
        &setdebuglist, &showdebuglist);
  pyuw_gdbarch_data
      = gdbarch_data_register_post_init (pyuw_gdbarch_data_init);
  observer_attach_architecture_changed (pyuw_on_new_gdbarch);
  sniffer_info_object_type.tp_new = PyType_GenericNew;
  if (PyType_Ready (&sniffer_info_object_type) < 0)
    return -1;
  return gdb_pymodule_addobject (gdb_module, "SnifferInfo",
      (PyObject *) &sniffer_info_object_type);
}

static PyMethodDef sniffer_info_object_methods[] =
{
  { "read_register", sniffer_infopy_read_register, METH_VARARGS,
    "read_register (register_name) -> gdb.Value\n\
Return the value of the register in the frame." },
  {NULL}  /* Sentinel */
};

static PyTypeObject sniffer_info_object_type =
{
  PyVarObject_HEAD_INIT (NULL, 0)
  "gdb.SnifferInfo",              /* tp_name */
  sizeof (sniffer_info_object),   /* tp_basicsize */
  0,                              /* tp_itemsize */
  0,                              /* tp_dealloc */
  0,                              /* tp_print */
  0,                              /* tp_getattr */
  0,                              /* tp_setattr */
  0,                              /* tp_compare */
  0,                              /* tp_repr */
  0,                              /* tp_as_number */
  0,                              /* tp_as_sequence */
  0,                              /* tp_as_mapping */
  0,                              /* tp_hash  */
  0,                              /* tp_call */
  sniffer_infopy_str,             /* tp_str */
  0,                              /* tp_getattro */
  0,                              /* tp_setattro */
  0,                              /* tp_as_buffer */
  Py_TPFLAGS_DEFAULT,             /* tp_flags */
  "GDB snifferInfo object",       /* tp_doc */
  0,                              /* tp_traverse */
  0,                              /* tp_clear */
  0,                              /* tp_richcompare */
  0,                              /* tp_weaklistoffset */
  0,                              /* tp_iter */
  0,                              /* tp_iternext */
  sniffer_info_object_methods,    /* tp_methods */
  0,                              /* tp_members */
  0,                              /* tp_getset */
  0,                              /* tp_base */
  0,                              /* tp_dict */
  0,                              /* tp_descr_get */
  0,                              /* tp_descr_set */
  0,                              /* tp_dictoffset */
  0,                              /* tp_init */
  0,                              /* tp_alloc */
};
