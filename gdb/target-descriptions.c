/* Target description support for GDB.

   Copyright (C) 2006-2020 Free Software Foundation, Inc.

   Contributed by CodeSourcery.

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
#include "gdbcmd.h"
#include "gdbtypes.h"
#include "reggroups.h"
#include "target.h"
#include "target-descriptions.h"
#include "xml-support.h"
#include "xml-tdesc.h"
#include "osabi.h"

#include "gdb_obstack.h"
#include "hashtab.h"
#include "inferior.h"
#include <algorithm>
#include "completer.h"
#include "readline/tilde.h" /* tilde_expand */

/* Types.  */

struct property
{
  property (const std::string &key_, const std::string &value_)
  : key (key_), value (value_)
  {}

  std::string key;
  std::string value;
};

/* Convert a tdesc_type to a gdb type.  */

static type *
make_gdb_type (struct gdbarch *gdbarch, struct tdesc_type *ttype)
{
  class gdb_type_creator : public tdesc_element_visitor
  {
  public:
    gdb_type_creator (struct gdbarch *gdbarch)
      : m_gdbarch (gdbarch)
    {}

    type *get_type ()
    {
      return m_type;
    }

    void visit (const tdesc_type_builtin *e) override
    {
      switch (e->kind)
	{
	  /* Predefined types.  */
	case TDESC_TYPE_BOOL:
	  m_type = builtin_type (m_gdbarch)->builtin_bool;
	  return;
	case TDESC_TYPE_INT8:
	  m_type = builtin_type (m_gdbarch)->builtin_int8;
	  return;
	case TDESC_TYPE_INT16:
	  m_type = builtin_type (m_gdbarch)->builtin_int16;
	  return;
	case TDESC_TYPE_INT32:
	  m_type = builtin_type (m_gdbarch)->builtin_int32;
	  return;
	case TDESC_TYPE_INT64:
	  m_type = builtin_type (m_gdbarch)->builtin_int64;
	  return;
	case TDESC_TYPE_INT128:
	  m_type = builtin_type (m_gdbarch)->builtin_int128;
	  return;
	case TDESC_TYPE_UINT8:
	  m_type = builtin_type (m_gdbarch)->builtin_uint8;
	  return;
	case TDESC_TYPE_UINT16:
	  m_type = builtin_type (m_gdbarch)->builtin_uint16;
	  return;
	case TDESC_TYPE_UINT32:
	  m_type = builtin_type (m_gdbarch)->builtin_uint32;
	  return;
	case TDESC_TYPE_UINT64:
	  m_type = builtin_type (m_gdbarch)->builtin_uint64;
	  return;
	case TDESC_TYPE_UINT128:
	  m_type = builtin_type (m_gdbarch)->builtin_uint128;
	  return;
	case TDESC_TYPE_CODE_PTR:
	  m_type = builtin_type (m_gdbarch)->builtin_func_ptr;
	  return;
	case TDESC_TYPE_DATA_PTR:
	  m_type = builtin_type (m_gdbarch)->builtin_data_ptr;
	  return;
	}

      m_type = tdesc_find_type (m_gdbarch, e->name.c_str ());
      if (m_type != NULL)
	return;

      switch (e->kind)
	{
	case TDESC_TYPE_IEEE_HALF:
	  m_type = arch_float_type (m_gdbarch, -1, "builtin_type_ieee_half",
				    floatformats_ieee_half);
	  return;

	case TDESC_TYPE_IEEE_SINGLE:
	  m_type = arch_float_type (m_gdbarch, -1, "builtin_type_ieee_single",
				    floatformats_ieee_single);
	  return;

	case TDESC_TYPE_IEEE_DOUBLE:
	  m_type = arch_float_type (m_gdbarch, -1, "builtin_type_ieee_double",
				    floatformats_ieee_double);
	  return;
	case TDESC_TYPE_ARM_FPA_EXT:
	  m_type = arch_float_type (m_gdbarch, -1, "builtin_type_arm_ext",
				    floatformats_arm_ext);
	  return;

	case TDESC_TYPE_I387_EXT:
	  m_type = arch_float_type (m_gdbarch, -1, "builtin_type_i387_ext",
				    floatformats_i387_ext);
	  return;
	}

      internal_error (__FILE__, __LINE__,
		      "Type \"%s\" has an unknown kind %d",
		      e->name.c_str (), e->kind);
    }

    void visit (const tdesc_type_vector *e) override
    {
      m_type = tdesc_find_type (m_gdbarch, e->name.c_str ());
      if (m_type != NULL)
	return;

      type *element_gdb_type = make_gdb_type (m_gdbarch, e->element_type);
      m_type = init_vector_type (element_gdb_type, e->count);
      m_type->set_name (xstrdup (e->name.c_str ()));
      return;
    }

    void visit (const tdesc_type_with_fields *e) override
    {
      m_type = tdesc_find_type (m_gdbarch, e->name.c_str ());
      if (m_type != NULL)
	return;

      switch (e->kind)
	{
	case TDESC_TYPE_STRUCT:
	  make_gdb_type_struct (e);
	  return;
	case TDESC_TYPE_UNION:
	  make_gdb_type_union (e);
	  return;
	case TDESC_TYPE_FLAGS:
	  make_gdb_type_flags (e);
	  return;
	case TDESC_TYPE_ENUM:
	  make_gdb_type_enum (e);
	  return;
	}

      internal_error (__FILE__, __LINE__,
		      "Type \"%s\" has an unknown kind %d",
		      e->name.c_str (), e->kind);
    }

  private:

    void make_gdb_type_struct (const tdesc_type_with_fields *e)
    {
      m_type = arch_composite_type (m_gdbarch, NULL, TYPE_CODE_STRUCT);
      m_type->set_name (xstrdup (e->name.c_str ()));

      for (const tdesc_type_field &f : e->fields)
	{
	  if (f.start != -1 && f.end != -1)
	    {
	      /* Bitfield.  */
	      struct field *fld;
	      struct type *field_gdb_type;
	      int bitsize, total_size;

	      /* This invariant should be preserved while creating types.  */
	      gdb_assert (e->size != 0);
	      if (f.type != NULL)
		field_gdb_type = make_gdb_type (m_gdbarch, f.type);
	      else if (e->size > 4)
		field_gdb_type = builtin_type (m_gdbarch)->builtin_uint64;
	      else
		field_gdb_type = builtin_type (m_gdbarch)->builtin_uint32;

	      fld = append_composite_type_field_raw
		      (m_type, xstrdup (f.name.c_str ()), field_gdb_type);

	      /* For little-endian, BITPOS counts from the LSB of
		 the structure and marks the LSB of the field.  For
		 big-endian, BITPOS counts from the MSB of the
		 structure and marks the MSB of the field.  Either
		 way, it is the number of bits to the "left" of the
		 field.  To calculate this in big-endian, we need
		 the total size of the structure.  */
	      bitsize = f.end - f.start + 1;
	      total_size = e->size * TARGET_CHAR_BIT;
	      if (gdbarch_byte_order (m_gdbarch) == BFD_ENDIAN_BIG)
		SET_FIELD_BITPOS (fld[0], total_size - f.start - bitsize);
	      else
		SET_FIELD_BITPOS (fld[0], f.start);
	      fld->set_bitsize (bitsize);
	    }
	  else
	    {
	      gdb_assert (f.start == -1 && f.end == -1);
	      type *field_gdb_type = make_gdb_type (m_gdbarch, f.type);
	      append_composite_type_field (m_type,
					   xstrdup (f.name.c_str ()),
					   field_gdb_type);
	    }
	}

      if (e->size != 0)
	m_type->set_length (e->size);
    }

    void make_gdb_type_union (const tdesc_type_with_fields *e)
    {
      m_type = arch_composite_type (m_gdbarch, NULL, TYPE_CODE_UNION);
      m_type->set_name (xstrdup (e->name.c_str ()));

      for (const tdesc_type_field &f : e->fields)
	{
	  type* field_gdb_type = make_gdb_type (m_gdbarch, f.type);
	  append_composite_type_field (m_type, xstrdup (f.name.c_str ()),
				       field_gdb_type);

	  /* If any of the children of a union are vectors, flag the
	     union as a vector also.  This allows e.g. a union of two
	     vector types to show up automatically in "info vector".  */
	  if (TYPE_VECTOR (field_gdb_type))
	    m_type->set_is_vector (true);
	}
    }

    void make_gdb_type_flags (const tdesc_type_with_fields *e)
    {
      m_type = arch_flags_type (m_gdbarch, e->name.c_str (),
				e->size * TARGET_CHAR_BIT);

      for (const tdesc_type_field &f : e->fields)
	{
	  int bitsize = f.end - f.start + 1;

	  gdb_assert (f.type != NULL);
	  type *field_gdb_type = make_gdb_type (m_gdbarch, f.type);
	  append_flags_type_field (m_type, f.start, bitsize,
				   field_gdb_type, f.name.c_str ());
	}
    }

    void make_gdb_type_enum (const tdesc_type_with_fields *e)
    {
      m_type = arch_type (m_gdbarch, TYPE_CODE_ENUM, e->size * TARGET_CHAR_BIT,
			  e->name.c_str ());

      m_type->set_is_unsigned (true);

      for (const tdesc_type_field &f : e->fields)
	{
	  struct field *fld
	    = append_composite_type_field_raw (m_type,
					       xstrdup (f.name.c_str ()),
					       NULL);

	  SET_FIELD_BITPOS (fld[0], f.start);
	}
    }

    /* The gdbarch used.  */
    struct gdbarch *m_gdbarch;

    /* The type created.  */
    type *m_type;
  };

  gdb_type_creator gdb_type (gdbarch);
  ttype->accept (gdb_type);
  return gdb_type.get_type ();
}

/* A target description.  */

struct target_desc : tdesc_element
{
  target_desc ()
  {}

  virtual ~target_desc () = default;

  target_desc (const target_desc &) = delete;
  void operator= (const target_desc &) = delete;

  /* The architecture reported by the target, if any.  */
  const struct bfd_arch_info *arch = NULL;

  /* The osabi reported by the target, if any; GDB_OSABI_UNKNOWN
     otherwise.  */
  enum gdb_osabi osabi = GDB_OSABI_UNKNOWN;

  /* The list of compatible architectures reported by the target.  */
  std::vector<const bfd_arch_info *> compatible;

  /* Any architecture-specific properties specified by the target.  */
  std::vector<property> properties;

  /* The features associated with this target.  */
  std::vector<tdesc_feature_up> features;

  /* Used to cache the generated xml version of the target description.  */
  mutable char *xmltarget = nullptr;

  void accept (tdesc_element_visitor &v) const override
  {
    v.visit_pre (this);

    for (const tdesc_feature_up &feature : features)
      feature->accept (v);

    v.visit_post (this);
  }

  bool operator== (const target_desc &other) const
  {
    if (arch != other.arch)
      return false;

    if (osabi != other.osabi)
      return false;

    if (features.size () != other.features.size ())
      return false;

    for (int ix = 0; ix < features.size (); ix++)
      {
	const tdesc_feature_up &feature1 = features[ix];
	const tdesc_feature_up &feature2 = other.features[ix];

	if (feature1 != feature2 && *feature1 != *feature2)
	  return false;
      }

    return true;
  }

  bool operator!= (const target_desc &other) const
  {
    return !(*this == other);
  }
};

/* Per-architecture data associated with a target description.  The
   target description may be shared by multiple architectures, but
   this data is private to one gdbarch.  */

struct tdesc_arch_reg
{
  tdesc_arch_reg (tdesc_reg *reg_, struct type *type_)
  : reg (reg_), type (type_)
  {}

  struct tdesc_reg *reg;
  struct type *type;
};

struct tdesc_arch_data
{
  /* A list of register/type pairs, indexed by GDB's internal register number.
     During initialization of the gdbarch this list is used to store
     registers which the architecture assigns a fixed register number.
     Registers which are NULL in this array, or off the end, are
     treated as zero-sized and nameless (i.e. placeholders in the
     numbering).  */
  std::vector<tdesc_arch_reg> arch_regs;

  /* Functions which report the register name, type, and reggroups for
     pseudo-registers.  */
  gdbarch_register_name_ftype *pseudo_register_name = NULL;
  gdbarch_register_type_ftype *pseudo_register_type = NULL;
  gdbarch_register_reggroup_p_ftype *pseudo_register_reggroup_p = NULL;
};

/* Info about an inferior's target description.  There's one of these
   for each inferior.  */

struct target_desc_info
{
  /* A flag indicating that a description has already been fetched
     from the target, so it should not be queried again.  */

  int fetched;

  /* The description fetched from the target, or NULL if the target
     did not supply any description.  Only valid when
     target_desc_fetched is set.  Only the description initialization
     code should access this; normally, the description should be
     accessed through the gdbarch object.  */

  const struct target_desc *tdesc;

  /* The filename to read a target description from, as set by "set
     tdesc filename ..."  */

  char *filename;
};

/* Get the inferior INF's target description info, allocating one on
   the stop if necessary.  */

static struct target_desc_info *
get_tdesc_info (struct inferior *inf)
{
  if (inf->tdesc_info == NULL)
    inf->tdesc_info = XCNEW (struct target_desc_info);
  return inf->tdesc_info;
}

/* A handle for architecture-specific data associated with the
   target description (see struct tdesc_arch_data).  */

static struct gdbarch_data *tdesc_data;

/* See target-descriptions.h.  */

int
target_desc_info_from_user_p (struct target_desc_info *info)
{
  return info != NULL && info->filename != NULL;
}

/* See target-descriptions.h.  */

void
copy_inferior_target_desc_info (struct inferior *destinf, struct inferior *srcinf)
{
  struct target_desc_info *src = get_tdesc_info (srcinf);
  struct target_desc_info *dest = get_tdesc_info (destinf);

  dest->fetched = src->fetched;
  dest->tdesc = src->tdesc;
  dest->filename = src->filename != NULL ? xstrdup (src->filename) : NULL;
}

/* See target-descriptions.h.  */

void
target_desc_info_free (struct target_desc_info *tdesc_info)
{
  if (tdesc_info != NULL)
    {
      xfree (tdesc_info->filename);
      xfree (tdesc_info);
    }
}

/* Convenience helper macros.  */

#define target_desc_fetched \
  get_tdesc_info (current_inferior ())->fetched
#define current_target_desc \
  get_tdesc_info (current_inferior ())->tdesc
#define target_description_filename \
  get_tdesc_info (current_inferior ())->filename

/* The string manipulated by the "set tdesc filename ..." command.  */

static char *tdesc_filename_cmd_string;

/* Fetch the current target's description, and switch the current
   architecture to one which incorporates that description.  */

void
target_find_description (void)
{
  /* If we've already fetched a description from the target, don't do
     it again.  This allows a target to fetch the description early,
     during its to_open or to_create_inferior, if it needs extra
     information about the target to initialize.  */
  if (target_desc_fetched)
    return;

  /* The current architecture should not have any target description
     specified.  It should have been cleared, e.g. when we
     disconnected from the previous target.  */
  gdb_assert (gdbarch_target_desc (target_gdbarch ()) == NULL);

  /* First try to fetch an XML description from the user-specified
     file.  */
  current_target_desc = NULL;
  if (target_description_filename != NULL
      && *target_description_filename != '\0')
    current_target_desc
      = file_read_description_xml (target_description_filename);

  /* Next try to read the description from the current target using
     target objects.  */
  if (current_target_desc == NULL)
    current_target_desc = target_read_description_xml (current_top_target ());

  /* If that failed try a target-specific hook.  */
  if (current_target_desc == NULL)
    current_target_desc = target_read_description (current_top_target ());

  /* If a non-NULL description was returned, then update the current
     architecture.  */
  if (current_target_desc)
    {
      struct gdbarch_info info;

      gdbarch_info_init (&info);
      info.target_desc = current_target_desc;
      if (!gdbarch_update_p (info))
	warning (_("Architecture rejected target-supplied description"));
      else
	{
	  struct tdesc_arch_data *data;

	  data = ((struct tdesc_arch_data *)
		  gdbarch_data (target_gdbarch (), tdesc_data));
	  if (tdesc_has_registers (current_target_desc)
	      && data->arch_regs.empty ())
	    warning (_("Target-supplied registers are not supported "
		       "by the current architecture"));
	}
    }

  /* Now that we know this description is usable, record that we
     fetched it.  */
  target_desc_fetched = 1;
}

/* Discard any description fetched from the current target, and switch
   the current architecture to one with no target description.  */

void
target_clear_description (void)
{
  struct gdbarch_info info;

  if (!target_desc_fetched)
    return;

  target_desc_fetched = 0;
  current_target_desc = NULL;

  gdbarch_info_init (&info);
  if (!gdbarch_update_p (info))
    internal_error (__FILE__, __LINE__,
		    _("Could not remove target-supplied description"));
}

/* Return the global current target description.  This should only be
   used by gdbarch initialization code; most access should be through
   an existing gdbarch.  */

const struct target_desc *
target_current_description (void)
{
  if (target_desc_fetched)
    return current_target_desc;

  return NULL;
}

/* Return non-zero if this target description is compatible
   with the given BFD architecture.  */

int
tdesc_compatible_p (const struct target_desc *target_desc,
		    const struct bfd_arch_info *arch)
{
  for (const bfd_arch_info *compat : target_desc->compatible)
    {
      if (compat == arch
	  || arch->compatible (arch, compat)
	  || compat->compatible (compat, arch))
	return 1;
    }

  return 0;
}


/* Direct accessors for target descriptions.  */

/* Return the string value of a property named KEY, or NULL if the
   property was not specified.  */

const char *
tdesc_property (const struct target_desc *target_desc, const char *key)
{
  for (const property &prop : target_desc->properties)
    if (prop.key == key)
      return prop.value.c_str ();

  return NULL;
}

/* Return the BFD architecture associated with this target
   description, or NULL if no architecture was specified.  */

const struct bfd_arch_info *
tdesc_architecture (const struct target_desc *target_desc)
{
  return target_desc->arch;
}

/* See gdbsupport/tdesc.h.  */

const char *
tdesc_architecture_name (const struct target_desc *target_desc)
{
  return target_desc->arch->printable_name;
}

/* Return the OSABI associated with this target description, or
   GDB_OSABI_UNKNOWN if no osabi was specified.  */

enum gdb_osabi
tdesc_osabi (const struct target_desc *target_desc)
{
  return target_desc->osabi;
}

/* See gdbsupport/tdesc.h.  */

const char *
tdesc_osabi_name (const struct target_desc *target_desc)
{
  enum gdb_osabi osabi = tdesc_osabi (target_desc);
  if (osabi > GDB_OSABI_UNKNOWN && osabi < GDB_OSABI_INVALID)
    return gdbarch_osabi_name (osabi);
  return nullptr;
}

/* Return 1 if this target description includes any registers.  */

int
tdesc_has_registers (const struct target_desc *target_desc)
{
  if (target_desc == NULL)
    return 0;

  for (const tdesc_feature_up &feature : target_desc->features)
    if (!feature->registers.empty ())
      return 1;

  return 0;
}

/* Return the feature with the given name, if present, or NULL if
   the named feature is not found.  */

const struct tdesc_feature *
tdesc_find_feature (const struct target_desc *target_desc,
		    const char *name)
{
  for (const tdesc_feature_up &feature : target_desc->features)
    if (feature->name == name)
      return feature.get ();

  return NULL;
}

/* Return the name of FEATURE.  */

const char *
tdesc_feature_name (const struct tdesc_feature *feature)
{
  return feature->name.c_str ();
}

/* Lookup type associated with ID.  */

struct type *
tdesc_find_type (struct gdbarch *gdbarch, const char *id)
{
  tdesc_arch_data *data
    = (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

  for (const tdesc_arch_reg &reg : data->arch_regs)
    {
      if (reg.reg
	  && reg.reg->tdesc_type
	  && reg.type
	  && reg.reg->tdesc_type->name == id)
	return reg.type;
    }

  return NULL;
}

/* Support for registers from target descriptions.  */

/* Construct the per-gdbarch data.  */

static void *
tdesc_data_init (struct obstack *obstack)
{
  return obstack_new<tdesc_arch_data> (obstack);
}

/* Similar, but for the temporary copy used during architecture
   initialization.  */

struct tdesc_arch_data *
tdesc_data_alloc (void)
{
  return new tdesc_arch_data ();
}

/* Free something allocated by tdesc_data_alloc, if it is not going
   to be used (for instance if it was unsuitable for the
   architecture).  */

void
tdesc_data_cleanup (void *data_untyped)
{
  struct tdesc_arch_data *data = (struct tdesc_arch_data *) data_untyped;

  delete data;
}

/* Search FEATURE for a register named NAME.  */

static struct tdesc_reg *
tdesc_find_register_early (const struct tdesc_feature *feature,
			   const char *name)
{
  for (const tdesc_reg_up &reg : feature->registers)
    if (strcasecmp (reg->name.c_str (), name) == 0)
      return reg.get ();

  return NULL;
}

/* Search FEATURE for a register named NAME.  Assign REGNO to it.  */

int
tdesc_numbered_register (const struct tdesc_feature *feature,
			 struct tdesc_arch_data *data,
			 int regno, const char *name)
{
  struct tdesc_reg *reg = tdesc_find_register_early (feature, name);

  if (reg == NULL)
    return 0;

  /* Make sure the vector includes a REGNO'th element.  */
  while (regno >= data->arch_regs.size ())
    data->arch_regs.emplace_back (nullptr, nullptr);

  data->arch_regs[regno] = tdesc_arch_reg (reg, NULL);

  return 1;
}

/* Search FEATURE for a register named NAME, but do not assign a fixed
   register number to it.  */

int
tdesc_unnumbered_register (const struct tdesc_feature *feature,
			   const char *name)
{
  struct tdesc_reg *reg = tdesc_find_register_early (feature, name);

  if (reg == NULL)
    return 0;

  return 1;
}

/* Search FEATURE for a register whose name is in NAMES and assign
   REGNO to it.  */

int
tdesc_numbered_register_choices (const struct tdesc_feature *feature,
				 struct tdesc_arch_data *data,
				 int regno, const char *const names[])
{
  int i;

  for (i = 0; names[i] != NULL; i++)
    if (tdesc_numbered_register (feature, data, regno, names[i]))
      return 1;

  return 0;
}

/* Search FEATURE for a register named NAME, and return its size in
   bits.  The register must exist.  */

int
tdesc_register_bitsize (const struct tdesc_feature *feature, const char *name)
{
  struct tdesc_reg *reg = tdesc_find_register_early (feature, name);

  gdb_assert (reg != NULL);
  return reg->bitsize;
}

/* Look up a register by its GDB internal register number.  */

static struct tdesc_arch_reg *
tdesc_find_arch_register (struct gdbarch *gdbarch, int regno)
{
  struct tdesc_arch_data *data;

  data = (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);
  if (regno < data->arch_regs.size ())
    return &data->arch_regs[regno];
  else
    return NULL;
}

static struct tdesc_reg *
tdesc_find_register (struct gdbarch *gdbarch, int regno)
{
  struct tdesc_arch_reg *reg = tdesc_find_arch_register (gdbarch, regno);

  return reg? reg->reg : NULL;
}

/* Return the name of register REGNO, from the target description or
   from an architecture-provided pseudo_register_name method.  */

const char *
tdesc_register_name (struct gdbarch *gdbarch, int regno)
{
  struct tdesc_reg *reg = tdesc_find_register (gdbarch, regno);
  int num_regs = gdbarch_num_regs (gdbarch);

  if (reg != NULL)
    return reg->name.c_str ();

  if (regno >= num_regs && regno < gdbarch_num_cooked_regs (gdbarch))
    {
      struct tdesc_arch_data *data
	= (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

      gdb_assert (data->pseudo_register_name != NULL);
      return data->pseudo_register_name (gdbarch, regno);
    }

  return "";
}

struct type *
tdesc_register_type (struct gdbarch *gdbarch, int regno)
{
  struct tdesc_arch_reg *arch_reg = tdesc_find_arch_register (gdbarch, regno);
  struct tdesc_reg *reg = arch_reg? arch_reg->reg : NULL;
  int num_regs = gdbarch_num_regs (gdbarch);
  int num_pseudo_regs = gdbarch_num_pseudo_regs (gdbarch);

  if (reg == NULL && regno >= num_regs && regno < num_regs + num_pseudo_regs)
    {
      struct tdesc_arch_data *data
	= (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

      gdb_assert (data->pseudo_register_type != NULL);
      return data->pseudo_register_type (gdbarch, regno);
    }

  if (reg == NULL)
    /* Return "int0_t", since "void" has a misleading size of one.  */
    return builtin_type (gdbarch)->builtin_int0;

  if (arch_reg->type == NULL)
    {
      /* First check for a predefined or target defined type.  */
      if (reg->tdesc_type)
	arch_reg->type = make_gdb_type (gdbarch, reg->tdesc_type);

      /* Next try size-sensitive type shortcuts.  */
      else if (reg->type == "float")
	{
	  if (reg->bitsize == gdbarch_float_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_float;
	  else if (reg->bitsize == gdbarch_double_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_double;
	  else if (reg->bitsize == gdbarch_long_double_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_long_double;
	  else
	    {
	      warning (_("Register \"%s\" has an unsupported size (%d bits)"),
		       reg->name.c_str (), reg->bitsize);
	      arch_reg->type = builtin_type (gdbarch)->builtin_double;
	    }
	}
      else if (reg->type == "int")
	{
	  if (reg->bitsize == gdbarch_long_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_long;
	  else if (reg->bitsize == TARGET_CHAR_BIT)
	    arch_reg->type = builtin_type (gdbarch)->builtin_char;
	  else if (reg->bitsize == gdbarch_short_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_short;
	  else if (reg->bitsize == gdbarch_int_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_int;
	  else if (reg->bitsize == gdbarch_long_long_bit (gdbarch))
	    arch_reg->type = builtin_type (gdbarch)->builtin_long_long;
	  else if (reg->bitsize == gdbarch_ptr_bit (gdbarch))
	  /* A bit desperate by this point...  */
	    arch_reg->type = builtin_type (gdbarch)->builtin_data_ptr;
	  else
	    {
	      warning (_("Register \"%s\" has an unsupported size (%d bits)"),
		       reg->name.c_str (), reg->bitsize);
	      arch_reg->type = builtin_type (gdbarch)->builtin_long;
	    }
	}

      if (arch_reg->type == NULL)
	internal_error (__FILE__, __LINE__,
			"Register \"%s\" has an unknown type \"%s\"",
			reg->name.c_str (), reg->type.c_str ());
    }

  return arch_reg->type;
}

static int
tdesc_remote_register_number (struct gdbarch *gdbarch, int regno)
{
  struct tdesc_reg *reg = tdesc_find_register (gdbarch, regno);

  if (reg != NULL)
    return reg->target_regnum;
  else
    return -1;
}

/* Check whether REGNUM is a member of REGGROUP.  Registers from the
   target description may be classified as general, float, vector or other
   register groups registered with reggroup_add().  Unlike a gdbarch
   register_reggroup_p method, this function will return -1 if it does not
   know; the caller should handle registers with no specified group.

   The names of containing features are not used.  This might be extended
   to display registers in some more useful groupings.

   The save-restore flag is also implemented here.  */

int
tdesc_register_in_reggroup_p (struct gdbarch *gdbarch, int regno,
			      struct reggroup *reggroup)
{
  struct tdesc_reg *reg = tdesc_find_register (gdbarch, regno);

  if (reg != NULL && !reg->group.empty ()
      && (reg->group == reggroup_name (reggroup)))
	return 1;

  if (reg != NULL
      && (reggroup == save_reggroup || reggroup == restore_reggroup))
    return reg->save_restore;

  return -1;
}

/* Check whether REGNUM is a member of REGGROUP.  Registers with no
   group specified go to the default reggroup function and are handled
   by type.  */

static int
tdesc_register_reggroup_p (struct gdbarch *gdbarch, int regno,
			   struct reggroup *reggroup)
{
  int num_regs = gdbarch_num_regs (gdbarch);
  int num_pseudo_regs = gdbarch_num_pseudo_regs (gdbarch);
  int ret;

  if (regno >= num_regs && regno < num_regs + num_pseudo_regs)
    {
      struct tdesc_arch_data *data
	= (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

      if (data->pseudo_register_reggroup_p != NULL)
	return data->pseudo_register_reggroup_p (gdbarch, regno, reggroup);
      /* Otherwise fall through to the default reggroup_p.  */
    }

  ret = tdesc_register_in_reggroup_p (gdbarch, regno, reggroup);
  if (ret != -1)
    return ret;

  return default_register_reggroup_p (gdbarch, regno, reggroup);
}

/* Record architecture-specific functions to call for pseudo-register
   support.  */

void
set_tdesc_pseudo_register_name (struct gdbarch *gdbarch,
				gdbarch_register_name_ftype *pseudo_name)
{
  struct tdesc_arch_data *data
    = (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

  data->pseudo_register_name = pseudo_name;
}

void
set_tdesc_pseudo_register_type (struct gdbarch *gdbarch,
				gdbarch_register_type_ftype *pseudo_type)
{
  struct tdesc_arch_data *data
    = (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

  data->pseudo_register_type = pseudo_type;
}

void
set_tdesc_pseudo_register_reggroup_p
  (struct gdbarch *gdbarch,
   gdbarch_register_reggroup_p_ftype *pseudo_reggroup_p)
{
  struct tdesc_arch_data *data
    = (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);

  data->pseudo_register_reggroup_p = pseudo_reggroup_p;
}

/* Update GDBARCH to use the target description for registers.  */

void
tdesc_use_registers (struct gdbarch *gdbarch,
		     const struct target_desc *target_desc,
		     struct tdesc_arch_data *early_data)
{
  int num_regs = gdbarch_num_regs (gdbarch);
  struct tdesc_arch_data *data;
  htab_t reg_hash;

  /* We can't use the description for registers if it doesn't describe
     any.  This function should only be called after validating
     registers, so the caller should know that registers are
     included.  */
  gdb_assert (tdesc_has_registers (target_desc));

  data = (struct tdesc_arch_data *) gdbarch_data (gdbarch, tdesc_data);
  data->arch_regs = early_data->arch_regs;
  delete early_data;

  /* Build up a set of all registers, so that we can assign register
     numbers where needed.  The hash table expands as necessary, so
     the initial size is arbitrary.  */
  reg_hash = htab_create (37, htab_hash_pointer, htab_eq_pointer, NULL);
  for (const tdesc_feature_up &feature : target_desc->features)
    for (const tdesc_reg_up &reg : feature->registers)
      {
	void **slot = htab_find_slot (reg_hash, reg.get (), INSERT);

	*slot = reg.get ();
	/* Add reggroup if its new.  */
	if (!reg->group.empty ())
	  if (reggroup_find (gdbarch, reg->group.c_str ()) == NULL)
	    reggroup_add (gdbarch, reggroup_gdbarch_new (gdbarch,
							 reg->group.c_str (),
							 USER_REGGROUP));
      }

  /* Remove any registers which were assigned numbers by the
     architecture.  */
  for (const tdesc_arch_reg &arch_reg : data->arch_regs)
    if (arch_reg.reg != NULL)
      htab_remove_elt (reg_hash, arch_reg.reg);

  /* Assign numbers to the remaining registers and add them to the
     list of registers.  The new numbers are always above gdbarch_num_regs.
     Iterate over the features, not the hash table, so that the order
     matches that in the target description.  */

  gdb_assert (data->arch_regs.size () <= num_regs);
  while (data->arch_regs.size () < num_regs)
    data->arch_regs.emplace_back (nullptr, nullptr);

  for (const tdesc_feature_up &feature : target_desc->features)
    for (const tdesc_reg_up &reg : feature->registers)
      if (htab_find (reg_hash, reg.get ()) != NULL)
	{
	  data->arch_regs.emplace_back (reg.get (), nullptr);
	  num_regs++;
	}

  htab_delete (reg_hash);

  /* Update the architecture.  */
  set_gdbarch_num_regs (gdbarch, num_regs);
  set_gdbarch_register_name (gdbarch, tdesc_register_name);
  set_gdbarch_register_type (gdbarch, tdesc_register_type);
  set_gdbarch_remote_register_number (gdbarch,
				      tdesc_remote_register_number);
  set_gdbarch_register_reggroup_p (gdbarch, tdesc_register_reggroup_p);
}

/* See gdbsupport/tdesc.h.  */

struct tdesc_feature *
tdesc_create_feature (struct target_desc *tdesc, const char *name)
{
  struct tdesc_feature *new_feature = new tdesc_feature (name);

  tdesc->features.emplace_back (new_feature);

  return new_feature;
}

struct target_desc *
allocate_target_description (void)
{
  return new target_desc ();
}

void
target_desc_deleter::operator() (struct target_desc *target_desc) const
{
  delete target_desc;
}

void
tdesc_add_compatible (struct target_desc *target_desc,
		      const struct bfd_arch_info *compatible)
{
  /* If this instance of GDB is compiled without BFD support for the
     compatible architecture, simply ignore it -- we would not be able
     to handle it anyway.  */
  if (compatible == NULL)
    return;

  for (const bfd_arch_info *compat : target_desc->compatible)
    if (compat == compatible)
      internal_error (__FILE__, __LINE__,
		      _("Attempted to add duplicate "
			"compatible architecture \"%s\""),
		      compatible->printable_name);

  target_desc->compatible.push_back (compatible);
}

void
set_tdesc_property (struct target_desc *target_desc,
		    const char *key, const char *value)
{
  gdb_assert (key != NULL && value != NULL);

  if (tdesc_property (target_desc, key) != NULL)
    internal_error (__FILE__, __LINE__,
		    _("Attempted to add duplicate property \"%s\""), key);

  target_desc->properties.emplace_back (key, value);
}

/* See gdbsupport/tdesc.h.  */

void
set_tdesc_architecture (struct target_desc *target_desc,
			const char *name)
{
  set_tdesc_architecture (target_desc, bfd_scan_arch (name));
}

void
set_tdesc_architecture (struct target_desc *target_desc,
			const struct bfd_arch_info *arch)
{
  target_desc->arch = arch;
}

/* See gdbsupport/tdesc.h.  */

void
set_tdesc_osabi (struct target_desc *target_desc, const char *name)
{
  set_tdesc_osabi (target_desc, osabi_from_tdesc_string (name));
}

void
set_tdesc_osabi (struct target_desc *target_desc, enum gdb_osabi osabi)
{
  target_desc->osabi = osabi;
}


static struct cmd_list_element *tdesc_set_cmdlist, *tdesc_show_cmdlist;
static struct cmd_list_element *tdesc_unset_cmdlist;

/* Helper functions for the CLI commands.  */

static void
set_tdesc_filename_cmd (const char *args, int from_tty,
			struct cmd_list_element *c)
{
  xfree (target_description_filename);
  target_description_filename = xstrdup (tdesc_filename_cmd_string);

  target_clear_description ();
  target_find_description ();
}

static void
show_tdesc_filename_cmd (struct ui_file *file, int from_tty,
			 struct cmd_list_element *c,
			 const char *value)
{
  value = target_description_filename;

  if (value != NULL && *value != '\0')
    printf_filtered (_("The target description will be read from \"%s\".\n"),
		     value);
  else
    printf_filtered (_("The target description will be "
		       "read from the target.\n"));
}

static void
unset_tdesc_filename_cmd (const char *args, int from_tty)
{
  xfree (target_description_filename);
  target_description_filename = NULL;
  target_clear_description ();
  target_find_description ();
}

/* Print target description in C.  */

class print_c_tdesc : public tdesc_element_visitor
{
public:
  print_c_tdesc (std::string &filename_after_features)
    : m_filename_after_features (filename_after_features)
  {
    const char *inp;
    char *outp;
    const char *filename = lbasename (m_filename_after_features.c_str ());

    m_function = (char *) xmalloc (strlen (filename) + 1);
    for (inp = filename, outp = m_function; *inp != '\0'; inp++)
      if (*inp == '.')
	break;
      else if (*inp == '-')
	*outp++ = '_';
      else
	*outp++ = *inp;
    *outp = '\0';

    /* Standard boilerplate.  */
    printf_unfiltered ("/* THIS FILE IS GENERATED.  "
		       "-*- buffer-read-only: t -*- vi"
		       ":set ro:\n");
  }

  ~print_c_tdesc ()
  {
    xfree (m_function);
  }

  void visit_pre (const target_desc *e) override
  {
    printf_unfiltered ("  Original: %s */\n\n",
		       lbasename (m_filename_after_features.c_str ()));

    printf_unfiltered ("#include \"defs.h\"\n");
    printf_unfiltered ("#include \"osabi.h\"\n");
    printf_unfiltered ("#include \"target-descriptions.h\"\n");
    printf_unfiltered ("\n");

    printf_unfiltered ("struct target_desc *tdesc_%s;\n", m_function);
    printf_unfiltered ("static void\n");
    printf_unfiltered ("initialize_tdesc_%s (void)\n", m_function);
    printf_unfiltered ("{\n");
    printf_unfiltered
      ("  struct target_desc *result = allocate_target_description ();\n");

    if (tdesc_architecture (e) != NULL)
      {
	printf_unfiltered
	  ("  set_tdesc_architecture (result, bfd_scan_arch (\"%s\"));\n",
	   tdesc_architecture (e)->printable_name);
	printf_unfiltered ("\n");
      }
    if (tdesc_osabi (e) > GDB_OSABI_UNKNOWN
	&& tdesc_osabi (e) < GDB_OSABI_INVALID)
      {
	printf_unfiltered
	  ("  set_tdesc_osabi (result, osabi_from_tdesc_string (\"%s\"));\n",
	   gdbarch_osabi_name (tdesc_osabi (e)));
	printf_unfiltered ("\n");
      }

    for (const bfd_arch_info_type *compatible : e->compatible)
      printf_unfiltered
	("  tdesc_add_compatible (result, bfd_scan_arch (\"%s\"));\n",
	 compatible->printable_name);

    if (!e->compatible.empty ())
      printf_unfiltered ("\n");

    for (const property &prop : e->properties)
      printf_unfiltered ("  set_tdesc_property (result, \"%s\", \"%s\");\n",
			 prop.key.c_str (), prop.value.c_str ());

    printf_unfiltered ("  struct tdesc_feature *feature;\n");
  }

  void visit_pre (const tdesc_feature *e) override
  {
    printf_unfiltered ("\n  feature = tdesc_create_feature (result, \"%s\");\n",
		       e->name.c_str ());
  }

  void visit_post (const tdesc_feature *e) override
  {}

  void visit_post (const target_desc *e) override
  {
    printf_unfiltered ("\n  tdesc_%s = result;\n", m_function);
    printf_unfiltered ("}\n");
  }

  void visit (const tdesc_type_builtin *type) override
  {
    error (_("C output is not supported type \"%s\"."), type->name.c_str ());
  }

  void visit (const tdesc_type_vector *type) override
  {
    if (!m_printed_element_type)
      {
	printf_unfiltered ("  tdesc_type *element_type;\n");
	m_printed_element_type = true;
      }

    printf_unfiltered
      ("  element_type = tdesc_named_type (feature, \"%s\");\n",
       type->element_type->name.c_str ());
    printf_unfiltered
      ("  tdesc_create_vector (feature, \"%s\", element_type, %d);\n",
       type->name.c_str (), type->count);

    printf_unfiltered ("\n");
  }

  void visit (const tdesc_type_with_fields *type) override
  {
    if (!m_printed_type_with_fields)
      {
	printf_unfiltered ("  tdesc_type_with_fields *type_with_fields;\n");
	m_printed_type_with_fields = true;
      }

    switch (type->kind)
      {
      case TDESC_TYPE_STRUCT:
      case TDESC_TYPE_FLAGS:
	if (type->kind == TDESC_TYPE_STRUCT)
	  {
	    printf_unfiltered
	      ("  type_with_fields = tdesc_create_struct (feature, \"%s\");\n",
	       type->name.c_str ());
	    if (type->size != 0)
	      printf_unfiltered
		("  tdesc_set_struct_size (type_with_fields, %d);\n", type->size);
	  }
	else
	  {
	    printf_unfiltered
	      ("  type_with_fields = tdesc_create_flags (feature, \"%s\", %d);\n",
	       type->name.c_str (), type->size);
	  }
	for (const tdesc_type_field &f : type->fields)
	  {
	    const char *type_name;

	    gdb_assert (f.type != NULL);
	    type_name = f.type->name.c_str ();

	    /* To minimize changes to generated files, don't emit type
	       info for fields that have defaulted types.  */
	    if (f.start != -1)
	      {
		gdb_assert (f.end != -1);
		if (f.type->kind == TDESC_TYPE_BOOL)
		  {
		    gdb_assert (f.start == f.end);
		    printf_unfiltered
		      ("  tdesc_add_flag (type_with_fields, %d, \"%s\");\n",
		       f.start, f.name.c_str ());
		  }
		else if ((type->size == 4 && f.type->kind == TDESC_TYPE_UINT32)
			 || (type->size == 8
			     && f.type->kind == TDESC_TYPE_UINT64))
		  {
		    printf_unfiltered
		      ("  tdesc_add_bitfield (type_with_fields, \"%s\", %d, %d);\n",
		       f.name.c_str (), f.start, f.end);
		  }
		else
		  {
		    printf_field_type_assignment
		      ("tdesc_named_type (feature, \"%s\");\n",
		       type_name);
		    printf_unfiltered
		      ("  tdesc_add_typed_bitfield (type_with_fields, \"%s\","
		       " %d, %d, field_type);\n",
		       f.name.c_str (), f.start, f.end);
		  }
	      }
	    else /* Not a bitfield.  */
	      {
		gdb_assert (f.end == -1);
		gdb_assert (type->kind == TDESC_TYPE_STRUCT);
		printf_field_type_assignment
		  ("tdesc_named_type (feature, \"%s\");\n", type_name);
		printf_unfiltered
		  ("  tdesc_add_field (type_with_fields, \"%s\", field_type);\n",
		   f.name.c_str ());
	      }
	  }
	break;
      case TDESC_TYPE_UNION:
	printf_unfiltered
	  ("  type_with_fields = tdesc_create_union (feature, \"%s\");\n",
	   type->name.c_str ());
	for (const tdesc_type_field &f : type->fields)
	  {
	    printf_field_type_assignment
	      ("tdesc_named_type (feature, \"%s\");\n", f.type->name.c_str ());
	    printf_unfiltered
	      ("  tdesc_add_field (type_with_fields, \"%s\", field_type);\n",
	       f.name.c_str ());
	  }
	break;
      case TDESC_TYPE_ENUM:
	printf_unfiltered
	  ("  type_with_fields = tdesc_create_enum (feature, \"%s\", %d);\n",
	   type->name.c_str (), type->size);
	for (const tdesc_type_field &f : type->fields)
	  printf_unfiltered
	    ("  tdesc_add_enum_value (type_with_fields, %d, \"%s\");\n",
	     f.start, f.name.c_str ());
	break;
      default:
	error (_("C output is not supported type \"%s\"."), type->name.c_str ());
      }

    printf_unfiltered ("\n");
  }

  void visit (const tdesc_reg *reg) override
  {
    printf_unfiltered ("  tdesc_create_reg (feature, \"%s\", %ld, %d, ",
		       reg->name.c_str (), reg->target_regnum,
		       reg->save_restore);
    if (!reg->group.empty ())
      printf_unfiltered ("\"%s\", ", reg->group.c_str ());
    else
      printf_unfiltered ("NULL, ");
    printf_unfiltered ("%d, \"%s\");\n", reg->bitsize, reg->type.c_str ());
  }

protected:
  std::string m_filename_after_features;

private:

  /* Print an assignment to the field_type variable.  Print the declaration
     of field_type if that has not been done yet.  */
  ATTRIBUTE_PRINTF (2, 3)
  void printf_field_type_assignment (const char *fmt, ...)
  {
    if (!m_printed_field_type)
      {
	printf_unfiltered ("  tdesc_type *field_type;\n");
	m_printed_field_type = true;
      }

    printf_unfiltered ("  field_type = ");

    va_list args;
    va_start (args, fmt);
    vprintf_unfiltered (fmt, args);
    va_end (args);
  }

  char *m_function;

  /* Did we print "struct tdesc_type *element_type;" yet?  */
  bool m_printed_element_type = false;

  /* Did we print "struct tdesc_type_with_fields *element_type;" yet?  */
  bool m_printed_type_with_fields = false;

  /* Did we print "struct tdesc_type *field_type;" yet?  */
  bool m_printed_field_type = false;
};

/* Print target description feature in C.  */

class print_c_feature : public print_c_tdesc
{
public:
  print_c_feature (std::string &file)
    : print_c_tdesc (file)
  {
    /* Trim ".tmp".  */
    auto const pos = m_filename_after_features.find_last_of ('.');

    m_filename_after_features = m_filename_after_features.substr (0, pos);
  }

  void visit_pre (const target_desc *e) override
  {
    printf_unfiltered ("  Original: %s */\n\n",
		       lbasename (m_filename_after_features.c_str ()));

    printf_unfiltered ("#include \"gdbsupport/tdesc.h\"\n");
    printf_unfiltered ("\n");
  }

  void visit_post (const target_desc *e) override
  {}

  void visit_pre (const tdesc_feature *e) override
  {
    std::string name (m_filename_after_features);

    auto pos = name.find_first_of ('.');

    name = name.substr (0, pos);
    std::replace (name.begin (), name.end (), '/', '_');
    std::replace (name.begin (), name.end (), '-', '_');

    printf_unfiltered ("static int\n");
    printf_unfiltered ("create_feature_%s ", name.c_str ());
    printf_unfiltered ("(struct target_desc *result, long regnum)\n");

    printf_unfiltered ("{\n");
    printf_unfiltered ("  struct tdesc_feature *feature;\n");

    printf_unfiltered
      ("\n  feature = tdesc_create_feature (result, \"%s\");\n",
       e->name.c_str ());
  }

  void visit_post (const tdesc_feature *e) override
  {
    printf_unfiltered ("  return regnum;\n");
    printf_unfiltered ("}\n");
  }

  void visit (const tdesc_reg *reg) override
  {
    /* Most "reg" in XML target descriptions don't have "regnum"
       attribute, so the register number is allocated sequentially.
       In case that reg has "regnum" attribute, register number
       should be set by that explicitly.  */

    if (reg->target_regnum < m_next_regnum)
      {
	/* The integrity check, it can catch some errors on register
	   number collision, like this,

	  <reg name="x0" bitsize="32"/>
	  <reg name="x1" bitsize="32"/>
	  <reg name="x2" bitsize="32"/>
	  <reg name="x3" bitsize="32"/>
	  <reg name="ps" bitsize="32" regnum="3"/>

	  but it also has false negatives.  The target description
	  below is correct,

	  <reg name="x1" bitsize="32" regnum="1"/>
	  <reg name="x3" bitsize="32" regnum="3"/>
	  <reg name="x2" bitsize="32" regnum="2"/>
	  <reg name="x4" bitsize="32" regnum="4"/>

	  but it is not a good practice, so still error on this,
	  and also print the message so that it can be saved in the
	  generated c file.  */

	printf_unfiltered ("ERROR: \"regnum\" attribute %ld ",
			   reg->target_regnum);
	printf_unfiltered ("is not the largest number (%d).\n",
			   m_next_regnum);
	error (_("\"regnum\" attribute %ld is not the largest number (%d)."),
	       reg->target_regnum, m_next_regnum);
      }

    if (reg->target_regnum > m_next_regnum)
      {
	printf_unfiltered ("  regnum = %ld;\n", reg->target_regnum);
	m_next_regnum = reg->target_regnum;
      }

    printf_unfiltered ("  tdesc_create_reg (feature, \"%s\", regnum++, %d, ",
		       reg->name.c_str (), reg->save_restore);
    if (!reg->group.empty ())
      printf_unfiltered ("\"%s\", ", reg->group.c_str ());
    else
      printf_unfiltered ("NULL, ");
    printf_unfiltered ("%d, \"%s\");\n", reg->bitsize, reg->type.c_str ());

    m_next_regnum++;
  }

private:
  /* The register number to use for the next register we see.  */
  int m_next_regnum = 0;
};

/* See gdbsupport/tdesc.h.  */

const char *
tdesc_get_features_xml (const target_desc *tdesc)
{
  if (tdesc->xmltarget == nullptr)
    {
      std::string buffer ("@");
      print_xml_feature v (&buffer);
      tdesc->accept (v);
      tdesc->xmltarget = xstrdup (buffer.c_str ());
    }
  return tdesc->xmltarget;
}

static void
maint_print_c_tdesc_cmd (const char *args, int from_tty)
{
  const struct target_desc *tdesc;
  const char *filename;

  if (args == NULL)
    {
      /* Use the global target-supplied description, not the current
	 architecture's.  This lets a GDB for one architecture generate C
	 for another architecture's description, even though the gdbarch
	 initialization code will reject the new description.  */
      tdesc = current_target_desc;
      filename = target_description_filename;
    }
  else
    {
      /* Use the target description from the XML file.  */
      filename = args;
      tdesc = file_read_description_xml (filename);
    }

  if (tdesc == NULL)
    error (_("There is no target description to print."));

  if (filename == NULL)
    error (_("The current target description did not come from an XML file."));

  std::string filename_after_features (filename);
  auto loc = filename_after_features.rfind ("/features/");

  if (loc != std::string::npos)
    filename_after_features = filename_after_features.substr (loc + 10);

  /* Print c files for target features instead of target descriptions,
     because c files got from target features are more flexible than the
     counterparts.  */
  if (startswith (filename_after_features.c_str (), "i386/32bit-")
      || startswith (filename_after_features.c_str (), "i386/64bit-")
      || startswith (filename_after_features.c_str (), "i386/x32-core.xml")
      || startswith (filename_after_features.c_str (), "riscv/")
      || startswith (filename_after_features.c_str (), "tic6x-")
      || startswith (filename_after_features.c_str (), "aarch64")
      || startswith (filename_after_features.c_str (), "arm/")
      || startswith (filename_after_features.c_str (), "arc/"))
    {
      print_c_feature v (filename_after_features);

      tdesc->accept (v);
    }
  else
    {
      print_c_tdesc v (filename_after_features);

      tdesc->accept (v);
    }
}

namespace selftests {

/* A reference target description, used for testing (see record_xml_tdesc).  */

struct xml_test_tdesc
{
  xml_test_tdesc (const char *name, std::unique_ptr<const target_desc> &&tdesc)
    : name (name), tdesc (std::move (tdesc))
  {}

  const char *name;
  std::unique_ptr<const target_desc> tdesc;
};

static std::vector<xml_test_tdesc> xml_tdesc;

#if GDB_SELF_TEST

/* See target-descriptions.h.  */

void
record_xml_tdesc (const char *xml_file, const struct target_desc *tdesc)
{
  xml_tdesc.emplace_back (xml_file, std::unique_ptr<const target_desc> (tdesc));
}
#endif

}

/* Test the conversion process of a target description to/from xml: Take a target
   description TDESC, convert to xml, back to a description, and confirm the new
   tdesc is identical to the original.  */
static bool
maintenance_check_tdesc_xml_convert (const target_desc *tdesc, const char *name)
{
  const char *xml = tdesc_get_features_xml (tdesc);

  if (xml == nullptr || *xml != '@')
    {
      printf_filtered (_("Could not convert description for %s to xml.\n"),
		       name);
      return false;
    }

  const target_desc *tdesc_trans = string_read_description_xml (xml + 1);

  if (tdesc_trans == nullptr)
    {
      printf_filtered (_("Could not convert description for %s from xml.\n"),
		       name);
      return false;
    }
  else if (*tdesc != *tdesc_trans)
    {
      printf_filtered (_("Converted description for %s does not match.\n"),
		       name);
      return false;
    }
  return true;
}


/* Check that the target descriptions created dynamically by
   architecture-specific code equal the descriptions created from XML files
   found in the specified directory DIR.  */

static void
maintenance_check_xml_descriptions (const char *dir, int from_tty)
{
  if (dir == NULL)
    error (_("Missing dir name"));

  gdb::unique_xmalloc_ptr<char> dir1 (tilde_expand (dir));
  std::string feature_dir (dir1.get ());
  unsigned int failed = 0;

  for (auto const &e : selftests::xml_tdesc)
    {
      std::string tdesc_xml = (feature_dir + SLASH_STRING + e.name);
      const target_desc *tdesc
	= file_read_description_xml (tdesc_xml.data ());

      if (tdesc == NULL || *tdesc != *e.tdesc)
	{
	  printf_filtered ( _("Descriptions for %s do not match.\n"), e.name);
	  failed++;
	}
      else if (!maintenance_check_tdesc_xml_convert (tdesc, e.name)
	       || !maintenance_check_tdesc_xml_convert (e.tdesc.get (), e.name))
	failed++;
    }
  printf_filtered (_("Tested %lu XML files, %d failed\n"),
		   (long) selftests::xml_tdesc.size (), failed);
}

void _initialize_target_descriptions ();
void
_initialize_target_descriptions ()
{
  tdesc_data = gdbarch_data_register_pre_init (tdesc_data_init);

  add_basic_prefix_cmd ("tdesc", class_maintenance, _("\
Set target description specific variables."),
			&tdesc_set_cmdlist, "set tdesc ",
			0 /* allow-unknown */, &setlist);
  add_show_prefix_cmd ("tdesc", class_maintenance, _("\
Show target description specific variables."),
		       &tdesc_show_cmdlist, "show tdesc ",
		       0 /* allow-unknown */, &showlist);
  add_basic_prefix_cmd ("tdesc", class_maintenance, _("\
Unset target description specific variables."),
			&tdesc_unset_cmdlist, "unset tdesc ",
			0 /* allow-unknown */, &unsetlist);

  add_setshow_filename_cmd ("filename", class_obscure,
			    &tdesc_filename_cmd_string,
			    _("\
Set the file to read for an XML target description."), _("\
Show the file to read for an XML target description."), _("\
When set, GDB will read the target description from a local\n\
file instead of querying the remote target."),
			    set_tdesc_filename_cmd,
			    show_tdesc_filename_cmd,
			    &tdesc_set_cmdlist, &tdesc_show_cmdlist);

  add_cmd ("filename", class_obscure, unset_tdesc_filename_cmd, _("\
Unset the file to read for an XML target description.\n\
When unset, GDB will read the description from the target."),
	   &tdesc_unset_cmdlist);

  add_cmd ("c-tdesc", class_maintenance, maint_print_c_tdesc_cmd, _("\
Print the current target description as a C source file."),
	   &maintenanceprintlist);

  cmd_list_element *cmd;

  cmd = add_cmd ("xml-descriptions", class_maintenance,
		 maintenance_check_xml_descriptions, _("\
Check equality of GDB target descriptions and XML created descriptions.\n\
Check the target descriptions created in GDB equal the descriptions\n\
created from XML files in the directory.\n\
The parameter is the directory name."),
		 &maintenancechecklist);
  set_cmd_completer (cmd, filename_completer);
}
