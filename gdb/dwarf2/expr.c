/* DWARF 2 Expression Evaluator.

   Copyright (C) 2001-2021 Free Software Foundation, Inc.

   Contributed by Daniel Berlin (dan@dberlin.org)

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
#include "block.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "value.h"
#include "gdbcore.h"
#include "dwarf2.h"
#include "dwarf2/expr.h"
#include "dwarf2/loc.h"
#include "dwarf2/read.h"
#include "frame.h"
#include "gdbsupport/underlying.h"
#include "gdbarch.h"
#include "inferior.h"
#include "observable.h"

/* Cookie for gdbarch data.  */

static struct gdbarch_data *dwarf_arch_cookie;

/* This holds gdbarch-specific types used by the DWARF expression
   evaluator.  See comments in execute_stack_op.  */

struct dwarf_gdbarch_types
{
  struct type *dw_types[3];
};

/* Allocate and fill in dwarf_gdbarch_types for an arch.  */

static void *
dwarf_gdbarch_types_init (struct gdbarch *gdbarch)
{
  struct dwarf_gdbarch_types *types
    = GDBARCH_OBSTACK_ZALLOC (gdbarch, struct dwarf_gdbarch_types);

  /* The types themselves are lazily initialized.  */

  return types;
}

/* Ensure that a FRAME is defined, throw an exception otherwise.

   Throwing NOT_AVAILABLE_ERROR error so that a client can chose
   to react differently if the evaluation ended because there
   was a missing context information.  */

static void
ensure_have_frame (struct frame_info *frame, const char *op_name)
{
  if (frame == nullptr)
    throw_error (NOT_AVAILABLE_ERROR,
		 _("%s evaluation requires a frame."), op_name);
}

/* Ensure that a PER_CU is defined and throw an exception otherwise.

   Throwing NOT_AVAILABLE_ERROR error so that a client can chose
   to react differently if the evaluation ended because there
   was a missing context information.  */

static void
ensure_have_per_cu (struct dwarf2_per_cu_data *per_cu, const char* op_name)
{
  if (per_cu == nullptr)
    throw_error (NOT_AVAILABLE_ERROR,
		 _("%s evaluation requires a compilation unit."), op_name);
}

/* Return the number of bytes overlapping a contiguous chunk of N_BITS
   bits whose first bit is located at bit offset START.  */

static size_t
bits_to_bytes (ULONGEST start, ULONGEST n_bits)
{
  return (start % HOST_CHAR_BIT + n_bits + HOST_CHAR_BIT - 1) / HOST_CHAR_BIT;
}

/* Throw an exception about the invalid DWARF expression.  */

static void
ill_formed_expression ()
{
  error (_("Ill-formed DWARF expression"));
}

/* See expr.h.  */

CORE_ADDR
read_addr_from_reg (struct frame_info *frame, int reg)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);
  int regnum = dwarf_reg_to_regnum_or_error (gdbarch, reg);

  return address_from_register (regnum, frame);
}

/* Read register REGNUM's contents in a given FRAME context.

   The data read is offsetted by OFFSET, and the number of bytes read
   is defined by LENGTH.  The data is then copied into the
   caller-managed buffer BUF.

   If the register is optimized out or unavailable for the given
   FRAME, the OPTIMIZED and UNAVAILABLE outputs are set
   accordingly  */

static void
read_from_register (struct frame_info *frame, int regnum,
		    CORE_ADDR offset, gdb::array_view<gdb_byte> buf,
		    int *optimized, int *unavailable)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);
  int regsize = register_size (gdbarch, regnum);
  int numregs = gdbarch_num_cooked_regs (gdbarch);
  int length = buf.size ();

  /* If a register is wholly inside the OFFSET, skip it.  */
  if (frame == NULL || !regsize
      || offset + length > regsize || numregs < regnum)
    {
      *optimized = 0;
      *unavailable = 1;
      return;
    }

  gdb::byte_vector temp_buf (regsize);
  enum lval_type lval;
  CORE_ADDR address;
  int realnum;

  frame_register (frame, regnum, optimized, unavailable,
		  &lval, &address, &realnum, temp_buf.data ());

  if (!*optimized && !*unavailable)
     memcpy (buf.data (), (char *) temp_buf.data () + offset, length);

  return;
}

/* Write register REGNUM's contents in a given FRAME context.

   The data written is offsetted by OFFSET, and the number of bytes
   written is defined by LENGTH.  The data is copied from
   caller-managed buffer BUF.

   If the register is optimized out or unavailable for the given
   FRAME, the OPTIMIZED and UNAVAILABLE outputs are set
   accordingly. */

static void
write_to_register (struct frame_info *frame, int regnum,
		   CORE_ADDR offset, gdb::array_view<gdb_byte> buf,
		   int *optimized, int *unavailable)
{
  struct gdbarch *gdbarch = get_frame_arch (frame);
  int regsize = register_size (gdbarch, regnum);
  int numregs = gdbarch_num_cooked_regs (gdbarch);
  int length = buf.size ();

  /* If a register is wholly inside of OFFSET, skip it.  */
  if (frame == NULL || !regsize
     || offset + length > regsize || numregs < regnum)
    {
      *optimized = 0;
      *unavailable = 1;
      return;
    }

  gdb::byte_vector temp_buf (regsize);
  enum lval_type lval;
  CORE_ADDR address;
  int realnum;

  frame_register (frame, regnum, optimized, unavailable,
		  &lval, &address, &realnum, temp_buf.data ());

  if (!*optimized && !*unavailable)
    {
      memcpy ((char *) temp_buf.data () + offset, buf.data (), length);

      put_frame_register (frame, regnum, temp_buf.data ());
    }

  return;
}

/* Helper for read_from_memory and write_to_memory.  */

static void
xfer_memory (CORE_ADDR address, gdb_byte *readbuf,
	     const gdb_byte *writebuf,
	     size_t length, bool stack, int *unavailable)
{
  *unavailable = 0;

  enum target_object object
    = stack ? TARGET_OBJECT_STACK_MEMORY : TARGET_OBJECT_MEMORY;

  ULONGEST xfered_total = 0;

  while (xfered_total < length)
    {
      ULONGEST xfered_partial;

      enum target_xfer_status status
	= target_xfer_partial (current_inferior ()->top_target (), object, NULL,
			       (readbuf != nullptr
				? readbuf + xfered_total
				: nullptr),
			       (writebuf != nullptr
				? writebuf + xfered_total
				: nullptr),
			       address + xfered_total, length - xfered_total,
			       &xfered_partial);

      if (status == TARGET_XFER_OK)
	{
	  xfered_total += xfered_partial;
	  QUIT;
	}
      else if (status == TARGET_XFER_UNAVAILABLE)
	{
	  *unavailable = 1;
	  return;
	}
      else if (status == TARGET_XFER_EOF)
	memory_error (TARGET_XFER_E_IO, address + xfered_total);
      else
	memory_error (status, address + xfered_total);
    }
}

/* Read LENGTH bytes of memory contents starting at ADDRESS.

   The data read is copied to a caller-managed buffer BUF.  STACK
   indicates whether the memory range specified belongs to a stack
   memory region.

   If the memory is unavailable, the UNAVAILABLE output is set.  */

static void
read_from_memory (CORE_ADDR address, gdb_byte *buffer,
		  size_t length, bool stack, int *unavailable)
{
  xfer_memory (address, buffer, nullptr, length, stack, unavailable);
}

/* Write LENGTH bytes of memory contents starting at ADDRESS.

   The data written is copied from a caller-managed buffer buf.  STACK
   indicates whether the memory range specified belongs to a stack
   memory region.

   If the memory is unavailable, the UNAVAILABLE output is set.  */

static void
write_to_memory (CORE_ADDR address, const gdb_byte *buffer,
		 size_t length, bool stack, int *unavailable)
{
  xfer_memory (address, nullptr, buffer, length, stack, unavailable);

  gdb::observers::memory_changed.notify (current_inferior (), address,
					 length, buffer);
}

/* Return the type used for DWARF operations where the type is
   generic in the DWARF spec, the ARCH is a target architecture.
   of the type and ADDR_SIZE is expected size of the address.
   Only certain sizes are supported.  */

static struct type *
address_type (struct gdbarch *gdbarch, int addr_size)
{
  struct dwarf_gdbarch_types *types
    = (struct dwarf_gdbarch_types *) gdbarch_data (gdbarch,
						   dwarf_arch_cookie);
  int ndx;

  if (addr_size == 2)
    ndx = 0;
  else if (addr_size == 4)
    ndx = 1;
  else if (addr_size == 8)
    ndx = 2;
  else
    error (_("Unsupported address size in DWARF expressions: %d bits"),
	   8 * addr_size);

  if (types->dw_types[ndx] == NULL)
    types->dw_types[ndx]
      = arch_integer_type (gdbarch, HOST_CHAR_BIT * addr_size,
			   0, "<signed DWARF address type>");

  return types->dw_types[ndx];
}

class dwarf_location;
class dwarf_memory;
class dwarf_value;

/* Base class that describes entries found on a DWARF expression
   evaluation stack.  */

class dwarf_entry : public std::enable_shared_from_this<dwarf_entry>
{
public:
  virtual ~dwarf_entry () = 0;

  /* Convert DWARF entry into a DWARF location description.  ARCH
     defines an architecture of the location described.   */
  virtual std::shared_ptr<dwarf_location> to_location
    (struct gdbarch *arch) = 0;

  /* Convert DWARF entry into a DWARF value.  TYPE defines a
     desired type of the returned DWARF value if it already
     doesnt have one.  */
  virtual std::shared_ptr<dwarf_value> to_value (struct type *type) = 0;
};

dwarf_entry::~dwarf_entry () = default;

/* Location description entry found on a DWARF expression evaluation
   stack.

   Types of locations descirbed can be: register location, memory
   location, implicit location, implicit pointer location, undefined
   location and composite location (composed out of any of the location
   types including another composite location).  */

class dwarf_location : public dwarf_entry
{
public:
  /* Not expected to be called on it's own.  */
  dwarf_location (struct gdbarch *arch, LONGEST offset = 0,
		  LONGEST bit_suboffset = 0)
    : m_arch (arch), m_initialised (true)
  {
    m_offset = offset;
    m_offset += bit_suboffset / HOST_CHAR_BIT;
    m_bit_suboffset = bit_suboffset % HOST_CHAR_BIT;
  }

  virtual ~dwarf_location () = default;

  /* Add bit offset to the location description.  */
  void add_bit_offset (LONGEST bit_offset)
  {
    LONGEST bit_total_offset = m_bit_suboffset + bit_offset;

    m_offset += bit_total_offset / HOST_CHAR_BIT;
    m_bit_suboffset = bit_total_offset % HOST_CHAR_BIT;
  };

  void set_initialised (bool initialised)
  {
    m_initialised = initialised;
  };

  /* Convert DWARF entry into a DWARF location description.  If the
     entry is already a location description, it will be returned as a
     result and no conversion will be applied to it.  ARCH defines an
     architecture of the location described.  */
  std::shared_ptr<dwarf_location> to_location (struct gdbarch *arch) override
  {
    return std::dynamic_pointer_cast<dwarf_location> (shared_from_this ());
  }

  /* Convert DWARF entry into a DWARF value.  If the conversion
     from that location description kind to a value is not supported
     the result is an empty pointer.  TYPE defines a desired type of
     the returned DWARF value if it already doesnt have one.  */
  virtual std::shared_ptr<dwarf_value> to_value (struct type *type) override
  {
    ill_formed_expression ();
    return std::shared_ptr<dwarf_value> (nullptr);
  }

  /* Read contents from the descripbed location.

     The read operation is performed in the context of a FRAME.
     BIT_SIZE is the number of bits to read.  The data read is copied
     to the caller-managed buffer BUF.  BIG_ENDIAN defines the
     endianness of the target.  BITS_TO_SKIP is a bit offset into the
     location and BUF_BIT_OFFSET is buffer BUF's bit offset.
     LOCATION_BIT_LIMIT is a maximum number of bits that location can
     hold, where value zero signifies that there is no such
     restriction.

     Note that some location types can be read without a FRAME context.

     If the location is optimized out or unavailable, the OPTIMIZED and
     UNAVAILABLE outputs are set accordingly.  */
  virtual void read (struct frame_info *frame, gdb_byte *buf,
		     int buf_bit_offset, size_t bit_size,
		     LONGEST bits_to_skip, size_t location_bit_limit,
		     bool big_endian, int *optimized,
		     int *unavailable) const = 0;

  /* Write contents to a described location.

     The write operation is performed in the context of a FRAME.
     BIT_SIZE is the number of bits written.  The data written is
     copied from the caller-managed BUF buffer.  BIG_ENDIAN defines an
     endianness of the target.  BITS_TO_SKIP is a bit offset into the
     location and BUF_BIT_OFFSET is buffer BUF's bit offset.
     LOCATION_BIT_LIMIT is a maximum number of bits that location can
     hold, where value zero signifies that there is no such
     restriction.

     Note that some location types can be written without a FRAME
     context.

     If the location is optimized out or unavailable, the OPTIMIZED and
     UNAVAILABLE outputs are set.  */
  virtual void write (struct frame_info *frame, const gdb_byte *buf,
		      int buf_bit_offset, size_t bit_size,
		      LONGEST bits_to_skip, size_t location_bit_limit,
		      bool big_endian, int *optimized,
		      int *unavailable) const = 0;

protected:
  /* Architecture of the location.  */
  struct gdbarch *m_arch;

  /* Byte offset into the location.  */
  LONGEST m_offset;

  /* Bit suboffset of the last byte.  */
  LONGEST m_bit_suboffset;

  /* Whether the location is initialized.  Used for non-standard
     DW_OP_GNU_uninit operation.  */
  bool m_initialised;
};

/* Value entry found on a DWARF expression evaluation stack.  */

class dwarf_value : public dwarf_entry
{
public:
  dwarf_value (const gdb_byte *contents, struct type *type)
  {
    size_t type_len = TYPE_LENGTH (type);
    m_contents.reset ((gdb_byte *) xzalloc (type_len));

    memcpy (m_contents.get (), contents, type_len);
    m_type = type;
  }

  dwarf_value (ULONGEST value, struct type *type)
  {
    m_contents.reset ((gdb_byte *) xzalloc (TYPE_LENGTH (type)));

    pack_unsigned_long (m_contents.get (), type, value);
    m_type = type;
  }

  dwarf_value (LONGEST value, struct type *type)
  {
    m_contents.reset ((gdb_byte *) xzalloc (TYPE_LENGTH (type)));

    pack_long (m_contents.get (), type, value);
    m_type = type;
  }

  const gdb_byte* get_contents () const
  {
    return m_contents.get ();
  }

  struct type* get_type () const
  {
    return m_type;
  }

  LONGEST to_long () const
  {
    return unpack_long (m_type, m_contents.get ());
  }

  /* Convert DWARF value into a DWARF memory location description.
     ARCH defines an architecture of the location described.  */
  std::shared_ptr<dwarf_location> to_location (struct gdbarch *arch) override;

  /* Convert DWARF entry into a DWARF value.  If the entry
     is already a value, it is just returned and the TYPE type
     information is ignored.  */
  std::shared_ptr<dwarf_value> to_value (struct type *type) override
  {
    return std::dynamic_pointer_cast<dwarf_value> (shared_from_this ());
  }

private:
  /* Value contents as a stream of bytes in target byte order.  */
  gdb::unique_xmalloc_ptr<gdb_byte> m_contents;

  /* Type of the value held by the entry.  */
  struct type *m_type;
};

std::shared_ptr<dwarf_location>
dwarf_value::to_location (struct gdbarch *arch)
{
  LONGEST offset;

  if (gdbarch_integer_to_address_p (arch))
    offset = gdbarch_integer_to_address (arch, m_type, m_contents.get ());
  else
    offset = extract_unsigned_integer (m_contents.get (), TYPE_LENGTH (m_type),
				       type_byte_order (m_type));

  auto memory = std::make_shared<dwarf_memory> (arch, offset);
  return std::dynamic_pointer_cast<dwarf_location> (memory);
}

/* Undefined location description entry.  This is a special location
   description type that describes the location description that is
   not known.  */

class dwarf_undefined : public dwarf_location
{
public:
  dwarf_undefined (struct gdbarch *arch, LONGEST offset = 0,
		   LONGEST bit_suboffset = 0)
    : dwarf_location (arch, offset, bit_suboffset)
  {}

  void read (struct frame_info *frame, gdb_byte *buf, int buf_bit_offset,
	     size_t bit_size, LONGEST bits_to_skip, size_t location_bit_limit,
	     bool big_endian, int *optimized, int *unavailable) const override
  {
    *unavailable = 0;
    *optimized = 1;
  }

  void write (struct frame_info *frame, const gdb_byte *buf,
	      int buf_bit_offset, size_t bit_size, LONGEST bits_to_skip,
	      size_t location_bit_limit, bool big_endian,
	      int *optimized, int *unavailable) const override
  {
    *unavailable = 0;
    *optimized = 1;
  }
};

class dwarf_memory : public dwarf_location
{
public:
  dwarf_memory (struct gdbarch *arch, LONGEST offset,
	        LONGEST bit_suboffset = 0, bool stack = false)
    : dwarf_location (arch, offset, bit_suboffset),
      m_stack (stack)
  {}

  void set_stack (bool stack)
  {
    m_stack = stack;
  };

  std::shared_ptr<dwarf_value> to_value (struct type *type) override;

  void read (struct frame_info *frame, gdb_byte *buf, int buf_bit_offset,
	     size_t bit_size, LONGEST bits_to_skip,
	     size_t location_bit_limit, bool big_endian,
	     int *optimized, int *unavailable) const override;

  void write (struct frame_info *frame, const gdb_byte *buf,
	      int buf_bit_offset, size_t bit_size, LONGEST bits_to_skip,
	      size_t location_bit_limit, bool big_endian,
	      int *optimized, int *unavailable) const override;

private:
  /* True if the location belongs to a stack memory region.  */
  bool m_stack;
};

std::shared_ptr<dwarf_value>
dwarf_memory::to_value (struct type *type)
{
  return std::make_shared<dwarf_value> (m_offset, type);
}

void
dwarf_memory::read (struct frame_info *frame, gdb_byte *buf,
		    int buf_bit_offset, size_t bit_size,
		    LONGEST bits_to_skip, size_t location_bit_limit,
		    bool big_endian, int *optimized, int *unavailable) const
{
  LONGEST total_bits_to_skip = bits_to_skip;
  CORE_ADDR start_address
    = m_offset + (m_bit_suboffset + total_bits_to_skip) / HOST_CHAR_BIT;
  gdb::byte_vector temp_buf;

  *optimized = 0;
  total_bits_to_skip += m_bit_suboffset;

  if (total_bits_to_skip % HOST_CHAR_BIT == 0
      && bit_size % HOST_CHAR_BIT == 0
      && buf_bit_offset % HOST_CHAR_BIT == 0)
    {
      /* Everything is byte-aligned, no buffer needed.  */
      read_from_memory (start_address,
			buf + buf_bit_offset / HOST_CHAR_BIT,
			bit_size / HOST_CHAR_BIT, m_stack, unavailable);
    }
  else
    {
      LONGEST this_size = bits_to_bytes (total_bits_to_skip, bit_size);
      temp_buf.resize (this_size);

      /* Can only read from memory on byte granularity so an
	 additional buffer is required.  */
      read_from_memory (start_address, temp_buf.data (), this_size,
			m_stack, unavailable);

      if (!*unavailable)
	copy_bitwise (buf, buf_bit_offset, temp_buf.data (),
		      total_bits_to_skip % HOST_CHAR_BIT,
		      bit_size, big_endian);
    }
}

void
dwarf_memory::write (struct frame_info *frame, const gdb_byte *buf,
		     int buf_bit_offset, size_t bit_size,
		     LONGEST bits_to_skip, size_t location_bit_limit,
		     bool big_endian, int *optimized, int *unavailable) const
{
  LONGEST total_bits_to_skip = bits_to_skip;
  CORE_ADDR start_address
    = m_offset + (m_bit_suboffset + total_bits_to_skip) / HOST_CHAR_BIT;
  gdb::byte_vector temp_buf;

  total_bits_to_skip += m_bit_suboffset;
  *optimized = 0;

  if (total_bits_to_skip % HOST_CHAR_BIT == 0
      && bit_size % HOST_CHAR_BIT == 0
      && buf_bit_offset % HOST_CHAR_BIT == 0)
    {
      /* Everything is byte-aligned; no buffer needed.  */
      write_to_memory (start_address, buf + buf_bit_offset / HOST_CHAR_BIT,
		       bit_size / HOST_CHAR_BIT, m_stack, unavailable);
    }
  else
    {
      LONGEST this_size = bits_to_bytes (total_bits_to_skip, bit_size);
      temp_buf.resize (this_size);

      if (total_bits_to_skip % HOST_CHAR_BIT != 0
	  || bit_size % HOST_CHAR_BIT != 0)
	{
	  if (this_size <= HOST_CHAR_BIT)
	    /* Perform a single read for small sizes.  */
	    read_from_memory (start_address, temp_buf.data (),
			      this_size, m_stack, unavailable);
	  else
	    {
	      /* Only the first and last bytes can possibly have
		 any bits reused.  */
	      read_from_memory (start_address, temp_buf.data (),
				1, m_stack, unavailable);

	      if (!*unavailable)
		read_from_memory (start_address + this_size - 1,
				  &temp_buf[this_size - 1], 1,
				  m_stack, unavailable);
	    }
	}

      copy_bitwise (temp_buf.data (), total_bits_to_skip % HOST_CHAR_BIT,
		    buf, buf_bit_offset, bit_size, big_endian);

      write_to_memory (start_address, temp_buf.data (), this_size,
		       m_stack, unavailable);
    }
}

/* Register location description entry.  */

class dwarf_register : public dwarf_location
{
public:
  dwarf_register (struct gdbarch *arch, unsigned int regnum,
		  LONGEST offset = 0, LONGEST bit_suboffset = 0)
    : dwarf_location (arch, offset, bit_suboffset),
      m_regnum (regnum)
  {}

  void read (struct frame_info *frame, gdb_byte *buf, int buf_bit_offset,
	     size_t bit_size, LONGEST bits_to_skip, size_t location_bit_limit,
	     bool big_endian, int *optimized, int *unavailable) const override;

  void write (struct frame_info *frame, const gdb_byte *buf,
	      int buf_bit_offset, size_t bit_size, LONGEST bits_to_skip,
	      size_t location_bit_limit, bool big_endian,
	      int *optimized, int *unavailable) const override;

private:
  /* DWARF register number.  */
  unsigned int m_regnum;
};

void
dwarf_register::read (struct frame_info *frame, gdb_byte *buf,
		      int buf_bit_offset, size_t bit_size,
		      LONGEST bits_to_skip, size_t location_bit_limit,
		      bool big_endian, int *optimized, int *unavailable) const
{
  LONGEST total_bits_to_skip = bits_to_skip;
  size_t read_bit_limit = location_bit_limit;
  int reg = dwarf_reg_to_regnum_or_error (m_arch, m_regnum);
  ULONGEST reg_bits = HOST_CHAR_BIT * register_size (m_arch, reg);
  gdb::byte_vector temp_buf;

  if (big_endian)
    {
      if (!read_bit_limit || reg_bits <= read_bit_limit)
	read_bit_limit = bit_size;

      total_bits_to_skip += reg_bits - (m_offset * HOST_CHAR_BIT
					+ m_bit_suboffset + read_bit_limit);
    }
  else
    total_bits_to_skip += m_offset * HOST_CHAR_BIT + m_bit_suboffset;

  LONGEST this_size = bits_to_bytes (total_bits_to_skip, bit_size);
  temp_buf.resize (this_size);

  if (frame == NULL)
    internal_error (__FILE__, __LINE__, _("invalid frame information"));

  /* Can only read from a register on byte granularity so an
     additional buffer is required.  */
  read_from_register (frame, reg, total_bits_to_skip / HOST_CHAR_BIT,
		      temp_buf, optimized, unavailable);

  /* Only copy data if valid.  */
  if (!*optimized && !*unavailable)
    copy_bitwise (buf, buf_bit_offset, temp_buf.data (),
		  total_bits_to_skip % HOST_CHAR_BIT, bit_size, big_endian);
}

void
dwarf_register::write (struct frame_info *frame, const gdb_byte *buf,
		       int buf_bit_offset, size_t bit_size,
		       LONGEST bits_to_skip, size_t location_bit_limit,
		       bool big_endian, int *optimized, int *unavailable) const
{
  LONGEST total_bits_to_skip = bits_to_skip;
  size_t write_bit_limit = location_bit_limit;
  int gdb_regnum = dwarf_reg_to_regnum_or_error (m_arch, m_regnum);
  ULONGEST reg_bits = HOST_CHAR_BIT * register_size (m_arch, gdb_regnum);
  gdb::byte_vector temp_buf;

  if (frame == NULL)
    internal_error (__FILE__, __LINE__, _("invalid frame information"));

  if (big_endian)
    {
      if (!write_bit_limit || reg_bits <= write_bit_limit)
	write_bit_limit = bit_size;

      total_bits_to_skip += reg_bits - (m_offset * HOST_CHAR_BIT
					+ m_bit_suboffset + write_bit_limit);
    }
  else
    total_bits_to_skip += m_offset * HOST_CHAR_BIT + m_bit_suboffset;

  LONGEST this_size = bits_to_bytes (total_bits_to_skip, bit_size);
  temp_buf.resize (this_size);

  if (total_bits_to_skip % HOST_CHAR_BIT != 0
      || bit_size % HOST_CHAR_BIT != 0)
    {
      /* Contents is copied non-byte-aligned into the register.
         Need some bits from original register value.  */
      read_from_register (frame, gdb_regnum,
			  total_bits_to_skip / HOST_CHAR_BIT,
			  temp_buf, optimized, unavailable);
    }

  copy_bitwise (temp_buf.data (), total_bits_to_skip % HOST_CHAR_BIT, buf,
		buf_bit_offset, bit_size, big_endian);

  write_to_register (frame, gdb_regnum, total_bits_to_skip / HOST_CHAR_BIT,
		     temp_buf, optimized, unavailable);
}

/* Implicit location description entry.  Describes a location
   description not found on the target but instead saved in a
   gdb-allocated buffer.  */

class dwarf_implicit : public dwarf_location
{
public:

  dwarf_implicit (struct gdbarch *arch, const gdb_byte *contents,
		  size_t size, enum bfd_endian byte_order)
    : dwarf_location (arch)
  {
    m_contents.reset ((gdb_byte *) xzalloc (size));

    memcpy (m_contents.get (), contents, size);
    m_size = size;
    m_byte_order = byte_order;
  }

  void read (struct frame_info *frame, gdb_byte *buf, int buf_bit_offset,
	     size_t bit_size, LONGEST bits_to_skip, size_t location_bit_limit,
	     bool big_endian, int *optimized, int *unavailable) const override;

  void write (struct frame_info *frame, const gdb_byte *buf,
	      int buf_bit_offset, size_t bit_size,
	      LONGEST bits_to_skip, size_t location_bit_limit,
	      bool big_endian, int* optimized, int* unavailable) const override
  {
    *optimized = 1;
    *unavailable = 0;
  }

private:
  /* Implicit location contents as a stream of bytes in target byte-order.  */
  gdb::unique_xmalloc_ptr<gdb_byte> m_contents;

  /* Contents byte stream size.  */
  size_t m_size;

  /* Contents original byte order.  */
  enum bfd_endian m_byte_order;
};

void
dwarf_implicit::read (struct frame_info *frame, gdb_byte *buf,
		      int buf_bit_offset, size_t bit_size,
		      LONGEST bits_to_skip, size_t location_bit_limit,
		      bool big_endian, int *optimized, int *unavailable) const
{
  ULONGEST implicit_bit_size = HOST_CHAR_BIT * m_size;
  LONGEST total_bits_to_skip = bits_to_skip;
  size_t read_bit_limit = location_bit_limit;

  *optimized = 0;
  *unavailable = 0;

  /* Cut off at the end of the implicit value.  */
  if (m_byte_order == BFD_ENDIAN_BIG)
    {
      if (!read_bit_limit || read_bit_limit > implicit_bit_size)
	read_bit_limit = bit_size;

      total_bits_to_skip
	+= implicit_bit_size - (m_offset * HOST_CHAR_BIT
			       + m_bit_suboffset + read_bit_limit);
    }
  else
    total_bits_to_skip += m_offset * HOST_CHAR_BIT + m_bit_suboffset;

  if (total_bits_to_skip >= implicit_bit_size)
    {
      (*unavailable) = 1;
      return;
    }

  if (bit_size > implicit_bit_size - total_bits_to_skip)
    bit_size = implicit_bit_size - total_bits_to_skip;

  copy_bitwise (buf, buf_bit_offset, m_contents.get (),
		total_bits_to_skip, bit_size, big_endian);
}

/* Implicit pointer location description entry.  */

class dwarf_implicit_pointer : public dwarf_location
{
public:
  dwarf_implicit_pointer (struct gdbarch *arch,
			  dwarf2_per_objfile *per_objfile,
			  struct dwarf2_per_cu_data *per_cu,
			  int addr_size, sect_offset die_offset,
			  LONGEST offset, LONGEST bit_suboffset = 0)
    : dwarf_location (arch, offset, bit_suboffset),
      m_per_objfile (per_objfile), m_per_cu (per_cu),
      m_addr_size (addr_size), m_die_offset (die_offset)
  {}

  void read (struct frame_info *frame, gdb_byte *buf, int buf_bit_offset,
	     size_t bit_size, LONGEST bits_to_skip, size_t location_bit_limit,
	     bool big_endian, int *optimized, int *unavailable) const override;

  void write (struct frame_info *frame, const gdb_byte *buf,
	      int buf_bit_offset, size_t bit_size, LONGEST bits_to_skip,
	      size_t location_bit_limit, bool big_endian,
	      int* optimized, int* unavailable) const override
  {
    *optimized = 1;
    *unavailable = 0;
  }

private:
  /* Per object file data of the implicit pointer.  */
  dwarf2_per_objfile *m_per_objfile;

  /* Compilation unit context of the implicit pointer.  */
  struct dwarf2_per_cu_data *m_per_cu;

  /* Address size for the evaluation.  */
  int m_addr_size;

  /* DWARF die offset pointed by the implicit pointer.  */
  sect_offset m_die_offset;
};

void
dwarf_implicit_pointer::read (struct frame_info *frame, gdb_byte *buf,
			      int buf_bit_offset, size_t bit_size,
                              LONGEST bits_to_skip, size_t location_bit_limit,
			      bool big_endian, int *optimized,
			      int *unavailable) const
{
  struct frame_info *actual_frame = frame;
  LONGEST total_bits_to_skip = bits_to_skip + m_bit_suboffset;

  if (actual_frame == nullptr)
    actual_frame = get_selected_frame (_("No frame selected."));

  struct type *type
    = address_type (get_frame_arch (actual_frame), m_addr_size);

  struct value *value
    = indirect_synthetic_pointer (m_die_offset, m_offset, m_per_cu,
				  m_per_objfile, actual_frame, type);

  gdb_byte *value_contents
    = value_contents_raw (value) + total_bits_to_skip / HOST_CHAR_BIT;

  if (total_bits_to_skip % HOST_CHAR_BIT == 0
      && bit_size % HOST_CHAR_BIT == 0
      && buf_bit_offset % HOST_CHAR_BIT == 0)
    {
      memcpy (buf + buf_bit_offset / HOST_CHAR_BIT,
	      value_contents, bit_size / HOST_CHAR_BIT);
    }
  else
    {
      copy_bitwise (buf, buf_bit_offset, value_contents,
		    total_bits_to_skip % HOST_CHAR_BIT,
		    bit_size, big_endian);
    }
}

/* Composite location description entry.  */

class dwarf_composite : public dwarf_location
{
public:
  dwarf_composite (struct gdbarch *arch, struct dwarf2_per_cu_data *per_cu,
		   LONGEST offset = 0, LONGEST bit_suboffset = 0)
    : dwarf_location (arch, offset, bit_suboffset), m_per_cu (per_cu)
  {}

  void add_piece (std::shared_ptr<dwarf_location> location, ULONGEST bit_size)
  {
    gdb_assert (location != nullptr);
    m_pieces.emplace_back (location, bit_size);
  }

  void read (struct frame_info *frame, gdb_byte *buf, int buf_bit_offset,
	     size_t bit_size, LONGEST bits_to_skip, size_t location_bit_limit,
	     bool big_endian, int *optimized, int *unavailable) const override;

  void write (struct frame_info *frame, const gdb_byte *buf,
	      int buf_bit_offset, size_t bit_size, LONGEST bits_to_skip,
	      size_t location_bit_limit, bool big_endian,
	      int *optimized, int *unavailable) const override;

private:
  /* Composite piece that contains a piece location
     description and it's size.  */
  class piece
  {
  public:
    piece (std::shared_ptr<dwarf_location> location, ULONGEST size)
    : m_location (location),
      m_size (size)
    {}

    std::shared_ptr<dwarf_location> m_location;
    ULONGEST m_size;
  };

  /* Compilation unit context of the pointer.  */
  struct dwarf2_per_cu_data *m_per_cu;

  /* Vector of composite pieces.  */
  std::vector<struct piece> m_pieces;
};

void
dwarf_composite::read (struct frame_info *frame, gdb_byte *buf,
		       int buf_bit_offset, size_t bit_size,
		       LONGEST bits_to_skip, size_t location_bit_limit,
		       bool big_endian, int *optimized, int *unavailable) const
{
  unsigned int pieces_num = m_pieces.size ();
  LONGEST total_bits_to_skip = bits_to_skip;
  unsigned int i;

  total_bits_to_skip += m_offset * HOST_CHAR_BIT + m_bit_suboffset;

  /* Skip pieces covered by the read offset.  */
  for (i = 0; i < pieces_num; i++)
    {
      LONGEST piece_bit_size = m_pieces[i].m_size;

      if (total_bits_to_skip < piece_bit_size)
        break;

      total_bits_to_skip -= piece_bit_size;
    }

  for (; i < pieces_num; i++)
    {
      LONGEST piece_bit_size = m_pieces[i].m_size;
      LONGEST actual_bit_size = piece_bit_size;

      if (actual_bit_size > bit_size)
        actual_bit_size = bit_size;

      m_pieces[i].m_location->read (frame, buf, buf_bit_offset,
				    actual_bit_size, total_bits_to_skip,
				    piece_bit_size, big_endian,
				    optimized, unavailable);

      if (bit_size == actual_bit_size || *optimized || *unavailable)
	break;

      buf_bit_offset += actual_bit_size;
      bit_size -= actual_bit_size;
    }
}

void
dwarf_composite::write (struct frame_info *frame, const gdb_byte *buf,
			int buf_bit_offset, size_t bit_size,
			LONGEST bits_to_skip, size_t location_bit_limit,
			bool big_endian, int *optimized,
			int *unavailable) const
{
  LONGEST total_bits_to_skip = bits_to_skip;
  unsigned int pieces_num = m_pieces.size ();
  unsigned int i;

  total_bits_to_skip += m_offset * HOST_CHAR_BIT + m_bit_suboffset;

  /* Skip pieces covered by the write offset.  */
  for (i = 0; i < pieces_num; i++)
    {
      LONGEST piece_bit_size = m_pieces[i].m_size;

      if (total_bits_to_skip < piece_bit_size)
	break;

      total_bits_to_skip -= piece_bit_size;
    }

  for (; i < pieces_num; i++)
    {
      LONGEST piece_bit_size = m_pieces[i].m_size;
      LONGEST actual_bit_size = piece_bit_size;

      if (actual_bit_size > bit_size)
        actual_bit_size = bit_size;

      m_pieces[i].m_location->write (frame, buf, buf_bit_offset,
				     actual_bit_size, total_bits_to_skip,
				     piece_bit_size, big_endian,
				     optimized, unavailable);

      if (bit_size == actual_bit_size || *optimized || *unavailable)
	break;

      buf_bit_offset += actual_bit_size;
      bit_size -= actual_bit_size;
    }
}

struct piece_closure
{
  /* Reference count.  */
  int refc = 0;

  /* The objfile from which this closure's expression came.  */
  dwarf2_per_objfile *per_objfile = nullptr;

  /* The CU from which this closure's expression came.  */
  struct dwarf2_per_cu_data *per_cu = NULL;

  /* The pieces describing this variable.  */
  std::vector<dwarf_expr_piece> pieces;

  /* Frame ID of frame to which a register value is relative, used
     only by DWARF_VALUE_REGISTER.  */
  struct frame_id frame_id;
};

/* Allocate a closure for a value formed from separately-described
   PIECES.  */

static struct piece_closure *
allocate_piece_closure (dwarf2_per_cu_data *per_cu,
			dwarf2_per_objfile *per_objfile,
			std::vector<dwarf_expr_piece> &&pieces,
			struct frame_info *frame)
{
  struct piece_closure *c = new piece_closure;

  c->refc = 1;
  /* We must capture this here due to sharing of DWARF state.  */
  c->per_objfile = per_objfile;
  c->per_cu = per_cu;
  c->pieces = std::move (pieces);
  if (frame == NULL)
    c->frame_id = null_frame_id;
  else
    c->frame_id = get_frame_id (frame);

  for (dwarf_expr_piece &piece : c->pieces)
    if (piece.location == DWARF_VALUE_STACK)
      value_incref (piece.v.value);

  return c;
}

/* Read or write a pieced value V.  If FROM != NULL, operate in "write
   mode": copy FROM into the pieces comprising V.  If FROM == NULL,
   operate in "read mode": fetch the contents of the (lazy) value V by
   composing it from its pieces.  */

static void
rw_pieced_value (struct value *v, struct value *from)
{
  int i;
  LONGEST offset = 0, max_offset;
  ULONGEST bits_to_skip;
  gdb_byte *v_contents;
  const gdb_byte *from_contents;
  struct piece_closure *c
    = (struct piece_closure *) value_computed_closure (v);
  gdb::byte_vector buffer;
  bool bits_big_endian = type_byte_order (value_type (v)) == BFD_ENDIAN_BIG;

  if (from != NULL)
    {
      from_contents = value_contents (from);
      v_contents = NULL;
    }
  else
    {
      if (value_type (v) != value_enclosing_type (v))
	internal_error (__FILE__, __LINE__,
			_("Should not be able to create a lazy value with "
			  "an enclosing type"));
      v_contents = value_contents_raw (v);
      from_contents = NULL;
    }

  bits_to_skip = 8 * value_offset (v);
  if (value_bitsize (v))
    {
      bits_to_skip += (8 * value_offset (value_parent (v))
		       + value_bitpos (v));
      if (from != NULL
	  && (type_byte_order (value_type (from))
	      == BFD_ENDIAN_BIG))
	{
	  /* Use the least significant bits of FROM.  */
	  max_offset = 8 * TYPE_LENGTH (value_type (from));
	  offset = max_offset - value_bitsize (v);
	}
      else
	max_offset = value_bitsize (v);
    }
  else
    max_offset = 8 * TYPE_LENGTH (value_type (v));

  /* Advance to the first non-skipped piece.  */
  for (i = 0; i < c->pieces.size () && bits_to_skip >= c->pieces[i].size; i++)
    bits_to_skip -= c->pieces[i].size;

  for (; i < c->pieces.size () && offset < max_offset; i++)
    {
      struct dwarf_expr_piece *p = &c->pieces[i];
      size_t this_size_bits, this_size;

      this_size_bits = p->size - bits_to_skip;
      if (this_size_bits > max_offset - offset)
	this_size_bits = max_offset - offset;

      switch (p->location)
	{
	case DWARF_VALUE_REGISTER:
	  {
	    struct frame_info *frame = frame_find_by_id (c->frame_id);
	    struct gdbarch *arch = get_frame_arch (frame);
	    int gdb_regnum = dwarf_reg_to_regnum_or_error (arch, p->v.regno);
	    ULONGEST reg_bits = 8 * register_size (arch, gdb_regnum);
	    int optim, unavail;

	    if (gdbarch_byte_order (arch) == BFD_ENDIAN_BIG
		&& p->offset + p->size < reg_bits)
	      {
		/* Big-endian, and we want less than full size.  */
		bits_to_skip += reg_bits - (p->offset + p->size);
	      }
	    else
	      bits_to_skip += p->offset;

	    this_size = bits_to_bytes (bits_to_skip, this_size_bits);
	    buffer.resize (this_size);

	    if (from == NULL)
	      {
		/* Read mode.  */
		read_from_register (frame, gdb_regnum, bits_to_skip / 8,
				    buffer, &optim, &unavail);

		if (optim)
		  mark_value_bits_optimized_out (v, offset, this_size_bits);
		if (unavail)
		  mark_value_bits_unavailable (v, offset, this_size_bits);
		/* Only copy data if valid.  */
		if (!optim && !unavail)
		  copy_bitwise (v_contents, offset,
				buffer.data (), bits_to_skip % 8,
				this_size_bits, bits_big_endian);
	      }
	    else
	      {
		/* Write mode.  */
		if (bits_to_skip % 8 != 0 || this_size_bits % 8 != 0)
		  {
		    /* Data is copied non-byte-aligned into the register.
		       Need some bits from original register value.  */
		    read_from_register (frame, gdb_regnum, bits_to_skip / 8,
					buffer, &optim, &unavail);
		    if (optim)
		      throw_error (OPTIMIZED_OUT_ERROR,
				   _("Can't do read-modify-write to "
				     "update bitfield; containing word "
				     "has been optimized out"));
		    if (unavail)
		      throw_error (NOT_AVAILABLE_ERROR,
				   _("Can't do read-modify-write to "
				     "update bitfield; containing word "
				     "is unavailable"));
		  }

		copy_bitwise (buffer.data (), bits_to_skip % 8,
			      from_contents, offset,
			      this_size_bits, bits_big_endian);
		write_to_register (frame, gdb_regnum, bits_to_skip / 8,
				   buffer, &optim, &unavail);
	      }
	  }
	  break;

	case DWARF_VALUE_MEMORY:
	  {
	    bits_to_skip += p->offset;

	    CORE_ADDR start_addr = p->v.mem.addr + bits_to_skip / 8;
	    bool in_stack_memory = p->v.mem.in_stack_memory;
	    int unavail = 0;

	    if (bits_to_skip % 8 == 0 && this_size_bits % 8 == 0
		&& offset % 8 == 0)
	      {
		/* Everything is byte-aligned; no buffer needed.  */
		if (from != NULL)
		  write_to_memory (start_addr, (from_contents + offset / 8),
				   this_size_bits / 8, in_stack_memory,
				   &unavail);
		else
		  read_from_memory (start_addr, (v_contents + offset / 8),
				    this_size_bits / 8, in_stack_memory,
				    &unavail);
	      }
	    else
	      {
		this_size = bits_to_bytes (bits_to_skip, this_size_bits);
		buffer.resize (this_size);

		if (from == NULL)
		  {
		    /* Read mode.  */
		    read_from_memory (start_addr, buffer.data (),
				      this_size, in_stack_memory,
				      &unavail);
		    if (!unavail)
		      copy_bitwise (v_contents, offset,
				    buffer.data (), bits_to_skip % 8,
				    this_size_bits, bits_big_endian);
		  }
		else
		  {
		    /* Write mode.  */
		    if (bits_to_skip % 8 != 0 || this_size_bits % 8 != 0)
		      {
			if (this_size <= 8)
			  {
			    /* Perform a single read for small sizes.  */
			    read_from_memory (start_addr, buffer.data (),
					      this_size, in_stack_memory,
					      &unavail);
			  }
			else
			  {
			    /* Only the first and last bytes can possibly have
			       any bits reused.  */
			    read_from_memory (start_addr, buffer.data (),
					      1, in_stack_memory,
					      &unavail);
			    if (!unavail)
			      read_from_memory (start_addr + this_size - 1,
						&buffer[this_size - 1], 1,
						in_stack_memory, &unavail);
			  }
		      }

		    if (!unavail)
		      {
			copy_bitwise (buffer.data (), bits_to_skip % 8,
				      from_contents, offset,
				      this_size_bits, bits_big_endian);
			write_to_memory (start_addr, buffer.data (),
					 this_size, in_stack_memory,
					 &unavail);
		      }
		  }
	      }

	    if (unavail)
	      {
		if (from == NULL)
		  mark_value_bits_unavailable (v, (offset + bits_to_skip % 8),
					       this_size_bits);
		else
		  throw_error (NOT_AVAILABLE_ERROR,
			       _("Can't do read-modify-write to "
				 "update bitfield; containing word "
				 "is unavailable"));
	      }
	  }
	  break;

	case DWARF_VALUE_STACK:
	  {
	    if (from != NULL)
	      {
		mark_value_bits_optimized_out (v, offset, this_size_bits);
		break;
	      }

	    gdbarch *objfile_gdbarch = c->per_objfile->objfile->arch ();
	    ULONGEST stack_value_size_bits
	      = 8 * TYPE_LENGTH (value_type (p->v.value));

	    /* Use zeroes if piece reaches beyond stack value.  */
	    if (p->offset + p->size > stack_value_size_bits)
	      break;

	    /* Piece is anchored at least significant bit end.  */
	    if (gdbarch_byte_order (objfile_gdbarch) == BFD_ENDIAN_BIG)
	      bits_to_skip += stack_value_size_bits - p->offset - p->size;
	    else
	      bits_to_skip += p->offset;

	    copy_bitwise (v_contents, offset,
			  value_contents_all (p->v.value),
			  bits_to_skip,
			  this_size_bits, bits_big_endian);
	  }
	  break;

	case DWARF_VALUE_LITERAL:
	  {
	    if (from != NULL)
	      {
		mark_value_bits_optimized_out (v, offset, this_size_bits);
		break;
	      }

	    ULONGEST literal_size_bits = 8 * p->v.literal.length;
	    size_t n = this_size_bits;

	    /* Cut off at the end of the implicit value.  */
	    bits_to_skip += p->offset;
	    if (bits_to_skip >= literal_size_bits)
	      break;
	    if (n > literal_size_bits - bits_to_skip)
	      n = literal_size_bits - bits_to_skip;

	    copy_bitwise (v_contents, offset,
			  p->v.literal.data, bits_to_skip,
			  n, bits_big_endian);
	  }
	  break;

	case DWARF_VALUE_IMPLICIT_POINTER:
	    if (from != NULL)
	      {
		mark_value_bits_optimized_out (v, offset, this_size_bits);
		break;
	      }

	  /* These bits show up as zeros -- but do not cause the value to
	     be considered optimized-out.  */
	  break;

	case DWARF_VALUE_OPTIMIZED_OUT:
	  mark_value_bits_optimized_out (v, offset, this_size_bits);
	  break;

	default:
	  internal_error (__FILE__, __LINE__, _("invalid location type"));
	}

      offset += this_size_bits;
      bits_to_skip = 0;
    }
}

static void
read_pieced_value (struct value *v)
{
  rw_pieced_value (v, NULL);
}

static void
write_pieced_value (struct value *to, struct value *from)
{
  rw_pieced_value (to, from);
}

/* An implementation of an lval_funcs method to see whether a value is
   a synthetic pointer.  */

static int
check_pieced_synthetic_pointer (const struct value *value, LONGEST bit_offset,
				int bit_length)
{
  struct piece_closure *c
    = (struct piece_closure *) value_computed_closure (value);
  int i;

  bit_offset += 8 * value_offset (value);
  if (value_bitsize (value))
    bit_offset += value_bitpos (value);

  for (i = 0; i < c->pieces.size () && bit_length > 0; i++)
    {
      struct dwarf_expr_piece *p = &c->pieces[i];
      size_t this_size_bits = p->size;

      if (bit_offset > 0)
	{
	  if (bit_offset >= this_size_bits)
	    {
	      bit_offset -= this_size_bits;
	      continue;
	    }

	  bit_length -= this_size_bits - bit_offset;
	  bit_offset = 0;
	}
      else
	bit_length -= this_size_bits;

      if (p->location != DWARF_VALUE_IMPLICIT_POINTER)
	return 0;
    }

  return 1;
}

/* An implementation of an lval_funcs method to indirect through a
   pointer.  This handles the synthetic pointer case when needed.  */

static struct value *
indirect_pieced_value (struct value *value)
{
  struct piece_closure *c
    = (struct piece_closure *) value_computed_closure (value);
  struct type *type;
  struct frame_info *frame;
  int i, bit_length;
  LONGEST bit_offset;
  struct dwarf_expr_piece *piece = NULL;
  LONGEST byte_offset;
  enum bfd_endian byte_order;

  type = check_typedef (value_type (value));
  if (type->code () != TYPE_CODE_PTR)
    return NULL;

  bit_length = 8 * TYPE_LENGTH (type);
  bit_offset = 8 * value_offset (value);
  if (value_bitsize (value))
    bit_offset += value_bitpos (value);

  for (i = 0; i < c->pieces.size () && bit_length > 0; i++)
    {
      struct dwarf_expr_piece *p = &c->pieces[i];
      size_t this_size_bits = p->size;

      if (bit_offset > 0)
	{
	  if (bit_offset >= this_size_bits)
	    {
	      bit_offset -= this_size_bits;
	      continue;
	    }

	  bit_length -= this_size_bits - bit_offset;
	  bit_offset = 0;
	}
      else
	bit_length -= this_size_bits;

      if (p->location != DWARF_VALUE_IMPLICIT_POINTER)
	return NULL;

      if (bit_length != 0)
	error (_("Invalid use of DW_OP_implicit_pointer"));

      piece = p;
      break;
    }

  gdb_assert (piece != NULL && c->per_cu != nullptr);
  frame = get_selected_frame (_("No frame selected."));

  /* This is an offset requested by GDB, such as value subscripts.
     However, due to how synthetic pointers are implemented, this is
     always presented to us as a pointer type.  This means we have to
     sign-extend it manually as appropriate.  Use raw
     extract_signed_integer directly rather than value_as_address and
     sign extend afterwards on architectures that would need it
     (mostly everywhere except MIPS, which has signed addresses) as
     the later would go through gdbarch_pointer_to_address and thus
     return a CORE_ADDR with high bits set on architectures that
     encode address spaces and other things in CORE_ADDR.  */
  byte_order = gdbarch_byte_order (get_frame_arch (frame));
  byte_offset = extract_signed_integer (value_contents (value),
					TYPE_LENGTH (type), byte_order);
  byte_offset += piece->v.ptr.offset;

  return indirect_synthetic_pointer (piece->v.ptr.die_sect_off,
				     byte_offset, c->per_cu,
				     c->per_objfile, frame, type);
}

/* Implementation of the coerce_ref method of lval_funcs for synthetic C++
   references.  */

static struct value *
coerce_pieced_ref (const struct value *value)
{
  struct type *type = check_typedef (value_type (value));

  if (value_bits_synthetic_pointer (value, value_embedded_offset (value),
				    TARGET_CHAR_BIT * TYPE_LENGTH (type)))
    {
      const struct piece_closure *closure
	= (struct piece_closure *) value_computed_closure (value);
      struct frame_info *frame
	= get_selected_frame (_("No frame selected."));

      /* gdb represents synthetic pointers as pieced values with a single
	 piece.  */
      gdb_assert (closure != NULL);
      gdb_assert (closure->pieces.size () == 1);

      return indirect_synthetic_pointer
	(closure->pieces[0].v.ptr.die_sect_off,
	 closure->pieces[0].v.ptr.offset,
	 closure->per_cu, closure->per_objfile, frame, type);
    }
  else
    {
      /* Else: not a synthetic reference; do nothing.  */
      return NULL;
    }
}

static void *
copy_pieced_value_closure (const struct value *v)
{
  struct piece_closure *c
    = (struct piece_closure *) value_computed_closure (v);

  ++c->refc;
  return c;
}

static void
free_pieced_value_closure (struct value *v)
{
  struct piece_closure *c
    = (struct piece_closure *) value_computed_closure (v);

  --c->refc;
  if (c->refc == 0)
    {
      for (dwarf_expr_piece &p : c->pieces)
	if (p.location == DWARF_VALUE_STACK)
	  value_decref (p.v.value);

      delete c;
    }
}

/* Functions for accessing a variable described by DW_OP_piece.  */
static const struct lval_funcs pieced_value_funcs = {
  read_pieced_value,
  write_pieced_value,
  indirect_pieced_value,
  coerce_pieced_ref,
  check_pieced_synthetic_pointer,
  copy_pieced_value_closure,
  free_pieced_value_closure
};

/* Given context CTX, section offset SECT_OFF, and compilation unit
   data PER_CU, execute the "variable value" operation on the DIE
   found at SECT_OFF.  */

static struct value *
sect_variable_value (sect_offset sect_off,
		     dwarf2_per_cu_data *per_cu,
		     dwarf2_per_objfile *per_objfile)
{
  struct type *die_type
    = dwarf2_fetch_die_type_sect_off (sect_off, per_cu, per_objfile);

  if (die_type == NULL)
    error (_("Bad DW_OP_GNU_variable_value DIE."));

  /* Note: Things still work when the following test is removed.  This
     test and error is here to conform to the proposed specification.  */
  if (die_type->code () != TYPE_CODE_INT
      && die_type->code () != TYPE_CODE_PTR)
    error (_("Type of DW_OP_GNU_variable_value DIE must be an integer or pointer."));

  struct type *type = lookup_pointer_type (die_type);
  struct frame_info *frame = get_selected_frame (_("No frame selected."));
  return indirect_synthetic_pointer (sect_off, 0, per_cu, per_objfile, frame,
				     type, true);
}

/* Return the type used for DWARF operations where the type is
   unspecified in the DWARF spec.  Only certain sizes are
   supported.  */

struct type *
dwarf_expr_context::address_type () const
{
  return ::address_type (this->gdbarch, this->addr_size);
}

/* Create a new context for the expression evaluator.  */

dwarf_expr_context::dwarf_expr_context (dwarf2_per_objfile *per_objfile,
					int addr_size)
: gdbarch (per_objfile->objfile->arch ()),
  addr_size (addr_size),
  per_objfile (per_objfile)
{
}

/* Push VALUE onto the stack.  */

void
dwarf_expr_context::push (struct value *value, bool in_stack_memory)
{
  stack.emplace_back (value, in_stack_memory);
}

/* Push VALUE onto the stack.  */

void
dwarf_expr_context::push_address (CORE_ADDR value, bool in_stack_memory)
{
  push (value_from_ulongest (address_type (), value), in_stack_memory);
}

/* Pop the top item off of the stack.  */

void
dwarf_expr_context::pop ()
{
  if (stack.empty ())
    error (_("dwarf expression stack underflow"));

  stack.pop_back ();
}

/* Retrieve the N'th item on the stack.  */

struct value *
dwarf_expr_context::fetch (int n)
{
  if (stack.size () <= n)
     error (_("Asked for position %d of stack, "
	      "stack only has %zu elements on it."),
	    n, stack.size ());
  return stack[stack.size () - (1 + n)].value;
}

/* See expr.h.  */

void
dwarf_expr_context::get_frame_base (const gdb_byte **start,
				    size_t * length)
{
  ensure_have_frame (frame, "DW_OP_fbreg");

  const struct block *bl = get_frame_block (frame, NULL);

  if (bl == NULL)
    error (_("frame address is not available."));

  /* Use block_linkage_function, which returns a real (not inlined)
     function, instead of get_frame_function, which may return an
     inlined function.  */
  struct symbol *framefunc = block_linkage_function (bl);

  /* If we found a frame-relative symbol then it was certainly within
     some function associated with a frame. If we can't find the frame,
     something has gone wrong.  */
  gdb_assert (framefunc != NULL);

  func_get_frame_base_dwarf_block (framefunc,
				   get_frame_address_in_block (frame),
				   start, length);
}

/* See expr.h.  */

struct type *
dwarf_expr_context::get_base_type (cu_offset die_cu_off, int size)
{
  if (per_cu == nullptr)
    return builtin_type (this->gdbarch)->builtin_int;

  struct type *result = dwarf2_get_die_type (die_cu_off, per_cu, per_objfile);

  if (result == NULL)
    error (_("Could not find type for DW_OP_const_type"));

  if (size != 0 && TYPE_LENGTH (result) != size)
    error (_("DW_OP_const_type has different sizes for type and data"));

  return result;
}

/* See expr.h.  */

void
dwarf_expr_context::dwarf_call (cu_offset die_cu_off)
{
  ensure_have_per_cu (per_cu, "DW_OP_call");

  struct frame_info *frame = this->frame;

  auto get_pc_from_frame = [frame] ()
    {
      ensure_have_frame (frame, "DW_OP_call");
      return get_frame_address_in_block (frame);
    };

  struct dwarf2_locexpr_baton block
    = dwarf2_fetch_die_loc_cu_off (die_cu_off, per_cu, per_objfile,
				   get_pc_from_frame);

  /* DW_OP_call_ref is currently not supported.  */
  gdb_assert (block.per_cu == per_cu);

  this->eval (block.data, block.size);
}

/* See expr.h.  */

void
dwarf_expr_context::read_mem (gdb_byte *buf, CORE_ADDR addr,
			      size_t length)
{
  if (length == 0)
    return;

  /* Prefer the passed-in memory, if it exists.  */
  if (addr_info != nullptr)
    {
      CORE_ADDR offset = addr - addr_info->addr;

      if (offset < addr_info->valaddr.size ()
	  && offset + length <= addr_info->valaddr.size ())
    {
      memcpy (buf, addr_info->valaddr.data (), length);
      return;
    }
    }

  read_memory (addr, buf, length);
}

/* See expr.h.  */

void
dwarf_expr_context::push_dwarf_reg_entry_value
		      (enum call_site_parameter_kind kind,
		       union call_site_parameter_u kind_u,
		       int deref_size)
{
  ensure_have_per_cu (per_cu, "DW_OP_entry_value");
  ensure_have_frame (frame, "DW_OP_entry_value");

  dwarf2_per_cu_data *caller_per_cu;
  dwarf2_per_objfile *caller_per_objfile;
  struct frame_info *caller_frame = get_prev_frame (frame);
  struct call_site_parameter *parameter
    = dwarf_expr_reg_to_entry_parameter (frame, kind, kind_u,
					 &caller_per_cu,
					 &caller_per_objfile);
  const gdb_byte *data_src
    = deref_size == -1 ? parameter->value : parameter->data_value;
  size_t size
    = deref_size == -1 ? parameter->value_size : parameter->data_value_size;

  /* DEREF_SIZE size is not verified here.  */
  if (data_src == NULL)
    throw_error (NO_ENTRY_VALUE_ERROR,
		 _("Cannot resolve DW_AT_call_data_value"));

  /* We are about to evaluate an expression in the context of the caller
     of the current frame.  This evaluation context may be different from
     the current (callee's) context), so temporarily set the caller's context.

     It is possible for the caller to be from a different objfile from the
     callee if the call is made through a function pointer.  */
  scoped_restore save_frame = make_scoped_restore (&this->frame,
						   caller_frame);
  scoped_restore save_per_cu = make_scoped_restore (&this->per_cu,
						    caller_per_cu);
  scoped_restore save_addr_info = make_scoped_restore (&this->addr_info,
						       nullptr);
  scoped_restore save_per_objfile = make_scoped_restore (&this->per_objfile,
							 caller_per_objfile);

  scoped_restore save_arch = make_scoped_restore (&this->gdbarch);
  this->gdbarch = this->per_objfile->objfile->arch ();
  scoped_restore save_addr_size = make_scoped_restore (&this->addr_size);
  this->addr_size = this->per_cu->addr_size ();

  this->eval (data_src, size);
}

/* See expr.h.  */

struct value *
dwarf_expr_context::fetch_result (struct type *type,
				  struct type *subobj_type,
				  LONGEST subobj_offset,
				  bool as_lval)
{
  struct value *retval = nullptr;

  if (type == nullptr)
    type = address_type ();

  if (subobj_type == nullptr)
    subobj_type = type;

  if (this->pieces.size () > 0)
    {
      struct piece_closure *c;
      ULONGEST bit_size = 0;

      for (dwarf_expr_piece &piece : this->pieces)
	bit_size += piece.size;
      /* Complain if the expression is larger than the size of the
	 outer type.  */
      if (bit_size > 8 * TYPE_LENGTH (type))
	invalid_synthetic_pointer ();

      c = allocate_piece_closure (this->per_cu, this->per_objfile,
				  std::move (this->pieces), this->frame);
      retval = allocate_computed_value (subobj_type,
					&pieced_value_funcs, c);
      set_value_offset (retval, subobj_offset);
    }
  else
    {
      /* If AS_LVAL is false, means that the implicit conversion
	 from a location description to value is expected.  */
      if (as_lval == false)
	this->location = DWARF_VALUE_STACK;

      switch (this->location)
	{
	case DWARF_VALUE_REGISTER:
	  {
	    int dwarf_regnum
	      = longest_to_int (value_as_long (this->fetch (0)));
	    int gdb_regnum = dwarf_reg_to_regnum_or_error (this->gdbarch,
							   dwarf_regnum);

	    if (subobj_offset != 0)
	      error (_("cannot use offset on synthetic pointer to register"));

	    gdb_assert (this->frame != NULL);

	    retval = value_from_register (subobj_type, gdb_regnum,
					  this->frame);
	    if (value_optimized_out (retval))
	      {
		struct value *tmp;

		/* This means the register has undefined value / was
		   not saved.  As we're computing the location of some
		   variable etc. in the program, not a value for
		   inspecting a register ($pc, $sp, etc.), return a
		   generic optimized out value instead, so that we show
		   <optimized out> instead of <not saved>.  */
		tmp = allocate_value (subobj_type);
		value_contents_copy (tmp, 0, retval, 0,
				     TYPE_LENGTH (subobj_type));
		retval = tmp;
	      }
	  }
	  break;

	case DWARF_VALUE_MEMORY:
	  {
	    struct type *ptr_type;
	    CORE_ADDR address = this->fetch_address (0);
	    bool in_stack_memory = this->fetch_in_stack_memory (0);

	    /* DW_OP_deref_size (and possibly other operations too) may
	       create a pointer instead of an address.  Ideally, the
	       pointer to address conversion would be performed as part
	       of those operations, but the type of the object to
	       which the address refers is not known at the time of
	       the operation.  Therefore, we do the conversion here
	       since the type is readily available.  */

	    switch (subobj_type->code ())
	      {
		case TYPE_CODE_FUNC:
		case TYPE_CODE_METHOD:
		  ptr_type = builtin_type (this->gdbarch)->builtin_func_ptr;
		  break;
		default:
		  ptr_type = builtin_type (this->gdbarch)->builtin_data_ptr;
		  break;
	      }
	    address = value_as_address (value_from_pointer (ptr_type, address));

	    retval = value_at_lazy (subobj_type,
				    address + subobj_offset);
	    if (in_stack_memory)
	      set_value_stack (retval, 1);
	  }
	  break;

	case DWARF_VALUE_STACK:
	  {
	    struct value *value = this->fetch (0);
	    size_t n = TYPE_LENGTH (value_type (value));
	    size_t len = TYPE_LENGTH (subobj_type);
	    size_t max = TYPE_LENGTH (type);

	    if (subobj_offset + len > max)
	      invalid_synthetic_pointer ();

	    retval = allocate_value (subobj_type);

	    /* The given offset is relative to the actual object.  */
	    if (gdbarch_byte_order (this->gdbarch) == BFD_ENDIAN_BIG)
	      subobj_offset += n - max;

	    memcpy (value_contents_raw (retval),
		    value_contents_all (value) + subobj_offset, len);
	  }
	  break;

	case DWARF_VALUE_LITERAL:
	  {
	    bfd_byte *contents;
	    size_t n = TYPE_LENGTH (subobj_type);

	    if (subobj_offset + n > this->len)
	      invalid_synthetic_pointer ();

	    retval = allocate_value (subobj_type);
	    contents = value_contents_raw (retval);
	    memcpy (contents, this->data + subobj_offset, n);
	  }
	  break;

	case DWARF_VALUE_OPTIMIZED_OUT:
	  retval = allocate_optimized_out_value (subobj_type);
	  break;

	  /* DWARF_VALUE_IMPLICIT_POINTER was converted to a pieced
	     operation by execute_stack_op.  */
	case DWARF_VALUE_IMPLICIT_POINTER:
	  /* DWARF_VALUE_OPTIMIZED_OUT can't occur in this context --
	     it can only be encountered when making a piece.  */
	default:
	  internal_error (__FILE__, __LINE__, _("invalid location type"));
	}
    }

  set_value_initialized (retval, this->initialized);

  return retval;
}

/* See expr.h.  */

struct value *
dwarf_expr_context::evaluate (const gdb_byte *addr, size_t len, bool as_lval,
			      struct dwarf2_per_cu_data *per_cu,
			      struct frame_info *frame,
			      const struct property_addr_info *addr_info,
			      struct type *type,
			      struct type *subobj_type,
			      LONGEST subobj_offset)
{
  this->per_cu = per_cu;
  this->frame = frame;
  this->addr_info = addr_info;

  if (per_cu != nullptr)
    this->ref_addr_size = per_cu->ref_addr_size ();

  eval (addr, len);
  return fetch_result (type, subobj_type, subobj_offset, as_lval);
}

/* Require that TYPE be an integral type; throw an exception if not.  */

static void
dwarf_require_integral (struct type *type)
{
  if (type->code () != TYPE_CODE_INT
      && type->code () != TYPE_CODE_CHAR
      && type->code () != TYPE_CODE_BOOL)
    error (_("integral type expected in DWARF expression"));
}

/* Return the unsigned form of TYPE.  TYPE is necessarily an integral
   type.  */

static struct type *
get_unsigned_type (struct gdbarch *gdbarch, struct type *type)
{
  switch (TYPE_LENGTH (type))
    {
    case 1:
      return builtin_type (gdbarch)->builtin_uint8;
    case 2:
      return builtin_type (gdbarch)->builtin_uint16;
    case 4:
      return builtin_type (gdbarch)->builtin_uint32;
    case 8:
      return builtin_type (gdbarch)->builtin_uint64;
    default:
      error (_("no unsigned variant found for type, while evaluating "
	       "DWARF expression"));
    }
}

/* Return the signed form of TYPE.  TYPE is necessarily an integral
   type.  */

static struct type *
get_signed_type (struct gdbarch *gdbarch, struct type *type)
{
  switch (TYPE_LENGTH (type))
    {
    case 1:
      return builtin_type (gdbarch)->builtin_int8;
    case 2:
      return builtin_type (gdbarch)->builtin_int16;
    case 4:
      return builtin_type (gdbarch)->builtin_int32;
    case 8:
      return builtin_type (gdbarch)->builtin_int64;
    default:
      error (_("no signed variant found for type, while evaluating "
	       "DWARF expression"));
    }
}

/* Retrieve the N'th item on the stack, converted to an address.  */

CORE_ADDR
dwarf_expr_context::fetch_address (int n)
{
  struct value *result_val = fetch (n);
  enum bfd_endian byte_order = gdbarch_byte_order (this->gdbarch);
  ULONGEST result;

  dwarf_require_integral (value_type (result_val));
  result = extract_unsigned_integer (value_contents (result_val),
				     TYPE_LENGTH (value_type (result_val)),
				     byte_order);

  /* For most architectures, calling extract_unsigned_integer() alone
     is sufficient for extracting an address.  However, some
     architectures (e.g. MIPS) use signed addresses and using
     extract_unsigned_integer() will not produce a correct
     result.  Make sure we invoke gdbarch_integer_to_address()
     for those architectures which require it.  */
  if (gdbarch_integer_to_address_p (this->gdbarch))
    {
      gdb_byte *buf = (gdb_byte *) alloca (this->addr_size);
      struct type *int_type = get_unsigned_type (this->gdbarch,
						 value_type (result_val));

      store_unsigned_integer (buf, this->addr_size, byte_order, result);
      return gdbarch_integer_to_address (this->gdbarch, int_type, buf);
    }

  return (CORE_ADDR) result;
}

/* Retrieve the in_stack_memory flag of the N'th item on the stack.  */

bool
dwarf_expr_context::fetch_in_stack_memory (int n)
{
  if (stack.size () <= n)
     error (_("Asked for position %d of stack, "
	      "stack only has %zu elements on it."),
	    n, stack.size ());
  return stack[stack.size () - (1 + n)].in_stack_memory;
}

/* Return true if the expression stack is empty.  */

bool
dwarf_expr_context::stack_empty_p () const
{
  return stack.empty ();
}

/* Add a new piece to the dwarf_expr_context's piece list.  */
void
dwarf_expr_context::add_piece (ULONGEST size, ULONGEST offset)
{
  this->pieces.emplace_back ();
  dwarf_expr_piece &p = this->pieces.back ();

  p.location = this->location;
  p.size = size;
  p.offset = offset;

  if (p.location == DWARF_VALUE_LITERAL)
    {
      p.v.literal.data = this->data;
      p.v.literal.length = this->len;
    }
  else if (stack_empty_p ())
    {
      p.location = DWARF_VALUE_OPTIMIZED_OUT;
      /* Also reset the context's location, for our callers.  This is
	 a somewhat strange approach, but this lets us avoid setting
	 the location to DWARF_VALUE_MEMORY in all the individual
	 cases in the evaluator.  */
      this->location = DWARF_VALUE_OPTIMIZED_OUT;
    }
  else if (p.location == DWARF_VALUE_MEMORY)
    {
      p.v.mem.addr = fetch_address (0);
      p.v.mem.in_stack_memory = fetch_in_stack_memory (0);
    }
  else if (p.location == DWARF_VALUE_IMPLICIT_POINTER)
    {
      p.v.ptr.die_sect_off = (sect_offset) this->len;
      p.v.ptr.offset = value_as_long (fetch (0));
    }
  else if (p.location == DWARF_VALUE_REGISTER)
    p.v.regno = value_as_long (fetch (0));
  else
    {
      p.v.value = fetch (0);
    }
}

/* Evaluate the expression at ADDR (LEN bytes long).  */

void
dwarf_expr_context::eval (const gdb_byte *addr, size_t len)
{
  int old_recursion_depth = this->recursion_depth;

  execute_stack_op (addr, addr + len);

  /* RECURSION_DEPTH becomes invalid if an exception was thrown here.  */

  gdb_assert (this->recursion_depth == old_recursion_depth);
}

/* Helper to read a uleb128 value or throw an error.  */

const gdb_byte *
safe_read_uleb128 (const gdb_byte *buf, const gdb_byte *buf_end,
		   uint64_t *r)
{
  buf = gdb_read_uleb128 (buf, buf_end, r);
  if (buf == NULL)
    error (_("DWARF expression error: ran off end of buffer reading uleb128 value"));
  return buf;
}

/* Helper to read a sleb128 value or throw an error.  */

const gdb_byte *
safe_read_sleb128 (const gdb_byte *buf, const gdb_byte *buf_end,
		   int64_t *r)
{
  buf = gdb_read_sleb128 (buf, buf_end, r);
  if (buf == NULL)
    error (_("DWARF expression error: ran off end of buffer reading sleb128 value"));
  return buf;
}

const gdb_byte *
safe_skip_leb128 (const gdb_byte *buf, const gdb_byte *buf_end)
{
  buf = gdb_skip_leb128 (buf, buf_end);
  if (buf == NULL)
    error (_("DWARF expression error: ran off end of buffer reading leb128 value"));
  return buf;
}


/* Check that the current operator is either at the end of an
   expression, or that it is followed by a composition operator or by
   DW_OP_GNU_uninit (which should terminate the expression).  */

void
dwarf_expr_require_composition (const gdb_byte *op_ptr, const gdb_byte *op_end,
				const char *op_name)
{
  if (op_ptr != op_end && *op_ptr != DW_OP_piece && *op_ptr != DW_OP_bit_piece
      && *op_ptr != DW_OP_GNU_uninit)
    error (_("DWARF-2 expression error: `%s' operations must be "
	     "used either alone or in conjunction with DW_OP_piece "
	     "or DW_OP_bit_piece."),
	   op_name);
}

/* Return true iff the types T1 and T2 are "the same".  This only does
   checks that might reasonably be needed to compare DWARF base
   types.  */

static int
base_types_equal_p (struct type *t1, struct type *t2)
{
  if (t1->code () != t2->code ())
    return 0;
  if (t1->is_unsigned () != t2->is_unsigned ())
    return 0;
  return TYPE_LENGTH (t1) == TYPE_LENGTH (t2);
}

/* If <BUF..BUF_END] contains DW_FORM_block* with single DW_OP_reg* return the
   DWARF register number.  Otherwise return -1.  */

int
dwarf_block_to_dwarf_reg (const gdb_byte *buf, const gdb_byte *buf_end)
{
  uint64_t dwarf_reg;

  if (buf_end <= buf)
    return -1;
  if (*buf >= DW_OP_reg0 && *buf <= DW_OP_reg31)
    {
      if (buf_end - buf != 1)
	return -1;
      return *buf - DW_OP_reg0;
    }

  if (*buf == DW_OP_regval_type || *buf == DW_OP_GNU_regval_type)
    {
      buf++;
      buf = gdb_read_uleb128 (buf, buf_end, &dwarf_reg);
      if (buf == NULL)
	return -1;
      buf = gdb_skip_leb128 (buf, buf_end);
      if (buf == NULL)
	return -1;
    }
  else if (*buf == DW_OP_regx)
    {
      buf++;
      buf = gdb_read_uleb128 (buf, buf_end, &dwarf_reg);
      if (buf == NULL)
	return -1;
    }
  else
    return -1;
  if (buf != buf_end || (int) dwarf_reg != dwarf_reg)
    return -1;
  return dwarf_reg;
}

/* If <BUF..BUF_END] contains DW_FORM_block* with just DW_OP_breg*(0) and
   DW_OP_deref* return the DWARF register number.  Otherwise return -1.
   DEREF_SIZE_RETURN contains -1 for DW_OP_deref; otherwise it contains the
   size from DW_OP_deref_size.  */

int
dwarf_block_to_dwarf_reg_deref (const gdb_byte *buf, const gdb_byte *buf_end,
				CORE_ADDR *deref_size_return)
{
  uint64_t dwarf_reg;
  int64_t offset;

  if (buf_end <= buf)
    return -1;

  if (*buf >= DW_OP_breg0 && *buf <= DW_OP_breg31)
    {
      dwarf_reg = *buf - DW_OP_breg0;
      buf++;
      if (buf >= buf_end)
	return -1;
    }
  else if (*buf == DW_OP_bregx)
    {
      buf++;
      buf = gdb_read_uleb128 (buf, buf_end, &dwarf_reg);
      if (buf == NULL)
	return -1;
      if ((int) dwarf_reg != dwarf_reg)
       return -1;
    }
  else
    return -1;

  buf = gdb_read_sleb128 (buf, buf_end, &offset);
  if (buf == NULL)
    return -1;
  if (offset != 0)
    return -1;

  if (*buf == DW_OP_deref)
    {
      buf++;
      *deref_size_return = -1;
    }
  else if (*buf == DW_OP_deref_size)
    {
      buf++;
      if (buf >= buf_end)
       return -1;
      *deref_size_return = *buf++;
    }
  else
    return -1;

  if (buf != buf_end)
    return -1;

  return dwarf_reg;
}

/* If <BUF..BUF_END] contains DW_FORM_block* with single DW_OP_fbreg(X) fill
   in FB_OFFSET_RETURN with the X offset and return 1.  Otherwise return 0.  */

int
dwarf_block_to_fb_offset (const gdb_byte *buf, const gdb_byte *buf_end,
			  CORE_ADDR *fb_offset_return)
{
  int64_t fb_offset;

  if (buf_end <= buf)
    return 0;

  if (*buf != DW_OP_fbreg)
    return 0;
  buf++;

  buf = gdb_read_sleb128 (buf, buf_end, &fb_offset);
  if (buf == NULL)
    return 0;
  *fb_offset_return = fb_offset;
  if (buf != buf_end || fb_offset != (LONGEST) *fb_offset_return)
    return 0;

  return 1;
}

/* If <BUF..BUF_END] contains DW_FORM_block* with single DW_OP_bregSP(X) fill
   in SP_OFFSET_RETURN with the X offset and return 1.  Otherwise return 0.
   The matched SP register number depends on GDBARCH.  */

int
dwarf_block_to_sp_offset (struct gdbarch *gdbarch, const gdb_byte *buf,
			  const gdb_byte *buf_end, CORE_ADDR *sp_offset_return)
{
  uint64_t dwarf_reg;
  int64_t sp_offset;

  if (buf_end <= buf)
    return 0;
  if (*buf >= DW_OP_breg0 && *buf <= DW_OP_breg31)
    {
      dwarf_reg = *buf - DW_OP_breg0;
      buf++;
    }
  else
    {
      if (*buf != DW_OP_bregx)
       return 0;
      buf++;
      buf = gdb_read_uleb128 (buf, buf_end, &dwarf_reg);
      if (buf == NULL)
	return 0;
    }

  if (dwarf_reg_to_regnum (gdbarch, dwarf_reg)
      != gdbarch_sp_regnum (gdbarch))
    return 0;

  buf = gdb_read_sleb128 (buf, buf_end, &sp_offset);
  if (buf == NULL)
    return 0;
  *sp_offset_return = sp_offset;
  if (buf != buf_end || sp_offset != (LONGEST) *sp_offset_return)
    return 0;

  return 1;
}

/* The engine for the expression evaluator.  Using the context in this
   object, evaluate the expression between OP_PTR and OP_END.  */

void
dwarf_expr_context::execute_stack_op (const gdb_byte *op_ptr,
				      const gdb_byte *op_end)
{
  enum bfd_endian byte_order = gdbarch_byte_order (this->gdbarch);
  /* Old-style "untyped" DWARF values need special treatment in a
     couple of places, specifically DW_OP_mod and DW_OP_shr.  We need
     a special type for these values so we can distinguish them from
     values that have an explicit type, because explicitly-typed
     values do not need special treatment.  This special type must be
     different (in the `==' sense) from any base type coming from the
     CU.  */
  struct type *address_type = this->address_type ();

  this->location = DWARF_VALUE_MEMORY;
  this->initialized = 1;  /* Default is initialized.  */

  if (this->recursion_depth > this->max_recursion_depth)
    error (_("DWARF-2 expression error: Loop detected (%d)."),
	   this->recursion_depth);
  this->recursion_depth++;

  while (op_ptr < op_end)
    {
      enum dwarf_location_atom op = (enum dwarf_location_atom) *op_ptr++;
      ULONGEST result;
      /* Assume the value is not in stack memory.
	 Code that knows otherwise sets this to true.
	 Some arithmetic on stack addresses can probably be assumed to still
	 be a stack address, but we skip this complication for now.
	 This is just an optimization, so it's always ok to punt
	 and leave this as false.  */
      bool in_stack_memory = false;
      uint64_t uoffset, reg;
      int64_t offset;
      struct value *result_val = NULL;

      /* The DWARF expression might have a bug causing an infinite
	 loop.  In that case, quitting is the only way out.  */
      QUIT;

      switch (op)
	{
	case DW_OP_lit0:
	case DW_OP_lit1:
	case DW_OP_lit2:
	case DW_OP_lit3:
	case DW_OP_lit4:
	case DW_OP_lit5:
	case DW_OP_lit6:
	case DW_OP_lit7:
	case DW_OP_lit8:
	case DW_OP_lit9:
	case DW_OP_lit10:
	case DW_OP_lit11:
	case DW_OP_lit12:
	case DW_OP_lit13:
	case DW_OP_lit14:
	case DW_OP_lit15:
	case DW_OP_lit16:
	case DW_OP_lit17:
	case DW_OP_lit18:
	case DW_OP_lit19:
	case DW_OP_lit20:
	case DW_OP_lit21:
	case DW_OP_lit22:
	case DW_OP_lit23:
	case DW_OP_lit24:
	case DW_OP_lit25:
	case DW_OP_lit26:
	case DW_OP_lit27:
	case DW_OP_lit28:
	case DW_OP_lit29:
	case DW_OP_lit30:
	case DW_OP_lit31:
	  result = op - DW_OP_lit0;
	  result_val = value_from_ulongest (address_type, result);
	  break;

	case DW_OP_addr:
	  result = extract_unsigned_integer (op_ptr,
					     this->addr_size, byte_order);
	  op_ptr += this->addr_size;
	  /* Some versions of GCC emit DW_OP_addr before
	     DW_OP_GNU_push_tls_address.  In this case the value is an
	     index, not an address.  We don't support things like
	     branching between the address and the TLS op.  */
	  if (op_ptr >= op_end || *op_ptr != DW_OP_GNU_push_tls_address)
	    result += this->per_objfile->objfile->text_section_offset ();
	  result_val = value_from_ulongest (address_type, result);
	  break;

	case DW_OP_addrx:
	case DW_OP_GNU_addr_index:
	  ensure_have_per_cu (this->per_cu, "DW_OP_addrx");

	  op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
	  result = dwarf2_read_addr_index (this->per_cu, this->per_objfile,
					   uoffset);
	  result += this->per_objfile->objfile->text_section_offset ();
	  result_val = value_from_ulongest (address_type, result);
	  break;
	case DW_OP_GNU_const_index:
	  ensure_have_per_cu (per_cu, "DW_OP_GNU_const_index");

	  op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
	  result = dwarf2_read_addr_index (this->per_cu, this->per_objfile,
					   uoffset);
	  result_val = value_from_ulongest (address_type, result);
	  break;

	case DW_OP_const1u:
	  result = extract_unsigned_integer (op_ptr, 1, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 1;
	  break;
	case DW_OP_const1s:
	  result = extract_signed_integer (op_ptr, 1, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 1;
	  break;
	case DW_OP_const2u:
	  result = extract_unsigned_integer (op_ptr, 2, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 2;
	  break;
	case DW_OP_const2s:
	  result = extract_signed_integer (op_ptr, 2, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 2;
	  break;
	case DW_OP_const4u:
	  result = extract_unsigned_integer (op_ptr, 4, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 4;
	  break;
	case DW_OP_const4s:
	  result = extract_signed_integer (op_ptr, 4, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 4;
	  break;
	case DW_OP_const8u:
	  result = extract_unsigned_integer (op_ptr, 8, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 8;
	  break;
	case DW_OP_const8s:
	  result = extract_signed_integer (op_ptr, 8, byte_order);
	  result_val = value_from_ulongest (address_type, result);
	  op_ptr += 8;
	  break;
	case DW_OP_constu:
	  op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
	  result = uoffset;
	  result_val = value_from_ulongest (address_type, result);
	  break;
	case DW_OP_consts:
	  op_ptr = safe_read_sleb128 (op_ptr, op_end, &offset);
	  result = offset;
	  result_val = value_from_ulongest (address_type, result);
	  break;

	/* The DW_OP_reg operations are required to occur alone in
	   location expressions.  */
	case DW_OP_reg0:
	case DW_OP_reg1:
	case DW_OP_reg2:
	case DW_OP_reg3:
	case DW_OP_reg4:
	case DW_OP_reg5:
	case DW_OP_reg6:
	case DW_OP_reg7:
	case DW_OP_reg8:
	case DW_OP_reg9:
	case DW_OP_reg10:
	case DW_OP_reg11:
	case DW_OP_reg12:
	case DW_OP_reg13:
	case DW_OP_reg14:
	case DW_OP_reg15:
	case DW_OP_reg16:
	case DW_OP_reg17:
	case DW_OP_reg18:
	case DW_OP_reg19:
	case DW_OP_reg20:
	case DW_OP_reg21:
	case DW_OP_reg22:
	case DW_OP_reg23:
	case DW_OP_reg24:
	case DW_OP_reg25:
	case DW_OP_reg26:
	case DW_OP_reg27:
	case DW_OP_reg28:
	case DW_OP_reg29:
	case DW_OP_reg30:
	case DW_OP_reg31:
	  dwarf_expr_require_composition (op_ptr, op_end, "DW_OP_reg");

	  result = op - DW_OP_reg0;
	  result_val = value_from_ulongest (address_type, result);
	  this->location = DWARF_VALUE_REGISTER;
	  break;

	case DW_OP_regx:
	  op_ptr = safe_read_uleb128 (op_ptr, op_end, &reg);
	  dwarf_expr_require_composition (op_ptr, op_end, "DW_OP_regx");

	  result = reg;
	  result_val = value_from_ulongest (address_type, result);
	  this->location = DWARF_VALUE_REGISTER;
	  break;

	case DW_OP_implicit_value:
	  {
	    uint64_t len;

	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &len);
	    if (op_ptr + len > op_end)
	      error (_("DW_OP_implicit_value: too few bytes available."));
	    this->len = len;
	    this->data = op_ptr;
	    this->location = DWARF_VALUE_LITERAL;
	    op_ptr += len;
	    dwarf_expr_require_composition (op_ptr, op_end,
					    "DW_OP_implicit_value");
	  }
	  goto no_push;

	case DW_OP_stack_value:
	  this->location = DWARF_VALUE_STACK;
	  dwarf_expr_require_composition (op_ptr, op_end, "DW_OP_stack_value");
	  goto no_push;

	case DW_OP_implicit_pointer:
	case DW_OP_GNU_implicit_pointer:
	  {
	    int64_t len;
	    ensure_have_per_cu (per_cu, "DW_OP_implicit_pointer");

	    /* The referred-to DIE of sect_offset kind.  */
	    this->len = extract_unsigned_integer (op_ptr, this->ref_addr_size,
						 byte_order);
	    op_ptr += this->ref_addr_size;

	    /* The byte offset into the data.  */
	    op_ptr = safe_read_sleb128 (op_ptr, op_end, &len);
	    result = (ULONGEST) len;
	    result_val = value_from_ulongest (address_type, result);

	    this->location = DWARF_VALUE_IMPLICIT_POINTER;
	    dwarf_expr_require_composition (op_ptr, op_end,
					    "DW_OP_implicit_pointer");
	  }
	  break;

	case DW_OP_breg0:
	case DW_OP_breg1:
	case DW_OP_breg2:
	case DW_OP_breg3:
	case DW_OP_breg4:
	case DW_OP_breg5:
	case DW_OP_breg6:
	case DW_OP_breg7:
	case DW_OP_breg8:
	case DW_OP_breg9:
	case DW_OP_breg10:
	case DW_OP_breg11:
	case DW_OP_breg12:
	case DW_OP_breg13:
	case DW_OP_breg14:
	case DW_OP_breg15:
	case DW_OP_breg16:
	case DW_OP_breg17:
	case DW_OP_breg18:
	case DW_OP_breg19:
	case DW_OP_breg20:
	case DW_OP_breg21:
	case DW_OP_breg22:
	case DW_OP_breg23:
	case DW_OP_breg24:
	case DW_OP_breg25:
	case DW_OP_breg26:
	case DW_OP_breg27:
	case DW_OP_breg28:
	case DW_OP_breg29:
	case DW_OP_breg30:
	case DW_OP_breg31:
	  {
	    op_ptr = safe_read_sleb128 (op_ptr, op_end, &offset);
	    ensure_have_frame (this->frame, "DW_OP_breg");

	    result = read_addr_from_reg (this->frame, op - DW_OP_breg0);
	    result += offset;
	    result_val = value_from_ulongest (address_type, result);
	  }
	  break;
	case DW_OP_bregx:
	  {
	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &reg);
	    op_ptr = safe_read_sleb128 (op_ptr, op_end, &offset);
	    ensure_have_frame (this->frame, "DW_OP_bregx");

	    result = read_addr_from_reg (this->frame, reg);
	    result += offset;
	    result_val = value_from_ulongest (address_type, result);
	  }
	  break;
	case DW_OP_fbreg:
	  {
	    const gdb_byte *datastart;
	    size_t datalen;

	    op_ptr = safe_read_sleb128 (op_ptr, op_end, &offset);

	    /* Rather than create a whole new context, we simply
	       backup the current stack locally and install a new empty stack,
	       then reset it afterwards, effectively erasing whatever the
	       recursive call put there.  */
	    std::vector<dwarf_stack_value> saved_stack = std::move (stack);
	    stack.clear ();

	    /* FIXME: cagney/2003-03-26: This code should be using
	       get_frame_base_address(), and then implement a dwarf2
	       specific this_base method.  */
	    this->get_frame_base (&datastart, &datalen);
	    eval (datastart, datalen);
	    if (this->location == DWARF_VALUE_MEMORY)
	      result = fetch_address (0);
	    else if (this->location == DWARF_VALUE_REGISTER)
	      result = read_addr_from_reg (this->frame, value_as_long (fetch (0)));
	    else
	      error (_("Not implemented: computing frame "
		       "base using explicit value operator"));
	    result = result + offset;
	    result_val = value_from_ulongest (address_type, result);
	    in_stack_memory = true;

	    /* Restore the content of the original stack.  */
	    stack = std::move (saved_stack);

	    this->location = DWARF_VALUE_MEMORY;
	  }
	  break;

	case DW_OP_dup:
	  result_val = fetch (0);
	  in_stack_memory = fetch_in_stack_memory (0);
	  break;

	case DW_OP_drop:
	  pop ();
	  goto no_push;

	case DW_OP_pick:
	  offset = *op_ptr++;
	  result_val = fetch (offset);
	  in_stack_memory = fetch_in_stack_memory (offset);
	  break;
	  
	case DW_OP_swap:
	  {
	    if (stack.size () < 2)
	       error (_("Not enough elements for "
			"DW_OP_swap.  Need 2, have %zu."),
		      stack.size ());

	    dwarf_stack_value &t1 = stack[stack.size () - 1];
	    dwarf_stack_value &t2 = stack[stack.size () - 2];
	    std::swap (t1, t2);
	    goto no_push;
	  }

	case DW_OP_over:
	  result_val = fetch (1);
	  in_stack_memory = fetch_in_stack_memory (1);
	  break;

	case DW_OP_rot:
	  {
	    if (stack.size () < 3)
	       error (_("Not enough elements for "
			"DW_OP_rot.  Need 3, have %zu."),
		      stack.size ());

	    dwarf_stack_value temp = stack[stack.size () - 1];
	    stack[stack.size () - 1] = stack[stack.size () - 2];
	    stack[stack.size () - 2] = stack[stack.size () - 3];
	    stack[stack.size () - 3] = temp;
	    goto no_push;
	  }

	case DW_OP_deref:
	case DW_OP_deref_size:
	case DW_OP_deref_type:
	case DW_OP_GNU_deref_type:
	  {
	    int addr_size = (op == DW_OP_deref ? this->addr_size : *op_ptr++);
	    gdb_byte *buf = (gdb_byte *) alloca (addr_size);
	    CORE_ADDR addr = fetch_address (0);
	    struct type *type;

	    pop ();

	    if (op == DW_OP_deref_type || op == DW_OP_GNU_deref_type)
	      {
		op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
		cu_offset type_die_cu_off = (cu_offset) uoffset;
		type = get_base_type (type_die_cu_off, 0);
	      }
	    else
	      type = address_type;

	    this->read_mem (buf, addr, addr_size);

	    /* If the size of the object read from memory is different
	       from the type length, we need to zero-extend it.  */
	    if (TYPE_LENGTH (type) != addr_size)
	      {
		ULONGEST datum =
		  extract_unsigned_integer (buf, addr_size, byte_order);

		buf = (gdb_byte *) alloca (TYPE_LENGTH (type));
		store_unsigned_integer (buf, TYPE_LENGTH (type),
					byte_order, datum);
	      }

	    result_val = value_from_contents_and_address (type, buf, addr);
	    break;
	  }

	case DW_OP_abs:
	case DW_OP_neg:
	case DW_OP_not:
	case DW_OP_plus_uconst:
	  {
	    /* Unary operations.  */
	    result_val = fetch (0);
	    pop ();

	    switch (op)
	      {
	      case DW_OP_abs:
		if (value_less (result_val,
				value_zero (value_type (result_val), not_lval)))
		  result_val = value_neg (result_val);
		break;
	      case DW_OP_neg:
		result_val = value_neg (result_val);
		break;
	      case DW_OP_not:
		dwarf_require_integral (value_type (result_val));
		result_val = value_complement (result_val);
		break;
	      case DW_OP_plus_uconst:
		dwarf_require_integral (value_type (result_val));
		result = value_as_long (result_val);
		op_ptr = safe_read_uleb128 (op_ptr, op_end, &reg);
		result += reg;
		result_val = value_from_ulongest (address_type, result);
		break;
	      }
	  }
	  break;

	case DW_OP_and:
	case DW_OP_div:
	case DW_OP_minus:
	case DW_OP_mod:
	case DW_OP_mul:
	case DW_OP_or:
	case DW_OP_plus:
	case DW_OP_shl:
	case DW_OP_shr:
	case DW_OP_shra:
	case DW_OP_xor:
	case DW_OP_le:
	case DW_OP_ge:
	case DW_OP_eq:
	case DW_OP_lt:
	case DW_OP_gt:
	case DW_OP_ne:
	  {
	    /* Binary operations.  */
	    struct value *first, *second;

	    second = fetch (0);
	    pop ();

	    first = fetch (0);
	    pop ();

	    if (! base_types_equal_p (value_type (first), value_type (second)))
	      error (_("Incompatible types on DWARF stack"));

	    switch (op)
	      {
	      case DW_OP_and:
		dwarf_require_integral (value_type (first));
		dwarf_require_integral (value_type (second));
		result_val = value_binop (first, second, BINOP_BITWISE_AND);
		break;
	      case DW_OP_div:
		result_val = value_binop (first, second, BINOP_DIV);
		break;
	      case DW_OP_minus:
		result_val = value_binop (first, second, BINOP_SUB);
		break;
	      case DW_OP_mod:
		{
		  int cast_back = 0;
		  struct type *orig_type = value_type (first);

		  /* We have to special-case "old-style" untyped values
		     -- these must have mod computed using unsigned
		     math.  */
		  if (orig_type == address_type)
		    {
		      struct type *utype
			= get_unsigned_type (this->gdbarch, orig_type);

		      cast_back = 1;
		      first = value_cast (utype, first);
		      second = value_cast (utype, second);
		    }
		  /* Note that value_binop doesn't handle float or
		     decimal float here.  This seems unimportant.  */
		  result_val = value_binop (first, second, BINOP_MOD);
		  if (cast_back)
		    result_val = value_cast (orig_type, result_val);
		}
		break;
	      case DW_OP_mul:
		result_val = value_binop (first, second, BINOP_MUL);
		break;
	      case DW_OP_or:
		dwarf_require_integral (value_type (first));
		dwarf_require_integral (value_type (second));
		result_val = value_binop (first, second, BINOP_BITWISE_IOR);
		break;
	      case DW_OP_plus:
		result_val = value_binop (first, second, BINOP_ADD);
		break;
	      case DW_OP_shl:
		dwarf_require_integral (value_type (first));
		dwarf_require_integral (value_type (second));
		result_val = value_binop (first, second, BINOP_LSH);
		break;
	      case DW_OP_shr:
		dwarf_require_integral (value_type (first));
		dwarf_require_integral (value_type (second));
		if (!value_type (first)->is_unsigned ())
		  {
		    struct type *utype
		      = get_unsigned_type (this->gdbarch, value_type (first));

		    first = value_cast (utype, first);
		  }

		result_val = value_binop (first, second, BINOP_RSH);
		/* Make sure we wind up with the same type we started
		   with.  */
		if (value_type (result_val) != value_type (second))
		  result_val = value_cast (value_type (second), result_val);
		break;
	      case DW_OP_shra:
		dwarf_require_integral (value_type (first));
		dwarf_require_integral (value_type (second));
		if (value_type (first)->is_unsigned ())
		  {
		    struct type *stype
		      = get_signed_type (this->gdbarch, value_type (first));

		    first = value_cast (stype, first);
		  }

		result_val = value_binop (first, second, BINOP_RSH);
		/* Make sure we wind up with the same type we started
		   with.  */
		if (value_type (result_val) != value_type (second))
		  result_val = value_cast (value_type (second), result_val);
		break;
	      case DW_OP_xor:
		dwarf_require_integral (value_type (first));
		dwarf_require_integral (value_type (second));
		result_val = value_binop (first, second, BINOP_BITWISE_XOR);
		break;
	      case DW_OP_le:
		/* A <= B is !(B < A).  */
		result = ! value_less (second, first);
		result_val = value_from_ulongest (address_type, result);
		break;
	      case DW_OP_ge:
		/* A >= B is !(A < B).  */
		result = ! value_less (first, second);
		result_val = value_from_ulongest (address_type, result);
		break;
	      case DW_OP_eq:
		result = value_equal (first, second);
		result_val = value_from_ulongest (address_type, result);
		break;
	      case DW_OP_lt:
		result = value_less (first, second);
		result_val = value_from_ulongest (address_type, result);
		break;
	      case DW_OP_gt:
		/* A > B is B < A.  */
		result = value_less (second, first);
		result_val = value_from_ulongest (address_type, result);
		break;
	      case DW_OP_ne:
		result = ! value_equal (first, second);
		result_val = value_from_ulongest (address_type, result);
		break;
	      default:
		internal_error (__FILE__, __LINE__,
				_("Can't be reached."));
	      }
	  }
	  break;

	case DW_OP_call_frame_cfa:
	  ensure_have_frame (this->frame, "DW_OP_call_frame_cfa");

	  result = dwarf2_frame_cfa (this->frame);
	  result_val = value_from_ulongest (address_type, result);
	  in_stack_memory = true;
	  break;

	case DW_OP_GNU_push_tls_address:
	case DW_OP_form_tls_address:
	  /* Variable is at a constant offset in the thread-local
	  storage block into the objfile for the current thread and
	  the dynamic linker module containing this expression.  Here
	  we return returns the offset from that base.  The top of the
	  stack has the offset from the beginning of the thread
	  control block at which the variable is located.  Nothing
	  should follow this operator, so the top of stack would be
	  returned.  */
	  result = value_as_long (fetch (0));
	  pop ();
	  result = target_translate_tls_address (this->per_objfile->objfile,
						 result);
	  result_val = value_from_ulongest (address_type, result);
	  break;

	case DW_OP_skip:
	  offset = extract_signed_integer (op_ptr, 2, byte_order);
	  op_ptr += 2;
	  op_ptr += offset;
	  goto no_push;

	case DW_OP_bra:
	  {
	    struct value *val;

	    offset = extract_signed_integer (op_ptr, 2, byte_order);
	    op_ptr += 2;
	    val = fetch (0);
	    dwarf_require_integral (value_type (val));
	    if (value_as_long (val) != 0)
	      op_ptr += offset;
	    pop ();
	  }
	  goto no_push;

	case DW_OP_nop:
	  goto no_push;

	case DW_OP_piece:
	  {
	    uint64_t size;

	    /* Record the piece.  */
	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &size);
	    add_piece (8 * size, 0);

	    /* Pop off the address/regnum, and reset the location
	       type.  */
	    if (this->location != DWARF_VALUE_LITERAL
		&& this->location != DWARF_VALUE_OPTIMIZED_OUT)
	      pop ();
	    this->location = DWARF_VALUE_MEMORY;
	  }
	  goto no_push;

	case DW_OP_bit_piece:
	  {
	    uint64_t size, uleb_offset;

	    /* Record the piece.  */
	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &size);
	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &uleb_offset);
	    add_piece (size, uleb_offset);

	    /* Pop off the address/regnum, and reset the location
	       type.  */
	    if (this->location != DWARF_VALUE_LITERAL
		&& this->location != DWARF_VALUE_OPTIMIZED_OUT)
	      pop ();
	    this->location = DWARF_VALUE_MEMORY;
	  }
	  goto no_push;

	case DW_OP_GNU_uninit:
	  if (op_ptr != op_end)
	    error (_("DWARF-2 expression error: DW_OP_GNU_uninit must always "
		   "be the very last op."));

	  this->initialized = 0;
	  goto no_push;

	case DW_OP_call2:
	  {
	    cu_offset cu_off
	      = (cu_offset) extract_unsigned_integer (op_ptr, 2, byte_order);
	    op_ptr += 2;
	    this->dwarf_call (cu_off);
	  }
	  goto no_push;

	case DW_OP_call4:
	  {
	    cu_offset cu_off
	      = (cu_offset) extract_unsigned_integer (op_ptr, 4, byte_order);
	    op_ptr += 4;
	    this->dwarf_call (cu_off);
	  }
	  goto no_push;

	case DW_OP_GNU_variable_value:
	  {
	    ensure_have_per_cu (per_cu, "DW_OP_GNU_variable_value");

	    sect_offset sect_off
	      = (sect_offset) extract_unsigned_integer (op_ptr,
							this->ref_addr_size,
							byte_order);
	    op_ptr += this->ref_addr_size;
	    result_val = sect_variable_value (sect_off, this->per_cu,
					      this->per_objfile);
	    result_val = value_cast (address_type, result_val);
	  }
	  break;
	
	case DW_OP_entry_value:
	case DW_OP_GNU_entry_value:
	  {
	    uint64_t len;
	    CORE_ADDR deref_size;
	    union call_site_parameter_u kind_u;

	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &len);
	    if (op_ptr + len > op_end)
	      error (_("DW_OP_entry_value: too few bytes available."));

	    kind_u.dwarf_reg = dwarf_block_to_dwarf_reg (op_ptr, op_ptr + len);
	    if (kind_u.dwarf_reg != -1)
	      {
		op_ptr += len;
		this->push_dwarf_reg_entry_value (CALL_SITE_PARAMETER_DWARF_REG,
						  kind_u,
						  -1 /* deref_size */);
		goto no_push;
	      }

	    kind_u.dwarf_reg = dwarf_block_to_dwarf_reg_deref (op_ptr,
							       op_ptr + len,
							       &deref_size);
	    if (kind_u.dwarf_reg != -1)
	      {
		if (deref_size == -1)
		  deref_size = this->addr_size;
		op_ptr += len;
		this->push_dwarf_reg_entry_value (CALL_SITE_PARAMETER_DWARF_REG,
						  kind_u, deref_size);
		goto no_push;
	      }

	    error (_("DWARF-2 expression error: DW_OP_entry_value is "
		     "supported only for single DW_OP_reg* "
		     "or for DW_OP_breg*(0)+DW_OP_deref*"));
	  }

	case DW_OP_GNU_parameter_ref:
	  {
	    union call_site_parameter_u kind_u;

	    kind_u.param_cu_off
	      = (cu_offset) extract_unsigned_integer (op_ptr, 4, byte_order);
	    op_ptr += 4;
	    this->push_dwarf_reg_entry_value (CALL_SITE_PARAMETER_PARAM_OFFSET,
					      kind_u,
					      -1 /* deref_size */);
	  }
	  goto no_push;

	case DW_OP_const_type:
	case DW_OP_GNU_const_type:
	  {
	    int n;
	    const gdb_byte *data;
	    struct type *type;

	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
	    cu_offset type_die_cu_off = (cu_offset) uoffset;

	    n = *op_ptr++;
	    data = op_ptr;
	    op_ptr += n;

	    type = get_base_type (type_die_cu_off, n);
	    result_val = value_from_contents (type, data);
	  }
	  break;

	case DW_OP_regval_type:
	case DW_OP_GNU_regval_type:
	  {
	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &reg);
	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
	    cu_offset type_die_cu_off = (cu_offset) uoffset;

	    ensure_have_frame (this->frame, "DW_OP_regval_type");

	    struct type *type = get_base_type (type_die_cu_off, 0);
	    int regnum
	      = dwarf_reg_to_regnum_or_error (get_frame_arch (this->frame),
					      reg);
	    result_val = value_from_register (type, regnum, this->frame);
	  }
	  break;

	case DW_OP_convert:
	case DW_OP_GNU_convert:
	case DW_OP_reinterpret:
	case DW_OP_GNU_reinterpret:
	  {
	    struct type *type;

	    op_ptr = safe_read_uleb128 (op_ptr, op_end, &uoffset);
	    cu_offset type_die_cu_off = (cu_offset) uoffset;

	    if (to_underlying (type_die_cu_off) == 0)
	      type = address_type;
	    else
	      type = get_base_type (type_die_cu_off, 0);

	    result_val = fetch (0);
	    pop ();

	    if (op == DW_OP_convert || op == DW_OP_GNU_convert)
	      result_val = value_cast (type, result_val);
	    else if (type == value_type (result_val))
	      {
		/* Nothing.  */
	      }
	    else if (TYPE_LENGTH (type)
		     != TYPE_LENGTH (value_type (result_val)))
	      error (_("DW_OP_reinterpret has wrong size"));
	    else
	      result_val
		= value_from_contents (type,
				       value_contents_all (result_val));
	  }
	  break;

	case DW_OP_push_object_address:
	  /* Return the address of the object we are currently observing.  */
	  if (addr_info == nullptr)
	    error (_("Location address is not set."));

	  result_val
	    = value_from_ulongest (address_type, this->addr_info->addr);
	  break;

	default:
	  error (_("Unhandled dwarf expression opcode 0x%x"), op);
	}

      /* Most things push a result value.  */
      gdb_assert (result_val != NULL);
      push (result_val, in_stack_memory);
    no_push:
      ;
    }

  /* To simplify our main caller, if the result is an implicit
     pointer, then make a pieced value.  This is ok because we can't
     have implicit pointers in contexts where pieces are invalid.  */
  if (this->location == DWARF_VALUE_IMPLICIT_POINTER)
    add_piece (8 * this->addr_size, 0);

  this->recursion_depth--;
  gdb_assert (this->recursion_depth >= 0);
}

void _initialize_dwarf2expr ();
void
_initialize_dwarf2expr ()
{
  dwarf_arch_cookie
    = gdbarch_data_register_post_init (dwarf_gdbarch_types_init);
}
