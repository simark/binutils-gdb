/* GNU/Linux/ARM specific low level interface, for the remote server for GDB.
   Copyright (C) 1995-2016 Free Software Foundation, Inc.

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

#include "server.h"
#include <inttypes.h>
#include "linux-low.h"
#include "arch/arm.h"
#include "arch/arm-linux.h"
#include "arch/arm-get-next-pcs.h"
#include "arch/arm-insn-emit.h"
#include "arch/arm-insn-reloc.h"
#include "linux-aarch32-low.h"

#include <sys/uio.h>
/* Don't include elf.h if linux/elf.h got included by gdb_proc_service.h.
   On Bionic elf.h and linux/elf.h have conflicting definitions.  */
#ifndef ELFMAG0
#include <elf.h>
#endif
#include "nat/gdb_ptrace.h"
#include <signal.h>
#include <sys/syscall.h>
#include <sys/auxv.h>

#include "tracepoint.h"

/* Defined in auto-generated files.  */
void init_registers_arm (void);
extern const struct target_desc *tdesc_arm;

void init_registers_arm_with_iwmmxt (void);
extern const struct target_desc *tdesc_arm_with_iwmmxt;

void init_registers_arm_with_vfpv2 (void);
extern const struct target_desc *tdesc_arm_with_vfpv2;

void init_registers_arm_with_vfpv3 (void);
extern const struct target_desc *tdesc_arm_with_vfpv3;

#ifndef PTRACE_GET_THREAD_AREA
#define PTRACE_GET_THREAD_AREA 22
#endif

#ifndef PTRACE_GETWMMXREGS
# define PTRACE_GETWMMXREGS 18
# define PTRACE_SETWMMXREGS 19
#endif

#ifndef PTRACE_GETVFPREGS
# define PTRACE_GETVFPREGS 27
# define PTRACE_SETVFPREGS 28
#endif

#ifndef PTRACE_GETHBPREGS
#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30
#endif

/* Information describing the hardware breakpoint capabilities.  */
static struct
{
  unsigned char arch;
  unsigned char max_wp_length;
  unsigned char wp_count;
  unsigned char bp_count;
} arm_linux_hwbp_cap;

/* Enum describing the different types of ARM hardware break-/watch-points.  */
typedef enum
{
  arm_hwbp_break = 0,
  arm_hwbp_load = 1,
  arm_hwbp_store = 2,
  arm_hwbp_access = 3
} arm_hwbp_type;

/* Type describing an ARM Hardware Breakpoint Control register value.  */
typedef unsigned int arm_hwbp_control_t;

/* Structure used to keep track of hardware break-/watch-points.  */
struct arm_linux_hw_breakpoint
{
  /* Address to break on, or being watched.  */
  unsigned int address;
  /* Control register for break-/watch- point.  */
  arm_hwbp_control_t control;
};

/* Since we cannot dynamically allocate subfields of arch_process_info,
   assume a maximum number of supported break-/watchpoints.  */
#define MAX_BPTS 32
#define MAX_WPTS 32

/* Per-process arch-specific data we want to keep.  */
struct arch_process_info
{
  /* Hardware breakpoints for this process.  */
  struct arm_linux_hw_breakpoint bpts[MAX_BPTS];
  /* Hardware watchpoints for this process.  */
  struct arm_linux_hw_breakpoint wpts[MAX_WPTS];
};

/* Per-thread arch-specific data we want to keep.  */
struct arch_lwp_info
{
  /* Non-zero if our copy differs from what's recorded in the thread.  */
  char bpts_changed[MAX_BPTS];
  char wpts_changed[MAX_WPTS];
  /* Cached stopped data address.  */
  CORE_ADDR stopped_data_address;
};

/* These are in <asm/elf.h> in current kernels.  */
#define HWCAP_VFP       64
#define HWCAP_IWMMXT    512
#define HWCAP_NEON      4096
#define HWCAP_VFPv3     8192
#define HWCAP_VFPv3D16  16384

#ifdef HAVE_SYS_REG_H
#include <sys/reg.h>
#endif

#define arm_num_regs 26

static int arm_regmap[] = {
  0, 4, 8, 12, 16, 20, 24, 28,
  32, 36, 40, 44, 48, 52, 56, 60,
  -1, -1, -1, -1, -1, -1, -1, -1, -1,
  64
};

/* Forward declarations needed for get_next_pcs ops.  */
static ULONGEST get_next_pcs_read_memory_unsigned_integer (CORE_ADDR memaddr,
							   int len,
							   int byte_order);

static CORE_ADDR get_next_pcs_addr_bits_remove (struct arm_get_next_pcs *self,
						CORE_ADDR val);

static CORE_ADDR get_next_pcs_syscall_next_pc (struct arm_get_next_pcs *self);

static int get_next_pcs_is_thumb (struct arm_get_next_pcs *self);

/* get_next_pcs operations.  */
static struct arm_get_next_pcs_ops get_next_pcs_ops = {
  get_next_pcs_read_memory_unsigned_integer,
  get_next_pcs_syscall_next_pc,
  get_next_pcs_addr_bits_remove,
  get_next_pcs_is_thumb,
  arm_linux_get_next_pcs_fixup,
};

static int
arm_cannot_store_register (int regno)
{
  return (regno >= arm_num_regs);
}

static int
arm_cannot_fetch_register (int regno)
{
  return (regno >= arm_num_regs);
}

static void
arm_fill_wmmxregset (struct regcache *regcache, void *buf)
{
  int i;

  if (regcache->tdesc != tdesc_arm_with_iwmmxt)
    return;

  for (i = 0; i < 16; i++)
    collect_register (regcache, arm_num_regs + i, (char *) buf + i * 8);

  /* We only have access to wcssf, wcasf, and wcgr0-wcgr3.  */
  for (i = 0; i < 6; i++)
    collect_register (regcache, arm_num_regs + i + 16,
		      (char *) buf + 16 * 8 + i * 4);
}

static void
arm_store_wmmxregset (struct regcache *regcache, const void *buf)
{
  int i;

  if (regcache->tdesc != tdesc_arm_with_iwmmxt)
    return;

  for (i = 0; i < 16; i++)
    supply_register (regcache, arm_num_regs + i, (char *) buf + i * 8);

  /* We only have access to wcssf, wcasf, and wcgr0-wcgr3.  */
  for (i = 0; i < 6; i++)
    supply_register (regcache, arm_num_regs + i + 16,
		     (char *) buf + 16 * 8 + i * 4);
}

static void
arm_fill_vfpregset (struct regcache *regcache, void *buf)
{
  int num;

  if (regcache->tdesc == tdesc_arm_with_neon
      || regcache->tdesc == tdesc_arm_with_vfpv3)
    num = 32;
  else if (regcache->tdesc == tdesc_arm_with_vfpv2)
    num = 16;
  else
    return;

  arm_fill_vfpregset_num (regcache, buf, num);
}

/* Wrapper of UNMAKE_THUMB_ADDR for get_next_pcs.  */
static CORE_ADDR
get_next_pcs_addr_bits_remove (struct arm_get_next_pcs *self, CORE_ADDR val)
{
  return UNMAKE_THUMB_ADDR (val);
}

static void
arm_store_vfpregset (struct regcache *regcache, const void *buf)
{
  int num;

  if (regcache->tdesc == tdesc_arm_with_neon
      || regcache->tdesc == tdesc_arm_with_vfpv3)
    num = 32;
  else if (regcache->tdesc == tdesc_arm_with_vfpv2)
    num = 16;
  else
    return;

  arm_store_vfpregset_num (regcache, buf, num);
}

/* Wrapper of arm_is_thumb_mode for get_next_pcs.  */
static int
get_next_pcs_is_thumb (struct arm_get_next_pcs *self)
{
  return arm_is_thumb_mode ();
}

/* Read memory from the inferiror.
   BYTE_ORDER is ignored and there to keep compatiblity with GDB's
   read_memory_unsigned_integer. */
static ULONGEST
get_next_pcs_read_memory_unsigned_integer (CORE_ADDR memaddr,
					   int len,
					   int byte_order)
{
  ULONGEST res;

  (*the_target->read_memory) (memaddr, (unsigned char *) &res, len);
  return res;
}

/* Fetch the thread-local storage pointer for libthread_db.  */

ps_err_e
ps_get_thread_area (const struct ps_prochandle *ph,
		    lwpid_t lwpid, int idx, void **base)
{
  if (ptrace (PTRACE_GET_THREAD_AREA, lwpid, NULL, base) != 0)
    return PS_ERR;

  /* IDX is the bias from the thread pointer to the beginning of the
     thread descriptor.  It has to be subtracted due to implementation
     quirks in libthread_db.  */
  *base = (void *) ((char *)*base - idx);

  return PS_OK;
}


/* Query Hardware Breakpoint information for the target we are attached to
   (using PID as ptrace argument) and set up arm_linux_hwbp_cap.  */
static void
arm_linux_init_hwbp_cap (int pid)
{
  unsigned int val;

  if (ptrace (PTRACE_GETHBPREGS, pid, 0, &val) < 0)
    return;

  arm_linux_hwbp_cap.arch = (unsigned char)((val >> 24) & 0xff);
  if (arm_linux_hwbp_cap.arch == 0)
    return;

  arm_linux_hwbp_cap.max_wp_length = (unsigned char)((val >> 16) & 0xff);
  arm_linux_hwbp_cap.wp_count = (unsigned char)((val >> 8) & 0xff);
  arm_linux_hwbp_cap.bp_count = (unsigned char)(val & 0xff);

  if (arm_linux_hwbp_cap.wp_count > MAX_WPTS)
    internal_error (__FILE__, __LINE__, "Unsupported number of watchpoints");
  if (arm_linux_hwbp_cap.bp_count > MAX_BPTS)
    internal_error (__FILE__, __LINE__, "Unsupported number of breakpoints");
}

/* How many hardware breakpoints are available?  */
static int
arm_linux_get_hw_breakpoint_count (void)
{
  return arm_linux_hwbp_cap.bp_count;
}

/* How many hardware watchpoints are available?  */
static int
arm_linux_get_hw_watchpoint_count (void)
{
  return arm_linux_hwbp_cap.wp_count;
}

/* Maximum length of area watched by hardware watchpoint.  */
static int
arm_linux_get_hw_watchpoint_max_length (void)
{
  return arm_linux_hwbp_cap.max_wp_length;
}

/* Initialize an ARM hardware break-/watch-point control register value.
   BYTE_ADDRESS_SELECT is the mask of bytes to trigger on; HWBP_TYPE is the
   type of break-/watch-point; ENABLE indicates whether the point is enabled.
   */
static arm_hwbp_control_t
arm_hwbp_control_initialize (unsigned byte_address_select,
			     arm_hwbp_type hwbp_type,
			     int enable)
{
  gdb_assert ((byte_address_select & ~0xffU) == 0);
  gdb_assert (hwbp_type != arm_hwbp_break
	      || ((byte_address_select & 0xfU) != 0));

  return (byte_address_select << 5) | (hwbp_type << 3) | (3 << 1) | enable;
}

/* Does the breakpoint control value CONTROL have the enable bit set?  */
static int
arm_hwbp_control_is_enabled (arm_hwbp_control_t control)
{
  return control & 0x1;
}

/* Is the breakpoint control value CONTROL initialized?  */
static int
arm_hwbp_control_is_initialized (arm_hwbp_control_t control)
{
  return control != 0;
}

/* Change a breakpoint control word so that it is in the disabled state.  */
static arm_hwbp_control_t
arm_hwbp_control_disable (arm_hwbp_control_t control)
{
  return control & ~0x1;
}

/* Are two break-/watch-points equal?  */
static int
arm_linux_hw_breakpoint_equal (const struct arm_linux_hw_breakpoint *p1,
			       const struct arm_linux_hw_breakpoint *p2)
{
  return p1->address == p2->address && p1->control == p2->control;
}

/* Convert a raw breakpoint type to an enum arm_hwbp_type.  */

static arm_hwbp_type
raw_bkpt_type_to_arm_hwbp_type (enum raw_bkpt_type raw_type)
{
  switch (raw_type)
    {
    case raw_bkpt_type_hw:
      return arm_hwbp_break;
    case raw_bkpt_type_write_wp:
      return arm_hwbp_store;
    case raw_bkpt_type_read_wp:
      return arm_hwbp_load;
    case raw_bkpt_type_access_wp:
      return arm_hwbp_access;
    default:
      gdb_assert_not_reached ("unhandled raw type");
    }
}

/* Initialize the hardware breakpoint structure P for a breakpoint or
   watchpoint at ADDR to LEN.  The type of watchpoint is given in TYPE.
   Returns -1 if TYPE is unsupported, or -2 if the particular combination
   of ADDR and LEN cannot be implemented.  Otherwise, returns 0 if TYPE
   represents a breakpoint and 1 if type represents a watchpoint.  */
static int
arm_linux_hw_point_initialize (enum raw_bkpt_type raw_type, CORE_ADDR addr,
			       int len, struct arm_linux_hw_breakpoint *p)
{
  arm_hwbp_type hwbp_type;
  unsigned mask;

  hwbp_type = raw_bkpt_type_to_arm_hwbp_type (raw_type);

  if (hwbp_type == arm_hwbp_break)
    {
      /* For breakpoints, the length field encodes the mode.  */
      switch (len)
	{
	case 2:	 /* 16-bit Thumb mode breakpoint */
	case 3:  /* 32-bit Thumb mode breakpoint */
	  mask = 0x3;
	  addr &= ~1;
	  break;
	case 4:  /* 32-bit ARM mode breakpoint */
	  mask = 0xf;
	  addr &= ~3;
	  break;
	default:
	  /* Unsupported. */
	  return -2;
	}
    }
  else
    {
      CORE_ADDR max_wp_length = arm_linux_get_hw_watchpoint_max_length ();
      CORE_ADDR aligned_addr;

      /* Can not set watchpoints for zero or negative lengths.  */
      if (len <= 0)
	return -2;
      /* The current ptrace interface can only handle watchpoints that are a
	 power of 2.  */
      if ((len & (len - 1)) != 0)
	return -2;

      /* Test that the range [ADDR, ADDR + LEN) fits into the largest address
	 range covered by a watchpoint.  */
      aligned_addr = addr & ~(max_wp_length - 1);
      if (aligned_addr + max_wp_length < addr + len)
	return -2;

      mask = (1 << len) - 1;
    }

  p->address = (unsigned int) addr;
  p->control = arm_hwbp_control_initialize (mask, hwbp_type, 1);

  return hwbp_type != arm_hwbp_break;
}

/* Callback to mark a watch-/breakpoint to be updated in all threads of
   the current process.  */

struct update_registers_data
{
  int watch;
  int i;
};

static int
update_registers_callback (struct inferior_list_entry *entry, void *arg)
{
  struct thread_info *thread = (struct thread_info *) entry;
  struct lwp_info *lwp = get_thread_lwp (thread);
  struct update_registers_data *data = (struct update_registers_data *) arg;

  /* Only update the threads of the current process.  */
  if (pid_of (thread) == pid_of (current_thread))
    {
      /* The actual update is done later just before resuming the lwp,
         we just mark that the registers need updating.  */
      if (data->watch)
	lwp->arch_private->wpts_changed[data->i] = 1;
      else
	lwp->arch_private->bpts_changed[data->i] = 1;

      /* If the lwp isn't stopped, force it to momentarily pause, so
         we can update its breakpoint registers.  */
      if (!lwp->stopped)
        linux_stop_lwp (lwp);
    }

  return 0;
}

static int
arm_supports_z_point_type (char z_type)
{
  switch (z_type)
    {
    case Z_PACKET_SW_BP:
    case Z_PACKET_HW_BP:
    case Z_PACKET_WRITE_WP:
    case Z_PACKET_READ_WP:
    case Z_PACKET_ACCESS_WP:
      return 1;
    default:
      /* Leave the handling of sw breakpoints with the gdb client.  */
      return 0;
    }
}

/* Insert hardware break-/watchpoint.  */
static int
arm_insert_point (enum raw_bkpt_type type, CORE_ADDR addr,
		  int len, struct raw_breakpoint *bp)
{
  struct process_info *proc = current_process ();
  struct arm_linux_hw_breakpoint p, *pts;
  int watch, i, count;

  watch = arm_linux_hw_point_initialize (type, addr, len, &p);
  if (watch < 0)
    {
      /* Unsupported.  */
      return watch == -1 ? 1 : -1;
    }

  if (watch)
    {
      count = arm_linux_get_hw_watchpoint_count ();
      pts = proc->priv->arch_private->wpts;
    }
  else
    {
      count = arm_linux_get_hw_breakpoint_count ();
      pts = proc->priv->arch_private->bpts;
    }

  for (i = 0; i < count; i++)
    if (!arm_hwbp_control_is_enabled (pts[i].control))
      {
	struct update_registers_data data = { watch, i };
	pts[i] = p;
	find_inferior (&all_threads, update_registers_callback, &data);
	return 0;
      }

  /* We're out of watchpoints.  */
  return -1;
}

/* Remove hardware break-/watchpoint.  */
static int
arm_remove_point (enum raw_bkpt_type type, CORE_ADDR addr,
		  int len, struct raw_breakpoint *bp)
{
  struct process_info *proc = current_process ();
  struct arm_linux_hw_breakpoint p, *pts;
  int watch, i, count;

  watch = arm_linux_hw_point_initialize (type, addr, len, &p);
  if (watch < 0)
    {
      /* Unsupported.  */
      return -1;
    }

  if (watch)
    {
      count = arm_linux_get_hw_watchpoint_count ();
      pts = proc->priv->arch_private->wpts;
    }
  else
    {
      count = arm_linux_get_hw_breakpoint_count ();
      pts = proc->priv->arch_private->bpts;
    }

  for (i = 0; i < count; i++)
    if (arm_linux_hw_breakpoint_equal (&p, pts + i))
      {
	struct update_registers_data data = { watch, i };
	pts[i].control = arm_hwbp_control_disable (pts[i].control);
	find_inferior (&all_threads, update_registers_callback, &data);
	return 0;
      }

  /* No watchpoint matched.  */
  return -1;
}

/* Return whether current thread is stopped due to a watchpoint.  */
static int
arm_stopped_by_watchpoint (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_thread);
  siginfo_t siginfo;

  /* We must be able to set hardware watchpoints.  */
  if (arm_linux_get_hw_watchpoint_count () == 0)
    return 0;

  /* Retrieve siginfo.  */
  errno = 0;
  ptrace (PTRACE_GETSIGINFO, lwpid_of (current_thread), 0, &siginfo);
  if (errno != 0)
    return 0;

  /* This must be a hardware breakpoint.  */
  if (siginfo.si_signo != SIGTRAP
      || (siginfo.si_code & 0xffff) != 0x0004 /* TRAP_HWBKPT */)
    return 0;

  /* If we are in a positive slot then we're looking at a breakpoint and not
     a watchpoint.  */
  if (siginfo.si_errno >= 0)
    return 0;

  /* Cache stopped data address for use by arm_stopped_data_address.  */
  lwp->arch_private->stopped_data_address
    = (CORE_ADDR) (uintptr_t) siginfo.si_addr;

  return 1;
}

/* Return data address that triggered watchpoint.  Called only if
   arm_stopped_by_watchpoint returned true.  */
static CORE_ADDR
arm_stopped_data_address (void)
{
  struct lwp_info *lwp = get_thread_lwp (current_thread);
  return lwp->arch_private->stopped_data_address;
}

/* Called when a new process is created.  */
static struct arch_process_info *
arm_new_process (void)
{
  struct arch_process_info *info = XCNEW (struct arch_process_info);
  return info;
}

/* Called when a new thread is detected.  */
static void
arm_new_thread (struct lwp_info *lwp)
{
  struct arch_lwp_info *info = XCNEW (struct arch_lwp_info);
  int i;

  for (i = 0; i < MAX_BPTS; i++)
    info->bpts_changed[i] = 1;
  for (i = 0; i < MAX_WPTS; i++)
    info->wpts_changed[i] = 1;

  lwp->arch_private = info;
}

static void
arm_new_fork (struct process_info *parent, struct process_info *child)
{
  struct arch_process_info *parent_proc_info;
  struct arch_process_info *child_proc_info;
  struct lwp_info *child_lwp;
  struct arch_lwp_info *child_lwp_info;
  int i;

  /* These are allocated by linux_add_process.  */
  gdb_assert (parent->priv != NULL
	      && parent->priv->arch_private != NULL);
  gdb_assert (child->priv != NULL
	      && child->priv->arch_private != NULL);

  parent_proc_info = parent->priv->arch_private;
  child_proc_info = child->priv->arch_private;

  /* Linux kernel before 2.6.33 commit
     72f674d203cd230426437cdcf7dd6f681dad8b0d
     will inherit hardware debug registers from parent
     on fork/vfork/clone.  Newer Linux kernels create such tasks with
     zeroed debug registers.

     GDB core assumes the child inherits the watchpoints/hw
     breakpoints of the parent, and will remove them all from the
     forked off process.  Copy the debug registers mirrors into the
     new process so that all breakpoints and watchpoints can be
     removed together.  The debug registers mirror will become zeroed
     in the end before detaching the forked off process, thus making
     this compatible with older Linux kernels too.  */

  *child_proc_info = *parent_proc_info;

  /* Mark all the hardware breakpoints and watchpoints as changed to
     make sure that the registers will be updated.  */
  child_lwp = find_lwp_pid (ptid_of (child));
  child_lwp_info = child_lwp->arch_private;
  for (i = 0; i < MAX_BPTS; i++)
    child_lwp_info->bpts_changed[i] = 1;
  for (i = 0; i < MAX_WPTS; i++)
    child_lwp_info->wpts_changed[i] = 1;
}

/* Called when resuming a thread.
   If the debug regs have changed, update the thread's copies.  */
static void
arm_prepare_to_resume (struct lwp_info *lwp)
{
  struct thread_info *thread = get_lwp_thread (lwp);
  int pid = lwpid_of (thread);
  struct process_info *proc = find_process_pid (pid_of (thread));
  struct arch_process_info *proc_info = proc->priv->arch_private;
  struct arch_lwp_info *lwp_info = lwp->arch_private;
  int i;

  for (i = 0; i < arm_linux_get_hw_breakpoint_count (); i++)
    if (lwp_info->bpts_changed[i])
      {
	errno = 0;

	if (arm_hwbp_control_is_enabled (proc_info->bpts[i].control))
	  if (ptrace (PTRACE_SETHBPREGS, pid,
		      (PTRACE_TYPE_ARG3) ((i << 1) + 1),
		      &proc_info->bpts[i].address) < 0)
	    perror_with_name ("Unexpected error setting breakpoint address");

	if (arm_hwbp_control_is_initialized (proc_info->bpts[i].control))
	  if (ptrace (PTRACE_SETHBPREGS, pid,
		      (PTRACE_TYPE_ARG3) ((i << 1) + 2),
		      &proc_info->bpts[i].control) < 0)
	    perror_with_name ("Unexpected error setting breakpoint");

	lwp_info->bpts_changed[i] = 0;
      }

  for (i = 0; i < arm_linux_get_hw_watchpoint_count (); i++)
    if (lwp_info->wpts_changed[i])
      {
	errno = 0;

	if (arm_hwbp_control_is_enabled (proc_info->wpts[i].control))
	  if (ptrace (PTRACE_SETHBPREGS, pid,
		      (PTRACE_TYPE_ARG3) -((i << 1) + 1),
		      &proc_info->wpts[i].address) < 0)
	    perror_with_name ("Unexpected error setting watchpoint address");

	if (arm_hwbp_control_is_initialized (proc_info->wpts[i].control))
	  if (ptrace (PTRACE_SETHBPREGS, pid,
		      (PTRACE_TYPE_ARG3) -((i << 1) + 2),
		      &proc_info->wpts[i].control) < 0)
	    perror_with_name ("Unexpected error setting watchpoint");

	lwp_info->wpts_changed[i] = 0;
      }
}

/* Find the next pc for a sigreturn or rt_sigreturn syscall.  In
   addition, set IS_THUMB depending on whether we will return to ARM
   or Thumb code.
   See arm-linux.h for stack layout details.  */
static CORE_ADDR
arm_sigreturn_next_pc (struct regcache *regcache, int svc_number,
		       int *is_thumb)
{
  unsigned long sp;
  unsigned long sp_data;
  /* Offset of PC register.  */
  int pc_offset = 0;
  CORE_ADDR next_pc = 0;
  CORE_ADDR cpsr;

  gdb_assert (svc_number == __NR_sigreturn || svc_number == __NR_rt_sigreturn);

  collect_register_by_name (regcache, "sp", &sp);
  (*the_target->read_memory) (sp, (unsigned char *) &sp_data, 4);

  pc_offset = arm_linux_sigreturn_next_pc_offset
    (sp, sp_data, svc_number, __NR_sigreturn == svc_number ? 1 : 0);

  (*the_target->read_memory) (sp + pc_offset, (unsigned char *) &next_pc, 4);

  /* Set IS_THUMB according the CPSR saved on the stack.  */
  (*the_target->read_memory) (sp + pc_offset + 4, (unsigned char *) &cpsr, 4);
  *is_thumb = ((cpsr & CPSR_T) != 0);

  return next_pc;
}

/* When PC is at a syscall instruction, return the PC of the next
   instruction to be executed.  */
static CORE_ADDR
get_next_pcs_syscall_next_pc (struct arm_get_next_pcs *self)
{
  CORE_ADDR next_pc = 0;
  CORE_ADDR pc = regcache_read_pc (self->regcache);
  int is_thumb = arm_is_thumb_mode ();
  ULONGEST svc_number = 0;
  struct regcache *regcache = self->regcache;

  if (is_thumb)
    {
      collect_register (regcache, 7, &svc_number);
      next_pc = pc + 2;
    }
  else
    {
      unsigned long this_instr;
      unsigned long svc_operand;

      (*the_target->read_memory) (pc, (unsigned char *) &this_instr, 4);
      svc_operand = (0x00ffffff & this_instr);

      if (svc_operand)  /* OABI.  */
	{
	  svc_number = svc_operand - 0x900000;
	}
      else /* EABI.  */
	{
	  collect_register (regcache, 7, &svc_number);
	}

      next_pc = pc + 4;
    }

  /* This is a sigreturn or sigreturn_rt syscall.  */
  if (svc_number == __NR_sigreturn || svc_number == __NR_rt_sigreturn)
    {
      /* SIGRETURN or RT_SIGRETURN may affect the arm thumb mode, so
	 update IS_THUMB.   */
      next_pc = arm_sigreturn_next_pc (regcache, svc_number, &is_thumb);
    }

  /* Addresses for calling Thumb functions have the bit 0 set.  */
  if (is_thumb)
    next_pc = MAKE_THUMB_ADDR (next_pc);

  return next_pc;
}

static int
arm_get_hwcap (unsigned long *valp)
{
  unsigned char *data = (unsigned char *) alloca (8);
  int offset = 0;

  while ((*the_target->read_auxv) (offset, data, 8) == 8)
    {
      unsigned int *data_p = (unsigned int *)data;
      if (data_p[0] == AT_HWCAP)
	{
	  *valp = data_p[1];
	  return 1;
	}

      offset += 8;
    }

  *valp = 0;
  return 0;
}

static const struct target_desc *
arm_read_description (void)
{
  int pid = lwpid_of (current_thread);
  unsigned long arm_hwcap = 0;

  /* Query hardware watchpoint/breakpoint capabilities.  */
  arm_linux_init_hwbp_cap (pid);

  if (arm_get_hwcap (&arm_hwcap) == 0)
    return tdesc_arm;

  if (arm_hwcap & HWCAP_IWMMXT)
    return tdesc_arm_with_iwmmxt;

  if (arm_hwcap & HWCAP_VFP)
    {
      const struct target_desc *result;
      char *buf;

      /* NEON implies either no VFP, or VFPv3-D32.  We only support
	 it with VFP.  */
      if (arm_hwcap & HWCAP_NEON)
	result = tdesc_arm_with_neon;
      else if ((arm_hwcap & (HWCAP_VFPv3 | HWCAP_VFPv3D16)) == HWCAP_VFPv3)
	result = tdesc_arm_with_vfpv3;
      else
	result = tdesc_arm_with_vfpv2;

      /* Now make sure that the kernel supports reading these
	 registers.  Support was added in 2.6.30.  */
      errno = 0;
      buf = (char *) xmalloc (32 * 8 + 4);
      if (ptrace (PTRACE_GETVFPREGS, pid, 0, buf) < 0
	  && errno == EIO)
	result = tdesc_arm;

      free (buf);

      return result;
    }

  /* The default configuration uses legacy FPA registers, probably
     simulated.  */
  return tdesc_arm;
}

static void
arm_arch_setup (void)
{
  int tid = lwpid_of (current_thread);
  int gpregs[18];
  struct iovec iov;

  current_process ()->tdesc = arm_read_description ();

  iov.iov_base = gpregs;
  iov.iov_len = sizeof (gpregs);

  /* Check if PTRACE_GETREGSET works.  */
  if (ptrace (PTRACE_GETREGSET, tid, NT_PRSTATUS, &iov) == 0)
    have_ptrace_getregset = 1;
  else
    have_ptrace_getregset = 0;
}

/* Fetch the next possible PCs after the current instruction executes.  */

static VEC (CORE_ADDR) *
arm_gdbserver_get_next_pcs (struct regcache *regcache)
{
  struct arm_get_next_pcs next_pcs_ctx;
  VEC (CORE_ADDR) *next_pcs = NULL;

  arm_get_next_pcs_ctor (&next_pcs_ctx,
			 &get_next_pcs_ops,
			 /* Byte order is ignored assumed as host.  */
			 0,
			 0,
			 1,
			 regcache);

  next_pcs = arm_get_next_pcs (&next_pcs_ctx);

  return next_pcs;
}

/* Support for hardware single step.  */

static int
arm_supports_hardware_single_step (void)
{
  return 0;
}

/* Register sets without using PTRACE_GETREGSET.  */

static struct regset_info arm_regsets[] = {
  { PTRACE_GETREGS, PTRACE_SETREGS, 0, 18 * 4,
    GENERAL_REGS,
    arm_fill_gregset, arm_store_gregset },
  { PTRACE_GETWMMXREGS, PTRACE_SETWMMXREGS, 0, 16 * 8 + 6 * 4,
    EXTENDED_REGS,
    arm_fill_wmmxregset, arm_store_wmmxregset },
  { PTRACE_GETVFPREGS, PTRACE_SETVFPREGS, 0, 32 * 8 + 4,
    EXTENDED_REGS,
    arm_fill_vfpregset, arm_store_vfpregset },
  NULL_REGSET
};

static struct regsets_info arm_regsets_info =
  {
    arm_regsets, /* regsets */
    0, /* num_regsets */
    NULL, /* disabled_regsets */
  };

static struct usrregs_info arm_usrregs_info =
  {
    arm_num_regs,
    arm_regmap,
  };

static struct regs_info regs_info_arm =
  {
    NULL, /* regset_bitmap */
    &arm_usrregs_info,
    &arm_regsets_info
  };

static const struct regs_info *
arm_regs_info (void)
{
  const struct target_desc *tdesc = current_process ()->tdesc;

  if (have_ptrace_getregset == 1
      && (tdesc == tdesc_arm_with_neon || tdesc == tdesc_arm_with_vfpv3))
    return &regs_info_aarch32;
  else
    return &regs_info_arm;
}

/* Implementation of the linux_target_ops method "support_tracepoints".  */

static int
arm_supports_tracepoints (void)
{
  return 1;
}

static int
append_insns (CORE_ADDR *to, size_t len, const unsigned char *buf)
{
  if (write_inferior_memory (*to, buf, len) != 0)
    return 1;

  *to += len;

  return 0;
}

static int
append_insn_32 (CORE_ADDR *to, uint32_t insn)
{
  printf ("append_insn_32: Copying instruction %x to %s\n", insn,
	  paddress (*to));
  return append_insns (to, 4, (unsigned char *) &insn);
}

static int
append_insn_16 (CORE_ADDR *to, uint16_t insn)
{
  return append_insns (to, 2, (unsigned char *) &insn);
}

struct arm_insn_reloc_data
{
  union {
    uint32_t arm;
    uint16_t thumb32[2];
  } insns;

  /* The original PC of the instruction.  */
  CORE_ADDR orig_loc;

  /* The PC where the modified instruction(s) will start.  */
  CORE_ADDR new_loc;

  /* Error message to return to the client in case the relocation fails.  */
  const char *err;
};

static int
arm_reloc_refs_pc_error (struct arm_insn_reloc_data *data)
{
  data->err = "The instruction references the PC, couldn't relocate.";
  return 1;
}

static int
arm_reloc_others (uint32_t insn, const char *iname, struct arm_insn_reloc_data *data)
{
  data->insns.arm = insn;

  return 0;
}

static int
arm_reloc_alu_imm (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (arm_insn_references_pc (insn, 0x000f0000ul))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "ALU immediate", data);
}

static int
arm_reloc_alu_reg (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (arm_insn_references_pc (insn, 0x000ff00ful))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "ALU reg", data);
}

static int
arm_reloc_alu_shifted_reg (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (arm_insn_references_pc (insn, 0x000fff0ful))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "ALU shifted reg", data);
}

static int
arm_reloc_b_bl_blx (uint32_t insn, struct arm_insn_reloc_data *data)
{
  uint32_t cond = bits (insn, 28, 31);
  int exchange = (cond == 0xf);

  if (exchange)
    {
      /* blx */
      CORE_ADDR absolute_dest = BranchDest (data->orig_loc, insn);

      /* Adjust the address if the H bit is set.  */
      if (bit(insn, 24))
	absolute_dest |= (1 << 1);

      arm_emit_arm_blx_imm_insn (&data->insns.arm, data->new_loc,
				 absolute_dest);
    }
  else
    {
      /* b or bl */
      CORE_ADDR absolute_dest = BranchDest (data->orig_loc, insn);
      int link = exchange || bit (insn, 24);

      arm_emit_arm_branch_insn (&data->insns.arm, data->new_loc, absolute_dest,
				link);
    }

  return 0;
}

static int
arm_reloc_block_xfer (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (bit (insn, 20) == 1)
    {
      /* it's an LDM/POP-kind instruction.  If it mentions PC, the instruction
         will result in a jump.  The destination address is absolute, so it
         won't change the result if we execute it out of line.  */
      return arm_reloc_others (insn, "ldm", data);
    }
  else
    {
      /* It's an STM/PUSH-kind instruction.  If it mentions PC, we will store
         the wrong value of PC in memory.  Therefore, error out if PC is
         mentioned.  */
      if ((insn & (1 << 15)) != 0)
	return arm_reloc_refs_pc_error (data);

      return arm_reloc_others (insn, "stm", data);
    }
}

static int
arm_reloc_bx_blx_reg (uint32_t insn, struct arm_insn_reloc_data *data)
{
  /* These instructions take an absolute address in a register, so there's
     nothing special to do.  */
  return arm_reloc_others(insn, "bx/blx", data);
}

static int
arm_reloc_copro_load_store (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (arm_insn_references_pc (insn, 0x000f0000ul))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "copro load/store", data);
}

static int
arm_reloc_extra_ld_st (uint32_t insn, struct arm_insn_reloc_data *data,
		 int unprivileged)
{
  if (arm_insn_references_pc (insn, 0x000ff00ful))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "extra load/store", data);
}

static int
arm_reloc_ldr_str_ldrb_strb (uint32_t insn, struct arm_insn_reloc_data *data,
			     int load, int size, int usermode)
{
  if (arm_insn_references_pc (insn, 0x000ff00ful))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "load/store", data);
}

static int
arm_reloc_preload (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (arm_insn_references_pc (insn, 0x000f0000ul))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "preload", data);
}

static int
arm_reloc_preload_reg (uint32_t insn, struct arm_insn_reloc_data *data)
{
  if (arm_insn_references_pc (insn, 0x000f000ful))
    return arm_reloc_refs_pc_error (data);

  return arm_reloc_others (insn, "preload reg", data);
}

static int
arm_reloc_svc (uint32_t insn, struct arm_insn_reloc_data *data)
{
  /* There is nothing PC-relative in the SVC instruction.  */
  return arm_reloc_others(insn, "svc", data);
}

static int
arm_reloc_undef (uint32_t insn, struct arm_insn_reloc_data *data)
{

  data->err = "The instruction is undefined, couldn't relocate.";
  return 1;
}

static int
arm_reloc_unpred (uint32_t insn, struct arm_insn_reloc_data *data)
{
  data->err = "The instruction is unpredictable, couldn't relocate.";
  return 1;
}

struct arm_insn_reloc_visitor arm_insn_reloc_visitor = {
  arm_reloc_alu_imm,
  arm_reloc_alu_reg,
  arm_reloc_alu_shifted_reg,
  arm_reloc_b_bl_blx,
  arm_reloc_block_xfer,
  arm_reloc_bx_blx_reg,
  arm_reloc_copro_load_store,
  arm_reloc_extra_ld_st,
  arm_reloc_ldr_str_ldrb_strb,
  arm_reloc_others,
  arm_reloc_preload,
  arm_reloc_preload_reg,
  arm_reloc_svc,
  arm_reloc_undef,
  arm_reloc_unpred,
};

static int
copy_instruction_arm (CORE_ADDR *to, CORE_ADDR from, const char **err)
{
  uint32_t insn;
  struct arm_insn_reloc_data data;
  int ret;

  if (read_inferior_memory (from, (unsigned char *) &insn, sizeof (insn)) != 0)
    {
      *err = "Error reading memory while relocating instruction.";
      return 1;
    }

  /* Set a default generic error message, which can be overriden by the
     relocation functions.  */
  data.err = "Error relocating instruction";

  data.orig_loc = from;
  data.new_loc = *to;

  ret = arm_relocate_insn_arm (insn, &arm_insn_reloc_visitor, &data);
  if (ret != 0)
    {
      *err = data.err;
      return 1;
    }

  append_insn_32(to, data.insns.arm);
  return 0;
}

static int
thumb32_reloc_others (uint16_t insn1, uint16_t insn2, const char *iname,
		      struct arm_insn_reloc_data *data)
{
  data->insns.thumb32[0] = insn1;
  data->insns.thumb32[1] = insn2;

  return 0;
}

static int
thumb32_reloc_alu_imm (uint16_t insn1, uint16_t insn2,
		       struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_b_bl_blx (uint16_t insn1, uint16_t insn2,
			struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_block_xfer (uint16_t insn1, uint16_t insn2,
			  struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_copro_load_store (uint16_t insn1, uint16_t insn2,
				struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_load_literal (uint16_t insn1, uint16_t insn2,
			    struct arm_insn_reloc_data *data, int size)
{
  return 1;
}

static int
thumb32_reloc_load_reg_imm (uint16_t insn1, uint16_t insn2,
			    struct arm_insn_reloc_data *data, int writeback,
			    int immed)
{
  return 1;
}

static int
thumb32_reloc_pc_relative_32bit (uint16_t insn1, uint16_t insn2,
				 struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_preload (uint16_t insn1, uint16_t insn2,
		       struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_undef (uint16_t insn1, uint16_t insn2,
		     struct arm_insn_reloc_data *data)
{
  return 1;
}

static int
thumb32_reloc_table_branch (uint16_t insn1, uint16_t insn2,
			    struct arm_insn_reloc_data *data)
{
  return 1;
}


struct thumb_32bit_insn_reloc_visitor thumb_32bit_insns_reloc_visitor = {
  thumb32_reloc_alu_imm,
  thumb32_reloc_b_bl_blx,
  thumb32_reloc_block_xfer,
  thumb32_reloc_copro_load_store,
  thumb32_reloc_load_literal,
  thumb32_reloc_load_reg_imm,
  thumb32_reloc_others,
  thumb32_reloc_pc_relative_32bit,
  thumb32_reloc_preload,
  thumb32_reloc_undef,
  thumb32_reloc_table_branch,
};

static int
copy_instruction_thumb32 (CORE_ADDR *to, CORE_ADDR from, const char **err)
{
  uint16_t insn1, insn2;
  struct arm_insn_reloc_data data;
  int ret;

  if (read_inferior_memory (from, (unsigned char *) &insn1,
			    sizeof (insn1)) != 0)
    {
      *err = "Error reading memory while relocating instruction.";
      return 1;
    }

  if (read_inferior_memory (from + sizeof (insn1), (unsigned char *) &insn2,
			    sizeof (insn2)) != 0)
    {
      *err = "Error reading memory while relocating instruction.";
      return 1;
    }

  /* Set a default generic error message, which can be overriden by the
     relocation functions.  */
  data.err = "Error relocating instruction";

  ret = arm_relocate_insn_thumb_32bit (insn1, insn2,
				       &thumb_32bit_insns_reloc_visitor, &data);
  ;
  if (ret != 0)
    {
      *err = data.err;
      return 1;
    }

  append_insn_16 (to, data.insns.thumb32[0]);
  append_insn_16 (to, data.insns.thumb32[1]);
  return 0;
}

static int
arm_get_thread_area (int lwpid, CORE_ADDR *addr)
{
  uint32_t val;

  if (ptrace (PTRACE_GET_THREAD_AREA, lwpid, NULL, &val) != 0)
    return -1;

  *addr = val;
  return 0;
}

static int
arm_get_min_fast_tracepoint_insn_len (void)
{
  return 4;
}

static int
arm_install_fast_tracepoint_jump_pad_arm (struct tracepoint *tp,
					  struct ipa_symbol *collector,
					  struct ipa_symbol *lockaddr,
					  CORE_ADDR *jump_entry,
					  CORE_ADDR *trampoline,
					  ULONGEST *trampoline_size,
					  unsigned char *jjump_pad_insn,
					  ULONGEST *jjump_pad_insn_size,
					  char *err)
{
  unsigned char buf[0x100];
  CORE_ADDR buildaddr = *jump_entry;
  const struct target_desc *tdesc = current_process ()->tdesc;
  const int r0 = find_regno (tdesc, "r0");
  const int r2 = find_regno (tdesc, "r2");
  const int r4 = find_regno (tdesc, "r4");
  const uint32_t kuser_get_tls = 0xffff0fe0;
  const uint32_t push_r0 = 0xe52d0004;
  uint32_t *ptr = (uint32_t *) buf;
  const char *copy_insn_err;

  printf ("arm_install_fast_tracepoint_jump_pad_arm, buildaddr = %s\n",
	  paddress (buildaddr));

  /* Push VFP registers if available.  */
  if (tdesc == tdesc_arm_with_neon || tdesc == tdesc_arm_with_vfpv3)
    {
      *ptr++ = 0xed6d0b20; /* vpush {d16-d31} */
      *ptr++ = 0xed2d0b20; /* vpush {d0-d15} */
    }
  else if (tdesc == tdesc_arm_with_vfpv2)
    *ptr++ = 0xed2d0b20; /* vpush {d0-d15} */

  /* Function prologue, push common registers on the stack.  */
  *ptr++ = 0xe92d5fff; /* push { r0-r12,lr } */

  /* Push current processor state register (CPSR) on the stack.  */
  *ptr++ = 0xe10f0000; /* mrs r0,cpsr */
  *ptr++ = push_r0; /* push r0 */

  /* Push replaced instruction address on the stack.  */
  ptr = arm_emit_arm_load_insn (ptr, r0, (uint32_t) tp->address);
  *ptr++ = push_r0; /* push r0 (orig pc)  */

  /* Save current stack pointer for the REGS parameters of the gdb_collect
     call later. */
  *ptr++ = 0xe1a0100d; /* mov r1, sp (regs:arg2)  */

  /* Push current thread's local storage location on the stack.  */
  ptr = arm_emit_arm_load_insn (ptr, r0, kuser_get_tls);
  ptr = arm_emit_arm_blx_insn (ptr, r0);
  *ptr++ = push_r0; /* push r0 (tls)  */

  /* Push obj_addr_on_target on the stack.  */
  ptr = arm_emit_arm_load_insn (ptr, r0, (uint32_t) tp->obj_addr_on_target);
  *ptr++ = push_r0; /* push r0 (tpoint:arg1)  */

  if (collector->target_flags & (1 << 0))
    {
      /* collector is a thumb function */
      ptr = arm_emit_arm_load_insn (ptr, r2, (uint32_t) collector->addr | 1);
    }
  else
    {
      /* collector is an arm function */
      ptr = arm_emit_arm_load_insn (ptr, r2, (uint32_t) collector->addr);
    }

  ptr = arm_emit_arm_load_insn (ptr, r4, (uint32_t) lockaddr->addr);

  /*
   * At this point, the stack looks like:
   *           bottom
   * +-------------------------------------------------+
   * |  saved lr                                       |
   * |  saved r12                                      |
   * |  ...                                            |
   * |  saved r0                                       |
   * |  saved cpsr                                     |
   * |  tp->address                                    | <- r1
   * |  tls  (collecting_t.thread_area)                |
   * |  tp->obj_addr_on_target  (collecting_t.tpoint)  | <- r5
   * +-------------------------------------------------+
   *            top
   */

  /* Save current sp value, so we can restore it after the call to
     gdb_collect.  */
  *ptr++ = 0xe1a0500d; /*    mov r5, sp  */

  /* Spin lock on lockaddr (r4 contains address of lock) */

  /* This is a full memory barrier.  */
  *ptr++ = 0xf57ff05f; /* 1: dmb sy (memory barrier)  */
  /* Load lock value in r3 */
  *ptr++ = 0xe1943f9f; /* 2: ldrex r3, [r4]  */
  /* Is it already locked?  */
  *ptr++ = 0xe3530000; /*    cmp r3, #0  */
  /* If so, start over. */
  *ptr++ = 0x1a000002; /*    bne 3  */
  /* If not, write a value (our saved stack pointer in r5) to the location.  */
  *ptr++ = 0xe184ef95; /*    strex r14, r5, [r4]  */
  /* Did the write succeed?  */
  *ptr++ = 0xe35e0000; /*    cmp r14, #0  */
  /* If not, start over.  */
  *ptr++ = 0x1afffff9; /*    bne 2  */
  /* A full memory barrier again.  */
  *ptr++ = 0xf57ff05f; /* 3: dmb sy  */
  *ptr++ = 0x1afffff6; /*    bne 1  */

  /* Round the stack to a multiple of 8 (section 5.2.1.2) */
  *ptr++ = 0xe3c53007; /* bic r3, r5, 7  */
  *ptr++ = 0xe1a0d003; /* mov sp, r3  */

  /* Call collector (obj_addr_on_target, regs);
	  r2 -^      r0 -^             r1 -^  */
  ptr = arm_emit_arm_blx_insn (ptr, r2);

  /* Restore sp to pre-call/rounding value.  */
  *ptr++ = 0xe1a0d005; /* mov sp, r5  */

  /* Unlock the spin lock (by writing 0 to it).  */
  *ptr++ = 0xe3a03000; /* mov r3, #0  */
  *ptr++ = 0xe5843000; /* str r3, [r4]  */

  /* Pop everything that was saved. */

  /* tpoint, tls, tpaddr */
  *ptr++ = 0xe28dd00c; /* add sp, sp, #12  */

  /* cpsr */
  *ptr++ = 0xe49d0004; /* pop r0  */
  *ptr++ = 0xe12cf000; /* msr cpsr,r0  */

  /* r0-r12 and lr */
  *ptr++ = 0xe8bd5fff; /* pop { r0-r12,lr }  */

  /* Pop VFP registers.  */
  if (tdesc == tdesc_arm_with_neon || tdesc == tdesc_arm_with_vfpv3)
    {
      *ptr++ = 0xecfd0b20; /* vpop {d16-d31} */
      *ptr++ = 0xecbd0b20; /* vpop {d0-d15} */
    }
  else if (tdesc == tdesc_arm_with_vfpv2)
    *ptr++ = 0xecbd0b20; /* vpop {d0-d15} */

  append_insns (&buildaddr, (uint32_t) ptr - (uint32_t) buf, buf);

  tp->adjusted_insn_addr = buildaddr;
  if (copy_instruction_arm (&buildaddr, tp->address, &copy_insn_err) != 0)
    {
      sprintf (err, "E%s", copy_insn_err);
      return 1;
    }
  tp->adjusted_insn_addr = buildaddr;

  /* Possible improvements:
   This branch can be made non-relative:
   B <mem location>:
   push    {r0,r1}
   movw    r0, #<mem location>
   movt    r0, #<mem location>
   str     r0, [sp, #4]
   pop     {r0,pc}  */
  if (!arm_arm_is_reachable (buildaddr, tp->address + 4))
    {
      sprintf (err,
	       "E.Jump back from jump pad too far from tracepoint "
	       "(offset 0x%" PRIx32 " cannot be encoded in 24 bits).",
		arm_arm_branch_relative_distance (buildaddr, tp->address + 4));
      return 1;
    }
  /* b <tp_addr + 4>  */
  (void) arm_emit_arm_branch_insn ((uint32_t *) buf, buildaddr,
				   tp->address + 4, 0);
  append_insns (&buildaddr, 4, buf);

  /* write tp instr.  */
  if (!arm_arm_is_reachable (tp->address, *jump_entry))
    {
      sprintf (err,
	      "E.Jump pad too far from tracepoint "
	       "(offset 0x%" PRIx32 " cannot be encoded in 24 bits).",
	       arm_arm_branch_relative_distance (tp->address, *jump_entry));
      return 1;
    }
  (void) arm_emit_arm_branch_insn ((uint32_t *) jjump_pad_insn, tp->address,
				   *jump_entry, 0);
  *jjump_pad_insn_size = 4;
  *jump_entry = buildaddr;

  return 0;
}

static int
arm_install_fast_tracepoint_jump_pad_thumb2 (struct tracepoint *tp,
					     struct ipa_symbol *collector,
					     struct ipa_symbol *lockaddr,
					     CORE_ADDR *jump_entry,
					     CORE_ADDR *trampoline,
					     ULONGEST *trampoline_size,
					     unsigned char *jjump_pad_insn,
					     ULONGEST *jjump_pad_insn_size,
					     char *err)
{
  unsigned char buf[0x100];
  CORE_ADDR buildaddr = *jump_entry;
  const struct target_desc *tdesc = current_process ()->tdesc;
  const int r0 = find_regno (tdesc, "r0");
  const int r2 = find_regno (tdesc, "r2");
  const int r4 = find_regno (tdesc, "r4");
  const uint32_t kuser_get_tls = 0xffff0fe0;
  uint16_t *ptr = (uint16_t *) buf;
  const uint16_t push_r0 = 0xb401;
  const char *copy_insn_err;

  /* Push VFP registers if available.  */
  if (tdesc == tdesc_arm_with_neon || tdesc == tdesc_arm_with_vfpv3)
    {
      *ptr++ = 0xed2d; /* vpush {d0-d15} */
      *ptr++ = 0x0b20;
      *ptr++ = 0xed6d; /* vpush {d16-d31} */
      *ptr++ = 0x0b20;
    }
  else if (tdesc == tdesc_arm_with_vfpv2)
    {
      *ptr++ = 0xed2d; /* vpush {d0-d15} */
      *ptr++ = 0x0b20;
    }

  /* Function prologue, push common registers on the stack.  */
  *ptr++ = 0xe92d; /* push { r0-r12,lr }  */
  *ptr++ = 0x5fff;

  /* Push current processor state register (CPSR) on the stack.  */
  *ptr++ = 0xf3ef; /* mrs r0,cpsr  */
  *ptr++ = 0x8000;
  *ptr++ = push_r0; /* push r0  */

  /* Push replaced instruction address on the stack.  */
  ptr = arm_emit_thumb_load_insn (ptr, r0, (uint32_t) tp->address);
  *ptr++ = push_r0; /* push r0 (orig pc)  */

  /* Save current stack pointer for the REGS parameters of the gdb_collect
     call later. */
  *ptr++ = 0x4669; /* mov r1, sp (regs:arg2)  */

  /* Push current thread's local storage location on the stack.  */
  ptr = arm_emit_thumb_load_insn (ptr, r0, kuser_get_tls);
  ptr = arm_emit_thumb_blx_insn (ptr, r0);
  *ptr++ = push_r0; /* push r0 (tls)  */

  /* Push obj_addr_on_target on the stack.  */
  ptr = arm_emit_thumb_load_insn (ptr, r0, (uint32_t) tp->obj_addr_on_target);
  *ptr++ = push_r0; /* push r0 (tpoint:arg1)  */

  if (collector->target_flags & (1 << 0))
    {
      /* collector is a thumb function */
      ptr = arm_emit_thumb_load_insn (ptr, r2, (uint32_t) collector->addr | 1);
    }
  else
    {
      /* collector is an arm function */
      ptr = arm_emit_thumb_load_insn (ptr, r2, (uint32_t) collector->addr);
    }

  ptr = arm_emit_thumb_load_insn (ptr, r4, (uint32_t) lockaddr->addr);

  /*
   * At this point, the stack looks like:
   *           bottom
   * +-------------------------------------------------+
   * |  saved lr                                       |
   * |  saved r12                                      |
   * |  ...                                            |
   * |  saved r0                                       |
   * |  saved cpsr                                     |
   * |  tp->address                                    | <- r1
   * |  tls  (collecting_t.thread_area)                |
   * |  tp->obj_addr_on_target  (collecting_t.tpoint)  | <- r5
   * +-------------------------------------------------+
   *            top
   */

  /* Save current sp value, so we can restore it after the call to
     gdb_collect.  */
  *ptr++ = 0x466d; /*    mov r5, sp  */

  /* Spin lock on lockaddr (r4 contains address of lock) */

  /* This is a full memory barrier.  */
  *ptr++ = 0xf3bf; /* 1: dmb sy  */
  *ptr++ = 0x8f5f;

  /* Load lock value in r3 */
  *ptr++ = 0xe854; /* 2: ldrex   r3, [r4]	*/
  *ptr++ = 0x3f00;

  /* Is it already locked?  */
  *ptr++ = 0x2b00; /*    cmp     r3, #0  */

  /* If so, start over. */
  *ptr++ = 0xd104; /*    bne.n   3	 */

  /* If not, write a value (our saved stack pointer in r5) to the location.  */
  *ptr++ = 0xe844; /*    strex   r14, r5, [r4]  */
  *ptr++ = 0x5e00;

  /* Did the write succeed?  */
  *ptr++ = 0xf1be; /*    cmp.w   r14, #0  */
  *ptr++ = 0x0f00;

  /* If not, start over.  */
  *ptr++ = 0xd1f6; /*    bne.n   2	 */

  /* A full memory barrier again.  */
  *ptr++ = 0xf3bf; /* 3. dmb  sy  */
  *ptr++ = 0x8f5f;

  *ptr++ = 0xd1f1; /*    bne.n   1	 */

  /* Round the stack to a multiple of 8 (section 5.2.1.2) */
  *ptr++ = 0xf025; /* bic r3, r5, 7  */
  *ptr++ = 0x0307;
  *ptr++ = 0x469d; /* mov sp, r3  */

  /* Call collector (obj_addr_on_target, regs);
		r2 -^      r0 -^     r1 -^  */
  ptr = arm_emit_thumb_blx_insn (ptr, r2);

  /* Restore sp to pre-call/rounding value.  */
  *ptr++ = 0x46ad; /* mov sp, r5  */

  /* Unlock the spin lock (by writing 0 to it).  */
  *ptr++ = 0xf04f; /* mov r3, #0  */
  *ptr++ = 0x0300;
  *ptr++ = 0x6023; /* str r3, [r4]	 */

  /* Pop everything that was saved. */

  /* tpoint, tls, tpaddr */
  *ptr++ = 0xb003; /* add sp, #12	*/

  /* cpsr */
  *ptr++ = 0xbc01; /* pop r0  */
  *ptr++ = 0xf380; /* msr cpsr,r0	*/
  *ptr++ = 0x8c00;

  /* r0-r12 and lr */
  *ptr++ = 0xe8bd; /* pop { r0-r12,lr }  */
  *ptr++ = 0x5fff;

  /* Pop VFP registers.  */
  if (tdesc == tdesc_arm_with_neon || tdesc == tdesc_arm_with_vfpv3)
    {
      *ptr++ = 0xecfd; /* vpop {d16-d31} */
      *ptr++ = 0x0b20;
      *ptr++ = 0xecbd; /* vpop {d0-d15} */
      *ptr++ = 0x0b20;
    }
  else if (tdesc == tdesc_arm_with_vfpv2)
    {
      *ptr++ = 0xecbd; /* vpop {d0-d15} */
      *ptr++ = 0x0b20;
    }

  append_insns (&buildaddr, (uint32_t) ptr - (uint32_t) buf, buf);

  tp->adjusted_insn_addr = buildaddr;
  if (copy_instruction_thumb32 (&buildaddr, tp->address, &copy_insn_err) != 0)
    {
      sprintf (err, "E%s", copy_insn_err);
      return 1;
    }
  tp->adjusted_insn_addr_end = buildaddr;

  /* Possible improvements:
     This branch can be made non-relative:
     B <mem location>:
     push	   {r0,r1}
     movw	   r0, #<mem location>
     movt	   r0, #<mem location>
     str	   r0, [sp, #4]
     pop	   {r0,pc}  */
  if (!arm_thumb_is_reachable (buildaddr, tp->address + 4))
    {
      sprintf (err,
	      "E.Jump back from jump pad too far from tracepoint "
	      "(offset 0x%" PRIx32 " cannot be encoded in 23 bits).",
	      arm_thumb_branch_relative_distance (buildaddr, tp->address + 4));
      return 1;
    }
  (void) arm_emit_thumb_branch_insn ((uint16_t *) buf, buildaddr,
				     tp->address + 4);
  append_insns (&buildaddr, 4, buf);

  /* write tp instr.	*/
  if (!arm_thumb_is_reachable (tp->address, *jump_entry))
    {
      sprintf (err,
	      "E.Jump pad too far from tracepoint "
	      "(offset 0x%" PRIx32 " cannot be encoded in 23 bits).",
	      arm_thumb_branch_relative_distance (tp->address, *jump_entry));
      return 1;
    }
  (void) arm_emit_thumb_branch_insn ((uint16_t *) jjump_pad_insn, tp->address,
				     *jump_entry);
  *jjump_pad_insn_size = 4;
  *jump_entry = buildaddr;

  return 0;
}

static int
arm_install_fast_tracepoint_jump_pad (struct tracepoint *tp,
				      struct ipa_symbol *collector,
				      struct ipa_symbol *lockaddr,
				      CORE_ADDR *jump_entry,
				      CORE_ADDR *trampoline,
				      ULONGEST *trampoline_size,
				      unsigned char *jjump_pad_insn,
				      ULONGEST *jjump_pad_insn_size,
				      char *err)
{
  if (tp->kind == ARM_BP_KIND_ARM)
    {
      return arm_install_fast_tracepoint_jump_pad_arm (tp, collector, lockaddr,
						       jump_entry, trampoline,
						       trampoline_size,
						       jjump_pad_insn,
						       jjump_pad_insn_size,
						       err);
    }
  else if (tp->kind == ARM_BP_KIND_THUMB2)
    {
      return arm_install_fast_tracepoint_jump_pad_thumb2 (tp, collector,
							  lockaddr, jump_entry,
							  trampoline,
							  trampoline_size,
							  jjump_pad_insn,
							  jjump_pad_insn_size,
							  err);
    }
  else
    {
      strcpy (err,
	      "ECan't put a fast tracepoint jump on a two-bytes Thumb "
	      "instruction.");
      return 1;
    }
}

static void
arm_ipa_get_hwcap (unsigned long *valp)
{
#ifdef HAVE_GETAUXVAL
  *valp = getauxval (AT_HWCAP);
#else
  unsigned long data[2];
  FILE *f = fopen ("/proc/self/auxv", "r");

  if (f == NULL)
    return;

  while (fread (data, sizeof (data), 1, f) > 0)
    {
      if (data[0] == AT_HWCAP)
	{
	  *valp = data[1];
	  break;
	}
    }

  fclose (f);
#endif /* HAVE_GETAUXVAL */
}

enum arm_linux_tdesc {
  ARM_TDESC_ARM = 0,
  ARM_TDESC_ARM_WITH_VFPV2 = 1,
  ARM_TDESC_ARM_WITH_VFPV3 = 2,
  ARM_TDESC_ARM_WITH_NEON = 3,
};

enum arm_linux_tdesc
arm_ipa_read_hwcap (void)
{
  unsigned long arm_hwcap = 0;

  arm_ipa_get_hwcap (&arm_hwcap);

  if (arm_hwcap == 0)
    return ARM_TDESC_ARM;

  /* iwmmxt registers collection is not supported.  */
  if (arm_hwcap & HWCAP_IWMMXT)
    return ARM_TDESC_ARM;

  if (arm_hwcap & HWCAP_VFP)
    {
      /* NEON implies either no VFP, or VFPv3-D32.  We only support
	 it with VFP.  */
      if (arm_hwcap & HWCAP_NEON)
	return ARM_TDESC_ARM_WITH_NEON;
      else if ((arm_hwcap & (HWCAP_VFPv3 | HWCAP_VFPv3D16)) == HWCAP_VFPv3)
	return ARM_TDESC_ARM_WITH_VFPV3;
      else
	return ARM_TDESC_ARM_WITH_VFPV2;
    }

  /* The default configuration uses legacy FPA registers, probably
     simulated.  */
  return ARM_TDESC_ARM;
}

static int
arm_get_ipa_tdesc_idx (void)
{
  return arm_ipa_read_hwcap ();
}

struct linux_target_ops the_low_target = {
  arm_arch_setup,
  arm_regs_info,
  arm_cannot_fetch_register,
  arm_cannot_store_register,
  NULL, /* fetch_register */
  linux_get_pc_32bit,
  linux_set_pc_32bit,
  arm_breakpoint_kind_from_pc,
  arm_sw_breakpoint_from_kind,
  arm_gdbserver_get_next_pcs,
  0,
  arm_breakpoint_at,
  arm_supports_z_point_type,
  arm_insert_point,
  arm_remove_point,
  arm_stopped_by_watchpoint,
  arm_stopped_data_address,
  NULL, /* collect_ptrace_register */
  NULL, /* supply_ptrace_register */
  NULL, /* siginfo_fixup */
  arm_new_process,
  arm_new_thread,
  arm_new_fork,
  arm_prepare_to_resume,
  NULL, /* process_qsupported */
  arm_supports_tracepoints,
  arm_get_thread_area, /* get_thread_area */
  arm_install_fast_tracepoint_jump_pad, /* install_fast_tracepoint_jump_pad */
  NULL, /* emit_ops */
  arm_get_min_fast_tracepoint_insn_len, /* get_min_fast_tracepoint_insn_len */
  NULL, /* supports_range_stepping */
  arm_breakpoint_kind_from_current_state,
  arm_supports_hardware_single_step,
  NULL, /* get_syscall_trapinfo */
  arm_get_ipa_tdesc_idx,
};

void
initialize_low_arch (void)
{
  /* Initialize the Linux target descriptions.  */
  init_registers_arm ();
  init_registers_arm_with_iwmmxt ();
  init_registers_arm_with_vfpv2 ();
  init_registers_arm_with_vfpv3 ();

  initialize_low_arch_aarch32 ();

  initialize_regsets_info (&arm_regsets_info);
}
