#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER gdb

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./ust_tracepoints.h"

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#if !defined(UST_TRACEPOINTS_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define UST_TRACEPOINTS_H
#include "build-gnulib/config.h"
#include <lttng/tracepoint.h>

  TRACEPOINT_EVENT(
      gdb,
      inf_read,
      TP_ARGS(int, pid, unsigned long long, addr, unsigned long long, value, int, success, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_integer_hex(unsigned long long, addr, addr)
	  ctf_integer_hex(unsigned long long, value, value)
	  ctf_integer(int, success, success)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_write,
      TP_ARGS(int, pid, unsigned long long, addr, unsigned long long, value, int, success, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_integer_hex(unsigned long long, addr, addr)
	  ctf_integer_hex(unsigned long long, value, value)
	  ctf_integer(int, success, success)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_stop,
      TP_ARGS(int, pid, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_cont,
      TP_ARGS(int, pid, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_step,
      TP_ARGS(int, pid, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_forked,
      TP_ARGS(int, pid, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_attach,
      TP_ARGS(int, pid, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      inf_exit,
      TP_ARGS(int, pid, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, pid, pid)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  /* cmd tracepoints */
  TRACEPOINT_EVENT(
      gdb,
      cmd_break,
      TP_ARGS(char*, arg, char*, filename, int, line),
      TP_FIELDS(
	  ctf_string(arg, arg)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      cmd_run,
      TP_ARGS(char*, filename, int, line),
      TP_FIELDS(
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      cmd_continue,
      TP_ARGS(char*, filename, int, line),
      TP_FIELDS(
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  /* pgspace tracepoints */
  TRACEPOINT_EVENT(
      gdb,
      pgspace_new,
      TP_ARGS(int, num, char*, bfd_name, int, aspace, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, num, num)
	  ctf_integer(int, aspace, aspace)
	  ctf_string(bfd_name, bfd_name)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      pgspace_del,
      TP_ARGS(int, num, char*, bfd_name, char*, filename, int, line),
      TP_FIELDS(
	  ctf_integer(int, num, num)
	  ctf_string(bfd_name, bfd_name)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
      )
  )

  TRACEPOINT_EVENT(
      gdb,
      pgspace_switch,
      TP_ARGS(int, num, char*, bfd_name, char*, filename, int, line, char **, bt),
      TP_FIELDS(
	  ctf_integer(int, num, num)
	  ctf_string(bfd_name, bfd_name)
	  ctf_string(filename, filename)
	  ctf_integer(int, line, line)
	  ctf_string(bt0, bt[0])
	  ctf_string(bt1, bt[1])
	  ctf_string(bt2, bt[2])
	  ctf_string(bt3, bt[3])
	  ctf_string(bt4, bt[4])
      )
  )

#endif /* UST_TRACEPOINTS_H */

#include <lttng/tracepoint-event.h>

#ifdef __cplusplus
}
#endif /* __cplusplus */
