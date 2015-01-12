# Frame unwinding support.
# Copyright (C) 2013-2014 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Internal functions for working with frame sniffers."""

import gdb
import collections


def execute_sniffers(sniffer_info):
    """Internal function called from GDB that executes sniffers
    implemented in Python. A sniffer able to unwind the frame returns
    a tuple containing unwind information.

    Arguments:
        sniffer_info: an instance of gdb.SnifferInfo.

    Returns:
        unwind_info: a pair (REG_DATA, FRAME_ID_REGNUMS). REG_DATA is
        tuple of (REG_NUM, REG_VALUE) pairs, where REG_NUM is
        (platform-specific) register number, and REG_VALUE is Value
        object with register value. FRAME_ID_REGNUM can be a (SP,),
        (SP, PC), or (SP, PC, SPECIAL) tuple, where SP, PC, and
        SPECIAL are (platform specific) register numbers.
        The frame ID is built in each case as follows:
          (SP,)                 make_id_build_wild (Value(SP))
          (SP, PC)              make_id_build (Value(SP), Value(PC))
          (SP, PC, SPECIAL)     make_id_build_special (Value(SP),
                                   Value(PC), Value(SPECIAL)
        The registers present in FRAME_ID_REGNUM should be among those
        returned by REG_DATA.
    """

    current_progspace = gdb.current_progspace()
    for objfile in gdb.objfiles():
        for sniffer in objfile.frame_sniffers:
            unwind_info = sniffer(sniffer_info)
            if unwind_info is not None:
                return unwind_info

    for sniffer in current_progspace.frame_sniffers:
        unwind_info = sniffer(sniffer_info)
        if unwind_info is not None:
            return unwind_info

    for sniffer in gdb.frame_sniffers:
        unwind_info = sniffer(sniffer_info)
        if unwind_info is not None:
            return unwind_info

    return None
