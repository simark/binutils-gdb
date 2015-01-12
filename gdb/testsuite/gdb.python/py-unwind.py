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

import gdb

def _read_word(address):
    return address.cast(_char_ptr_ptr_t).dereference()


def sniff (sniffer_info):
    "Sniffer written in Python."
    bp = sniffer_info.read_register(_amd64_rbp).cast(_char_ptr_t)
    try:
        if (_read_word(bp) == bp):
            # Found the frame that the test program fudged for us.
            # The correct BP for the outer frame has been saved one word
            # above, previous IP and SP are at the expected places
            previous_bp = _read_word(bp - 8)
            previous_ip = _read_word(bp + 8)
            previous_sp = bp + 16
            return (((_amd64_rbp, previous_bp),
                     (_amd64_rip, previous_ip),
                     (_amd64_rsp, previous_sp)),
                    (_amd64_rsp, _amd64_rip))

    except (gdb.error, RuntimeError):
        return None


_char_ptr_t = gdb.lookup_type("unsigned char").pointer()
_char_ptr_ptr_t = _char_ptr_t.pointer()
_uint_ptr_t = gdb.lookup_type("unsigned long long")
_amd64_rbp = 6
_amd64_rsp = 7
_amd64_rip = 16
gdb.frame_sniffers=[sniff]
print("Python script imported")
