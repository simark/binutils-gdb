/* Self tests for the filtered_iterator class.

   Copyright (C) 2016-2019 Free Software Foundation, Inc.

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

#include "gdbsupport/common-defs.h"
#include "gdbsupport/selftest.h"
#include "gdbsupport/filtered-iterator.h"

#include <iterator>

namespace selftests {

/* A dummy iterator class that iterates on integers 1 to 10 (inclusively) and
   meets the requirements to be used with filtered_iterator.  */

struct one_to_ten_iterator
{
  using value_type = int;
  using reference = int &;
  using pointer = int *;
  using iterator_category = std::forward_iterator_tag;
  using difference_type = int;

  /* Tag type to differentiate the two constructors.  */
  struct begin_t {};

  one_to_ten_iterator (begin_t)
  {}

  /* Create a one-past-the-end iterator.  */
  one_to_ten_iterator ()
    : m_cur (11)
  {}

  bool operator== (const one_to_ten_iterator &other) const
  {
    return m_cur == other.m_cur;
  }

  bool operator!= (const one_to_ten_iterator &other) const
  {
    return m_cur != other.m_cur;
  }

  void operator++ ()
  {
    /* Make sure nothing tries to increment a past the end iterator. */
    gdb_assert (m_cur <= 10);

    m_cur++;
  }

  int operator* () const
  {
    /* Make sure nothing tries to dereference a past the end iterator. */
    gdb_assert (m_cur <= 10);

    return m_cur;
  }

private:
  int m_cur = 1;
};

struct even_numbers_only
{
  bool operator() (int n)
  {
    return n % 2 == 0;
  }
};

static void
test_filtered_iterator ()
{
  std::vector<int> ints;
  const std::vector<int> expected { 2, 4, 6, 8, 10 };

  filtered_iterator<one_to_ten_iterator, even_numbers_only>
    iter (one_to_ten_iterator::begin_t {});
  filtered_iterator<one_to_ten_iterator, even_numbers_only> end;

  for (; iter != end; ++iter)
    ints.push_back (*iter);

  gdb_assert (ints == expected);
}

} /* namespace selftests */

void
_initialize_filtered_iterator_selftests ()
{
  selftests::register_test ("filtered_iterator",
			    selftests::test_filtered_iterator);
}
