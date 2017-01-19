#!/usr/bin/env bash

set -e

if [ $# -ne 2 ]; then
  echo "Usage: l-to-c.sh [l-file] [c-file]"
  exit 1
fi

l_file=$1
c_file=$2

if [ -z "${FLEX}" ]; then
	echo "FLEX is not set"
	exit 1
fi

base=$(basename "${l_file}" | sed 's/-.*//')

${FLEX} -P "${base}_" -o "${c_file}" "${l_file}"
sed -i \
	-e '/extern.*malloc/d' \
	-e '/extern.*realloc/d' \
	-e '/extern.*free/d' \
	-e '/include.*malloc.h/d' \
	-e 's/\([^x]\)malloc/\1xmalloc/g' \
	-e 's/\([^x]\)realloc/\1xrealloc/g' \
	-e 's/\([ \t;,(]\)free\([ \t]*[&(),]\)/\1xfree\2/g' \
	-e 's/\([ \t;,(]\)free$$/\1xfree/g' \
	-e 's/yy_flex_xrealloc/yyxrealloc/g' \
	"${c_file}"
