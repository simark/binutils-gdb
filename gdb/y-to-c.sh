#!/usr/bin/env bash

set -e

if [ $# -ne 7 ]; then
  echo "Usage: y-to-c.sh [shell-binary] [ylwrap-binary] [yacc-binary] [yflags] [y-file] [c-file] [symbol-prefix]"
  exit 1
fi

shell_binary="$1"
ylwrap_binary="$2"
yacc_binary="$3"
yflags="$4"
y_file="$5"
c_file="$6"
symbol_prefix="$7"

${shell_binary} ${ylwrap_binary} ${y_file} y.tab.c ${c_file} -- \
	${yacc_binary} ${yflags} -p ${symbol_prefix}_yy
exit
sed -i "" \
	-e '/extern.*malloc/d' \
	-e '/extern.*realloc/d' \
	-e '/extern.*free/d' \
	-e '/include.*malloc.h/d' \
	-e 's/\([^x]\)malloc/\1xmalloc/g' \
	-e 's/\([^x]\)realloc/\1xrealloc/g' \
	-e 's/\([ \t;,(]\)free\([ \t]*[&(),]\)/\1xfree\2/g' \
	-e 's/\([ \t;,(]\)free$$/\1xfree/g' \
	-e '/^#line.*y.tab.c/d' \
	-e 's/YY_NULL/YY_NULLPTR/g' \
	"${c_file}"
