#!/bin/sh
# This script parses the package name and version out of configure.ac,
# uses them to assemble the names of the distribution tar.gz and source rpm,
# then calls make to generate those files.
# Any arguments will be passed on to configure when building the tarball.

AC_INIT=`grep AC_INIT configure.ac`
PACKAGE=`echo ${AC_INIT} | awk 'BEGIN { FS="[][]" }; { print $2 };'`
VERSION=`echo ${AC_INIT} | awk 'BEGIN { FS="[][]" }; { print $4 };'`

tgz=${PACKAGE}-${VERSION}.tar.gz
srpm=${PACKAGE}-${VERSION}-1.src.rpm

rm -f ${tgz} ${srpm}

make -f - <<EOF
.PHONY = all
all: ${tgz} ${srpm}

configure: configure.ac Makefile.am
	autoreconf --install -s

${tgz}: configure
	./configure ${@}
	make dist

${srpm}: ${tgz} ${PACKAGE}.spec
	rpmbuild --eval "%undefine dist"	\
		--define "_sourcedir ${PWD}"	\
		--define "_specdir ${PWD}" 	\
		--define "_srcrpmdir ${PWD}"	\
		-bs ${PACKAGE}.spec
EOF

