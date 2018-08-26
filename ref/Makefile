SHELL=/bin/sh

pcre_test: pcre_test.C
	g++ pcre_test.C -o pcre_test -l pcre

clean: FORCE
	@if [ -e pcre_test ]; then rm pcre_test; echo Removed pcre_test; fi

FORCE:
