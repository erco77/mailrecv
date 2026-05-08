VERSION=x.xx
SHELL=/bin/sh
CXXFLAGS=-Wall -Wextra -DVERSION=\"$(VERSION)\" -I/opt/homebrew/include

default: test-isolate-address \
         test-insert-return-path \
	 test-ascii-hex-encode \
	 pcre-test

test-isolate-address: test-isolate-address.cpp
	g++ $(CXXFLAGS) test-isolate-address.cpp -o test-isolate-address -lpcre

test-insert-return-path: test-insert-return-path.cpp
	g++ $(CXXFLAGS) test-insert-return-path.cpp -o test-insert-return-path -lpcre

test-ascii-hex-encode: test-ascii-hex-encode.cpp
	g++ $(CXXFLAGS) test-ascii-hex-encode.cpp -o test-ascii-hex-encode -lpcre

pcre-test: pcre-test.cpp
	g++ $(CXXFLAGS) pcre-test.cpp -o pcre-test -lpcre

clean: FORCE
	@if [ -e test-isolate-address ]; then rm test-isolate-address; echo Removed test-isolate-address; fi
	@if [ -e test-insert-return-path ]; then rm test-insert-return-path; echo Removed test-insert-return-path; fi
	@if [ -e test-ascii-hex-encode ]; then rm test-ascii-hex-encode; echo Removed test-ascii-hex-encode; fi
	@if [ -e pcre-test ]; then rm pcre-test; echo Removed pcre-test; fi

# Don't remove this line
FORCE:
