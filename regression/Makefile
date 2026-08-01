VERSION  = x.xx
SHELL    = /bin/sh
CXXFLAGS = -std=c++11 -Wall -Wextra -DVERSION=\"$(VERSION)\" -I/opt/homebrew/include

default: test-isolate-address \
         test-insert-return-path \
	 test-ascii-hex-encode \
	 test-readline-words \
	 test-fcrdns \
	 pcre-test

test-isolate-address: test-isolate-address.cpp
	g++ $(CXXFLAGS) test-isolate-address.cpp -o test-isolate-address -lpcre

test-insert-return-path: test-insert-return-path.cpp
	g++ $(CXXFLAGS) test-insert-return-path.cpp -o test-insert-return-path -lpcre

test-ascii-hex-encode: test-ascii-hex-encode.cpp
	g++ $(CXXFLAGS) test-ascii-hex-encode.cpp -o test-ascii-hex-encode -lpcre

test-readline-words: test-readline-words.cpp
	g++ $(CXXFLAGS) test-readline-words.cpp -o test-readline-words -lpcre

test-fcrdns: test-fcrdns.cpp
	g++ $(CXXFLAGS) test-fcrdns.cpp -o test-fcrdns -lpcre

pcre-test: pcre-test.cpp
	g++ $(CXXFLAGS) pcre-test.cpp -o pcre-test -lpcre

clean: FORCE
	@if [ -e test-isolate-address ]; then rm test-isolate-address; echo Removed test-isolate-address; fi
	@if [ -e test-insert-return-path ]; then rm test-insert-return-path; echo Removed test-insert-return-path; fi
	@if [ -e test-ascii-hex-encode ]; then rm test-ascii-hex-encode; echo Removed test-ascii-hex-encode; fi
	@if [ -e test-readline-words ]; then rm test-readline-words; echo Removed test-readline-words; fi
	@if [ -e test-fcrdns ]; then rm test-fcrdns; echo Removed test-fcrdns; fi
	@if [ -e pcre-test ]; then rm pcre-test; echo Removed pcre-test; fi

# Don't remove this line
FORCE:
