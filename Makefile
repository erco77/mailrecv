VERSION=1.10
SHELL=/bin/sh

mailrecv: mailrecv.cpp
	g++ -DVERSION=\"$(VERSION)\" -Wall mailrecv.cpp -o mailrecv -l pcre -lpthread

clean: FORCE
	if [ -e mailrecv ]; then rm -f mailrecv; fi
	( cd ref; make clean )

# GIT OPERATIONS
commit: FORCE
	@make clean
	@echo "------------------------------"
	@git status
	@echo "------------------------------"
	@read -p "Git status look OK? (^C to abort commit)"
	git add -u && git commit

# Run gitk
#    Disconnect it from the terminal
gitk: FORCE
	( nohup gitk > /dev/null 2>&1 < /dev/null & )

FORCE:
