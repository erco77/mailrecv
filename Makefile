VERSION=1.00
SHELL=/bin/sh

mailrecv: mailrecv.C
	g++ -DVERSION=\"$(VERSION)\" mailrecv.C -o mailrecv

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
