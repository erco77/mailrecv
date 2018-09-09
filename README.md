# mailrecv
mailrecv -- Standalone custom SMTP Server
-----------------------------------------

WHAT IS mailrecv?

    THIS IS CURRENTLY A WORK IN PROGRESS -- NOT READY FOR PRIME TIME.
    THIS MESSAGE WILL BE REMOVED WHEN THE PROGRAM IS USABLE FOR THE PUBLIC.
    
    mailrecv is a simple/dumb xinetd oriented SMTP listener that simply
    accepts emails in and writes the received email to either a file
    or pipe based on the recipient. Multiple recipients can be configured.

    Since it's an xinetd oriented tool, it reads stdin/writes stdout, 
    expecting those to be a TCP connection prepared by xinetd listening
    on an SMTP port, to act like an SMTP server to receive incoming emails.

    NOT INTENDED FOR NORMAL MAIL DELIVERY OR RELAYING.
    This is a dedicated tool for /just/ accepting emails and 
    writing the received messages to either a file or a pipe,
    depending on the configured allowed recipient(s).
    
WHY DID YOU WRITE THIS?

    In my case, it was easier to write this than to configure sendmail,
    lol. And in my case I /only/ needed to receive emails from a single
    trusted server, it's easy to rule out the entire internet, ignoring
    complex issues like spam and cracking probes.

    This just seemed "safer" than having to configure a complex mail
    system that may take hours and hours to master and perhaps never
    really fully understand.. whereas this is such a simple tool, it's
    easy to understand and add any kind of site specific customizations
    one wants, without a lot of network code and confusing external stuff.

LICENSING

    mailrecv is available under the terms of the GNU General
    Public License.  See the file "LICENSE" for more info.

BUILD INSTRUCTIONS

    Dependencies: A C++ compiler environment, and the perl regular
    expression library (libpcre), which on Ubuntu 16.x is a one line
    install with 'apt install libpcre3-dev'.

    To build, just run GNU 'make':

        make

    ..this creates the mailrecv executable that is then used by xinetd
    to start handling SMTP connections. (see INSTALL instructions below)
        
INSTALL INSTRUCTIONS

    TBD. 

    Basically configure an /etc/xinetd.d file to configure mailrecv
    to listen on the network port 25 to handle SMTP connections.

    Example: here's an /etc/xinetd.d/smtp file I used for testing:

	service smtp
	{
	     socket_type         = stream
	     wait                = no
	     nice                = 10
	     user                = mail
	     server              = /usr/sbin/mailrecv
	     server_args         = -c /etc/mailrecv.conf
	     instances           = 4
	     log_on_success     += PID HOST DURATION
	}

    With that, tell xinetd to reload, and connections to port 25
    will cause mailrecv to handle the connection. 

    With this configuration, you will only see xinetd in the process
    table unless there's an active SMTP connection in progress, as xinetd
    only starts 'mailrecv' when someone connects to port 25, and mailrecv
    only remains running while an SMTP session is in progress.

    One can test the server from a shell using 'netcat', e.g.

        $ nc localhost 25				<-- run this to connect to mailrecv
	220 mydomain.com SMTP (RFC 822) mailrecv	<-- mailrecv's response
	help						<-- type 'help' and hit ENTER
	214 Help:                                       \
	    HELO, DATA, RSET, NOOP, QUIT,                |__ mailrecv responds with the
	    MAIL FROM:,  RCPT TO:,                       |   smtp commands it supports
	    VRFY, EXPN, EHLO, SEND, SOML, SAML, TURN    /
	quit						<-- type 'quit' and hit ENTER
	221 fltk.org closing connection                 <-- mailrecv finishes
	$

CONFIGURATION

    TBD.

    See the mailrecv.conf and mailrecv-test.conf for examples of how to
    configure. Perl regular expressions are used for pattern matching
    the remote hostname/IP addresses, so it should be pretty flexible.

DOCUMENTATION

    TBD. Should be a perldoc so it can be turned into a manpage and email.

FEATURES

    The goal of this program is to make it easy and safe to set up
    a simple SMTP server for a domain that simply accepts emails
    for allowed recipients, and writes the mail to either a file
    or pipe.

    To prevent spam, the program can check the server's IP address
    for known allowed addresses/domains, and reject all others.

    In my case, I ONLY need to accept messages from certain servers.

LIMITATIONS
   
    TBD.

    This implements RFC822 protocol only (HELO), and does NOT handle
    the extended SMTP protocol (EHLO).

REPORTING BUGS

    Please use github's issue page:

        https://github.com/erco77/mailrecv/issues

    ..or email Greg directly: erco@seriss.com
