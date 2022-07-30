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

    Basically configure an /etc/xinetd.d file to configure mailrecv
    to listen on the network port 25 to handle SMTP connections.

    If your system doesn't have xinet installed, it can be installed
    with apt/yum/whatever.

    It's important to pick a user that mailrecv will run as, e.g. 'mail',
    and make sure all pipes and files mailrecv directs mail to and logs
    to are all owned by 'mail'. It's advised NEVER to run mailrecv as root.

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

    NOTE: It's possible this can also be configured with systemd instead
    of inetd/xinetd; I haven't investigated that yet.

    One can test the server from a shell using 'netcat', e.g.

        $ nc localhost 25                               <-- run this to connect to mailrecv
        220 mydomain.com SMTP (RFC 822) mailrecv        <-- mailrecv's response
        help                                            <-- type 'help' and hit ENTER
        214 Help:                                       \
            HELO, DATA, RSET, NOOP, QUIT,                |__ mailrecv responds with the
            MAIL FROM:,  RCPT TO:,                       |   smtp commands it supports
            VRFY, EXPN, EHLO, SEND, SOML, SAML, TURN    /
        quit                                            <-- type 'quit' and hit ENTER
        221 fltk.org closing connection                 <-- mailrecv finishes
        $

    To test delivery:

        $ nc localhost 25
        helo mydomain.com
        mail from: <me@mydomain.com>            -- angle brackets required
        rcpt to: <me@mydomain.com>              -- angle brackets required
        data
        From: Me <me@mydomain.com>
        Subject: Test

        Test message line 1.
        Test line 2.
        .
        quit

CONFIGURATION

    TBD.

    See the mailrecv.conf and mailrecv-test.conf for examples of how to
    configure. Perl regular expressions are used for pattern matching
    the remote hostname/IP addresses, so it should be pretty flexible.

    CONFIGURING DOMAIN

    Setting the domain is important, so the server knows which domain
    it's managing. So e.g.

        domain mydomain.com

    CONFIGURING LOGGING

    The default is for mailrecv to log to the system log (syslog),
    but it can also log to a file, e.g.

        logfile /var/log/mailrecv.log

    That makes it easy for tools like fail2ban(1) to monitor it
    and logrotate(1) to rotate it into an archive. Create the first
    log with:

        touch           /var/log/mailrecv.log
        chmod 644       /var/log/mailrecv.log
        chown mail:mail /var/log/mailrecv.log
              ---------
                  |
                  User/group you configure inetd to run mailrecv as

    It's advised to enable debug logging so you can see SMTP transactions
    to test them. Flags I like to use are:

        debug srw+F

    ..which logs smtp commands the remote sends to us (s), shows
    regex matches (r), warnings (w), from/to handling msgs (+),
    and fail2ban compatible logging (F).

    CONFIGURING TRUSTED MAIL SERVERS

    You can limit emails to a particular address to only come from a
    group of trusted servers. You can name groups anything you like,
    and add regex strings that can match domain names or ip addresses:

        allowgroup +google_servers  ^mail[a-zA-z0-9-]*\.google\.com$
        allowgroup +google_servers  \.google\.com$

    ..which creates a group called "+google_servers" which can then
    be referenced when configuring mail addresses we'll receive for,
    for instance:

        deliver allowgroup +google_servers rcpt_to myarchive@mydomain.com pipe /usr/local/sbin/somecommand -arg

    ..which configures mailrecv to accept mail to "myarchive@mydomain.com"
    ONLY if the mail is delivered from one of the machines in the +google_servers
    group. Any mail received is piped to 'somecommand -arg'.

    CONFIGURING EMAIL ADDRESSES TO A PIPE OR FILE

    The main purpose of mailrecv is to configure email addresses, and attach
    them to pipes to scripts for automation.

    A common example is to attach a google group (mailing list) to a local
    NNTP/news server for keeping an archive of posts.

    It's assumed your domain's DNS has MX records pointing to this machine
    running mailrecv, so it can manage all email addresses for the domain.
    Mailrecv is useful for simple domains that just use email addresses
    for automation, and not human email accounts. (For human readable
    email, you're better off configuring postfix, sendmail, qmail, etc)

    Each email address is configured with either a 'deliver rcpt_to' line
    for pipes and redirection to files, or a 'error rcpt_to" line
    to bounce back errors. e.g.

        deliver rcpt_to myarchive@mydomain.com pipe /some/command -arg
        deliver rcpt_to status@mydomain.com append /var/tmp/somestatus.txt

DOCUMENTATION

    TBD. Should be a perldoc so it can be a manpage or html.

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
    the extended SMTP protocol (EHLO) or any fancy secure email protocols
    that use e.g. TLS.

    Proper mail servers should be able to realize mailrecv only understands
    RFC822 commands, and will adjust the transaction accordingly.

REPORTING BUGS

    Please use github's issue page:

        https://github.com/erco77/mailrecv/issues

    ..or email Greg directly: erco@seriss.com
