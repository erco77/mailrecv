# mailrecv
mailrecv -- Standalone custom SMTP Server
-----------------------------------------

WHAT IS mailrecv?

    THIS IS CURRENTLY A WORK IN PROGRESS -- NOT READY FOR PRIME TIME.
    THIS MESSAGE WILL BE REMOVED WHEN THE PROGRAM IS USABLE FOR THE PUBLIC.
    
    mailrecv is a simple/dumb xinetd oriented SMTP server that simply
    accepts emails and writes those allowed to a file based on the
    recipient.

    It reads stdin/writes stdout, expecting those to be a TCP
    connection opened by xinetd to a remote SMTP server attempting
    to send an email to our domain.

    NOT INTENDED FOR NORMAL MAIL DELIVERY OR RELAYING.
    This is a dedicated tool for /just/ accepting emails and 
    writing the received messages to either a file or a pipe,
    depending on the configured allowed recipient(s).
    
    This is basically a template for writing ones own custom
    SMTP receiver.

    In my case, I needed a mail server on a domain that would
    receive mailing list emails, so that the received emails
    can be gatewayed directly into our NNTP server for archival.

LICENSING

    mailrecv is available under the terms of the GNU General
    Public License.  See the file "LICENSE" for more info.

BUILD INSTRUCTIONS

    Run GNU make to build the mailrecv binary:

        make
        
INSTALL INSTRUCTIONS

    TBD. Create an xinetd.d/mailrecv file that invokes this executable
    as the desired user for port 25.


CONFIGURATION

    TBD. Currently you hotrod the source code.

DOCUMENTATION

    TBD.

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
