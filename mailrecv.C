// vim: autoindent tabstop=8 shiftwidth=4 expandtab softtabstop=4

//
// mailrecv.C -- xinetd tool to act as a simple SMTP server
//
//     We just append letters to valid recipients to either a file
//     or pipe based on the RCPT TO: address.
//
// Copyright 2018 Greg Ercolano
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public Licensse as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//
// 80 //////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>     // strchr()
#include <sys/socket.h> // getpeername()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

using namespace std;

#define MYDOMAIN        "fltk.org"
#define LINE_LEN        4096
#define CRLF            "\r\n"

// TODO: MyLog() that logs date and remote IP

// TODO: Put a timer on this entire program.
//       Abort if we're running longer than e.g. 5 minutes.
//

// Minimum commands we must support:
//      HELO MAIL RCPT DATA RSET NOOP QUIT VRFY

// RETURN REMOTE'S IP ADDRESS
//    fp -- tcp connection as a FILE* (e.g. as xinetd would hand to us)
//    s  -- returned IP address string
//
int GetRemoteIPAddr(FILE *fp, char *s, int maxlen) {
    struct sockaddr_in raddr;
    socklen_t raddr_size = sizeof(raddr);
    if ( getpeername(fileno(fp), (struct sockaddr*)&raddr, &raddr_size) == 0 ) {
        // stdin is a TCP socket, get the IP address
        sprintf(s, "%.*s", maxlen, inet_ntoa(raddr.sin_addr));
    } else {
        // Non-fatal, i.e. if testing from a shell
        perror("WARNING: getpeername() couldn't determine remote IP address:");
        strcpy(s, "?.?.?.?");
        return -1;
    }
    return 0;
}

// RETURN REMOTE'S HOSTNAME
//    fp -- tcp connection as a FILE* (e.g. as xinetd would hand to us)
//    s  -- returned hostname
//
int GetRemoteHostname(FILE *fp, char *s, int maxlen) {
    GetRemoteIPAddr(fp, s, maxlen);             // TODO: Use getnameinfo(3)
}

// TRUNCATE STRING AT CR/LF
void StripCRLF(char *s) {
    char *eol;
    if ( (eol = strchr(s, '\r')) ) { *eol = 0; }
    if ( (eol = strchr(s, '\n')) ) { *eol = 0; }
}

#define ISIT(x)         !strcasecmp(cmd, x)
#define ISARG1(x)       !strcasecmp(arg1, x)

// READ LETTER'S DATA FROM THE REMOTE
//     Assumes an SMTP "DATA" command was just received.
//     Returns 0 on success, -1 on premature end of input.
//
int ReadLetter(FILE *fp, vector<string>& letter) {
    char s[LINE_LEN+1];
    while (fgets(s, LINE_LEN, stdin)) {
        StripCRLF(s);
        fprintf(stderr, "LETTER: '%s'\n", s);
        // End of letter? done
        if ( strcmp(s, ".") == 0 ) {
            return 0;
        }
        letter.push_back(s);
    }
    return -1;                  // premature end of input
}

// TODO: Check recipient, write to file or pipe
int DeliverMail(const char* mail_from,
                const char *rcpt_to,
                const vector<string>& letter) {
    fprintf(stderr, "MAIL FROM: %s\n", mail_from);
    fprintf(stderr, "RCPT TO: %s\n", rcpt_to);
    fprintf(stderr, "--- LETTER: START\n");
    for ( size_t i=0; i<letter.size(); i++ ) {
        fprintf(stderr, "%s\n", letter[i].c_str());
    }
    fprintf(stderr, "--- LETTER: END\n");
    return 0;
}

int main() {

    // TODO: parse command line, e.g. -version to print VERSION macro string

    // Get the remote IP address for stdin
    char remoteip[LINE_LEN+1];
    char remotehost[LINE_LEN+1];
    GetRemoteIPAddr(stdin, remoteip, LINE_LEN);
    GetRemoteHostname(stdin, remotehost, LINE_LEN);

    const char *mydomain = MYDOMAIN;

    vector<string> letter;
    char s[LINE_LEN+1],                 // raw line buffer
         cmd[LINE_LEN+1],               // cmd received
         arg1[LINE_LEN+1],              // arg1 received
         arg2[LINE_LEN+1],              // arg2 received
         mail_from[LINE_LEN+1],         // The remote's "MAIL FROM:" value
         rcpt_to[LINE_LEN+1];           // The remote's "RCPT TO:" value

    // WE IMPLEMENT RFC 822 HELO PROTOCOL ONLY
    printf("220 %s SMTP (RFC 822) mailrecv\n", mydomain);

    int quit = 0;
    while (!quit && fgets(s, LINE_LEN-1, stdin)) {
        s[LINE_LEN] = 0;        // extra caution
        StripCRLF(s);
        fprintf(stderr, "%s [%s] GOT: '%s'\n", remotehost, remoteip, s);

        // Break up command into args
        arg1[0] = arg2[0] = 0;
        if ( sscanf(s, "%s%s%s", cmd, arg1, arg2) < 1 ) continue;
        arg1[LINE_LEN] = 0;     // extra caution
        arg2[LINE_LEN] = 0;

        if ( ISIT("QUIT") ) {
            quit = 1;
            printf("221 %s closing connection%s", mydomain, CRLF);
            fflush(stdout);
        } else if ( ISIT("HELO") ) {
            printf("250 %s Hello %s [%s]%s", mydomain, remotehost, remoteip, CRLF);
            fflush(stdout);
        } else if ( ISIT("MAIL") ) {
            if ( ISARG1("FROM:")) {
                strcpy(mail_from, arg2);
                printf("250 '%s': Sender ok%s", mail_from, CRLF);
                fflush(stdout);
            } else {
                printf("501 Unknown argument '%s'%s", arg1, CRLF);
                fflush(stdout);
                fprintf(stderr, "%s [%s] ERROR: unknown MAIL argument '%s'",
		    remotehost, remoteip, arg1);
            }
        } else if ( ISIT("RCPT") ) {
            if ( ISARG1("TO:") ) {
                strcpy(rcpt_to, arg2);
                // TODO: If recipient fails, return "550 unknown local user"
                printf("250 %s... recipient ok%s", rcpt_to, CRLF);
            } else {
                printf("501 Unknown argument '%s'%s", arg1, CRLF);
                fprintf(stderr, "%s [%s] ERROR: unknown RCPT argument '%s'",
		    remotehost, remoteip, arg1);
            }
        } else if ( ISIT("DATA") ) {
            if ( rcpt_to[0] == 0 ) {
                printf("503 Bad sequence of commands -- missing RCPT TO%s", CRLF);
            } else if ( mail_from[0] == 0 ) {
                printf("503 Bad sequence of commands -- missing MAIL FROM%s", CRLF);
            } else {
                printf("354 Start mail input; end with <CRLF>.<CRLF>%s", CRLF);
                fflush(stdout);
                if ( ReadLetter(stdin, letter) == -1 ) {
                    fprintf(stderr, "%s %s: Premature end of input for DATA command\n",
		        remotehost, remoteip);
                    break;              // break fgets() loop
                }
		if ( letter.size() < 3 ) {
		    // Even a one line email has more header lines than this
		    printf("554 Message data was too short%s", CRLF);
		} else {
		    // Handle mail delivery
		    printf("250 Message accepted for delivery%s", CRLF);
		    DeliverMail(mail_from, rcpt_to, letter);
		}
            }
        } else if ( ISIT("RSET") ) {
            mail_from[0] = 0;
            rcpt_to[0] = 0;
            letter.clear();
            printf("250 OK%s", CRLF);
        } else if ( ISIT("NOOP") ) {
            printf("250 OK%s", CRLF);
        } else if ( ISIT("HELP") ) {
            printf("214 Help:%s", CRLF);
            printf("    HELO, DATA, RSET, NOOP, QUIT,%s", CRLF);
            printf("    MAIL FROM:,  RCPT TO:,%s", CRLF);
            printf("    VRFY, EXPN, EHLO, SEND, SOML, SAML, TURN%s", CRLF);
        } else if ( ISIT("VRFY") || ISIT("EXPN") ||
                    ISIT("SEND") || ISIT("SOML") ||
                    ISIT("SAML") || ISIT("TURN") ) {
            // COMMANDS WE DONT SUPPORT
            printf("502 Command not implemented or disabled%s", CRLF);
            fprintf(stderr, "%s [%s] ERROR: Remote tried '%s', we don't support it\n",
	        remotehost, remoteip, cmd);
        } else {
            printf("500 Unknown command%s", CRLF);
            fprintf(stderr, "%s [%s] ERROR: Remote tried '%s', unknown command\n",
	        remotehost, remoteip, cmd);
        }

        // All commands end up here, successful or not
        fflush(stdout);
    }

    if ( quit ) {
        // Normal end to transaction
        return 0;
    } else {
        // GOT HERE? END OF INPUT
        //     Connection closed with no "QUIT" issued.
        //
        fprintf(stderr, "%s %s: Premature end of input for SMTP commands\n",
            remotehost, remoteip);
        return 1;               // indicate an error occurred
    }
}
