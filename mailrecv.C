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
#include <string.h>     // strchr(), strerror()
#include <errno.h>      // errno
#include <stdlib.h>     // exit()
#include <sys/socket.h> // getpeername()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

using namespace std;

#define LINE_LEN        4096
#define CRLF            "\r\n"
#define CONFIG_FILE     "/etc/mailrecv.conf"

int G_debug = 0;

// Do a regular expression match test
//     Returns 0 on match, -1 on no match
//
int RegexMatch(const char*regex, const char *str) {
    return 1;               // TODO: handle pcre match here
}

class Configure {
    int maxsecs;                                    // maximum seconds program should run before stopping
    string domain;                                  // domain our server should know itself as (e.g. "example.com")

    // XXX: use a map
    vector<string> allow_mail_to_shell_address;     // mail_to shell addresses we allow
    vector<string> allow_mail_to_shell_command;     // mail_to shell command to pipe mail to

    // XXX: use a map
    vector<string> allow_mail_to_file_address;      // mail_to file addresses we allow
    vector<string> allow_mail_to_file_filename;     // mail_to file filename we append letters to

    // XXX: use a map
    vector<string> replace_mail_to_regex;           // mail_to regex to search for
    vector<string> replace_mail_to_after;           // mail_to regex match replacement string

    vector<string> allow_remotehost_regex;          // allowed remotehost name regex
    vector<string> allow_remoteip_regex;            // allowed remoteip address regex

public:
    Configure() {
        maxsecs = 300;
        domain  = "example.com";
    }

    // Accessors
    int MaxSecs() const { return maxsecs; }
    const char *Domain() const { return domain.c_str(); }

    // Load the specified config file
    //     Returns 0 on success, -1 on error (reason printed on stderr)
    //
    int Load(const char *conffile) {
        int err = 0;
        FILE *fp;
        if ( (fp = fopen(conffile, "r")) == NULL) {
            fprintf(stderr, "mailrecv: can't open %s: %s\n", conffile, strerror(errno));
            return -1;
        }
        char line[LINE_LEN+1], arg1[LINE_LEN+1], arg2[LINE_LEN+1];
        int linenum = 0;
        while ( fgets(line, LINE_LEN, fp) != NULL ) {
            // Keep count of lines
            ++linenum;

            // Strip comments, but keep trailing \n
            char *p = strchr(line,'#');
            if ( p ) { *p = 0; strcat(line, "\n"); }

            // Skip blank lines
            if ( line[0] == '\n' ) continue;

            // Handle config commands..
            //
            //     Note: Our combo of fgets() and sscanf() with just %s is safe from overruns;
            //     line[] is limited to LINE_LEN by fgets(), so arg1/arg2 must be shorter.
            //
            if ( sscanf(line, "domain %s", arg1) == 1 ) {
                domain = arg1;
            } else if ( sscanf(line, "allow mail_to %s file %s", arg1, arg2) == 2 ) {
                allow_mail_to_file_address.push_back(arg1);
                allow_mail_to_file_filename.push_back(arg2);
            } else if ( sscanf(line, "allow mail_to %s shell %[^\n]", arg1, arg2) == 2 ) {
                allow_mail_to_shell_address.push_back(arg1);
                allow_mail_to_shell_command.push_back(arg2);
            } else if ( sscanf(line, "replace mail_to %s %s", arg1, arg2) == 2 ) {
                replace_mail_to_regex.push_back(arg1);
                replace_mail_to_after.push_back(arg2);
            } else if ( sscanf(line, "allow remotehost %s", arg1) == 1 ) {
                allow_remotehost_regex.push_back(arg1);
            } else if ( sscanf(line, "allow remoteip %s", arg1) == 1 ) {
                allow_remoteip_regex.push_back(arg1);
            } else {
                fprintf(stderr, "ERROR: '%s' (LINE %d): ignoring unknown config command: %s\n", conffile, linenum, line);
                err = -1;
            }
        }
        fclose(fp);

        // Debugging enabled via command line?
        //     Show what we loaded..
        //
        if ( G_debug ) {
            fprintf(stderr, "--- Config file:\n");
            fprintf(stderr, "    maxsecs: %d\n", MaxSecs());
            fprintf(stderr, "    domain: '%s'\n", Domain());
            size_t t;
            for ( t=0; t<allow_mail_to_file_address.size(); t++ ) {
                fprintf(stderr, "    allow mail_to: address='%s', which writes to file='%s'\n",
                    allow_mail_to_file_address[t].c_str(),
                    allow_mail_to_file_filename[t].c_str());
            }
            for ( t=0; t<allow_mail_to_shell_address.size(); t++ ) {
                fprintf(stderr, "    allow mail_to: address='%s', which pipes to cmd='%s'\n",
                    allow_mail_to_shell_address[t].c_str(),
                    allow_mail_to_shell_command[t].c_str());
            }
            for ( t=0; t<allow_remotehost_regex.size(); t++ ) {
                fprintf(stderr, "    allow remote hostnames that match perl regex '%s'\n", allow_remotehost_regex[t].c_str());
            }
            for ( t=0; t<allow_remoteip_regex.size(); t++ ) {
                fprintf(stderr, "    allow remote IP addresses that match perl regex '%s'\n", allow_remoteip_regex[t].c_str());
            }
            fprintf(stderr, "---\n");
        }
        return err;     // let caller decide what to do
    }

    // See if remotehost/remoteip are allowed to connect to us
    //     Checks if any 'allow remotehost/remoteip ..' commands were configured,
    //     and if so, do match checks.
    //
    int CheckRemote(const char *remotehost, const char *remoteip) {
        // Nothing configured? Allow anyone
        if ( allow_remotehost_regex.size() == 0 &&
             allow_remoteip_regex.size()   == 0 ) {
            return 0;
        }

        // If one or both configured, must have at least one match

        // See if remote hostname allowed to connect to us
        for ( size_t t=0; t<allow_remotehost_regex.size(); t++ )
            if ( RegexMatch(allow_remotehost_regex[t].c_str(), remotehost) )
                return 0;   // match

        // Check if remote IP allowed to connect to us
        for ( size_t t=0; t<allow_remoteip_regex.size(); t++ )
            if ( RegexMatch(allow_remoteip_regex[t].c_str(), remoteip) )
                return 0;   // match

        return -1;          // No match? Failed
    }
};

Configure G_conf;

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

#define ISCMD(x)         !strcasecmp(cmd, x)
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
        if ( strcmp(s, ".") == 0 ) return 0;
        // Otherwise append lines with CRLF removed to letter
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

// Handle a complete SMTP session with the remote on stdin/stdout
int HandleSMTP(const char *remotehost, const char *remoteip) {
    vector<string> letter;
    char s[LINE_LEN+1],                 // raw line buffer
         cmd[LINE_LEN+1],               // cmd received
         arg1[LINE_LEN+1],              // arg1 received
         arg2[LINE_LEN+1],              // arg2 received
         mail_from[LINE_LEN+1],         // The remote's "MAIL FROM:" value
         rcpt_to[LINE_LEN+1];           // The remote's "RCPT TO:" value
    const char *domain = G_conf.Domain();

    // WE IMPLEMENT RFC 822 HELO PROTOCOL ONLY
    printf("220 %s SMTP (RFC 822) mailrecv\n", domain);

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

        if ( ISCMD("QUIT") ) {
            quit = 1;
            printf("221 %s closing connection%s", domain, CRLF);
            fflush(stdout);
        } else if ( ISCMD("HELO") ) {
            printf("250 %s Hello %s [%s]%s", domain, remotehost, remoteip, CRLF);
            fflush(stdout);
        } else if ( ISCMD("MAIL") ) {
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
        } else if ( ISCMD("RCPT") ) {
            if ( ISARG1("TO:") ) {
                strcpy(rcpt_to, arg2);
                // TODO: If recipient fails, return "550 unknown local user"
                printf("250 %s... recipient ok%s", rcpt_to, CRLF);
            } else {
                printf("501 Unknown argument '%s'%s", arg1, CRLF);
                fprintf(stderr, "%s [%s] ERROR: unknown RCPT argument '%s'",
		    remotehost, remoteip, arg1);
            }
        } else if ( ISCMD("DATA") ) {
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
        } else if ( ISCMD("RSET") ) {
            mail_from[0] = 0;
            rcpt_to[0] = 0;
            letter.clear();
            printf("250 OK%s", CRLF);
        } else if ( ISCMD("NOOP") ) {
            printf("250 OK%s", CRLF);
        } else if ( ISCMD("HELP") ) {
            printf("214 Help:%s", CRLF);
            printf("    HELO, DATA, RSET, NOOP, QUIT,%s", CRLF);
            printf("    MAIL FROM:,  RCPT TO:,%s", CRLF);
            printf("    VRFY, EXPN, EHLO, SEND, SOML, SAML, TURN%s", CRLF);
        } else if ( ISCMD("VRFY") || ISCMD("EXPN") ||
                    ISCMD("SEND") || ISCMD("SOML") ||
                    ISCMD("SAML") || ISCMD("TURN") ) {
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

// Show help and exit
void HelpAndExit() {
    fputs("mailrecv - a simple SMTP xinetd daemon (V " VERSION ")\n"
          "        See LICENSE file packaged with newsd for license/copyright info.\n"
          "\n"
	  "Options\n"
	  "    -c config-file     -- use 'config-file' instead of default (" CONFIG_FILE ")\n"
	  "    -d                 -- enable debugging messages on stderr\n"
	  "\n",
          stderr);
    exit(1);
}

int main(int argc, const char *argv[]) {
    // Initial config file
    const char *conffile = CONFIG_FILE;

    // Parse command line, possibly override default conffile, etc.
    for (int t=1; t<argc; t++) {
        if (strcmp(argv[t], "-c") == 0) {
	    if (++t >= argc) {
	        fprintf(stderr, "mailrecv: ERROR: expected filename after '-c'\n");
                return 1;
	    }
            conffile = argv[t];
	}
	else if (strcmp(argv[t], "-d") == 0) {
            G_debug = 1;
        } else if (strncmp(argv[t], "-h", 2) == 0) {
	    HelpAndExit();
        } else {
	    fprintf(stderr, "mailrecv: ERROR: unknown argument '%s'\n", argv[t]);
            HelpAndExit();
        }
    }

    // Load config file
    if ( G_conf.Load(conffile) < 0 ) {
        // Tell remote we can't receive SMTP at this time
        printf("221 Cannot receive messages at this time.\n");
        fflush(stdout);
        return 1;       // fail
    }

    // Get the remote IP address for stdin
    char remoteip[LINE_LEN+1];
    char remotehost[LINE_LEN+1];
    GetRemoteIPAddr(stdin, remoteip, LINE_LEN);
    GetRemoteHostname(stdin, remotehost, LINE_LEN);
    
    // Check if remote allowed to connect to us
    if ( G_conf.CheckRemote(remotehost, remoteip) < 0 ) {
        printf("221 Cannot receive messages from %s [%s] at this time.\n", remotehost, remoteip);
        fflush(stdout);
        fprintf(stderr, "DENIED: Connection from %s [%s] not in allow_remote* lists\n", remotehost, remoteip);
        return 1;
    }

    // Handle the SMTP session with the remote
    return HandleSMTP(remotehost, remoteip);
}
