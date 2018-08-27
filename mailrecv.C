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
#include <stdarg.h>     // vargs
#include <syslog.h>     // syslog()
#include <pcre.h>       // perl regular expressions API (see 'man pcreapi(3)')
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

// Log a message...
void Log(const char *msg, ...) {
    // Format the message...
    va_list      ap;			// Argument list pointer
    char         buffer[1024];		// Message buffer
    unsigned int bytes;			// Size of message

    va_start(ap, msg);
    bytes = vsnprintf(buffer, sizeof(buffer), msg, ap);
    va_end(ap);

    syslog(LOG_ERR, "%s", buffer);
}

// Do a regular expression match test
// 
//     regex -- regular expression to match against string
//     match -- string to be matched
//
// Returns:
//     1: string matched
//     0: string didn't match
//    -1: an error occurred (reason was printed to stderr)
//
int RegexMatch(const char*regex, const char *match) {
    const char *regex_errorstr;		// returned error if any
    int         regex_erroroff;		// offset in string where error occurred

    // Compile the regex..
    pcre *regex_compiled = pcre_compile(regex, 0, &regex_errorstr, &regex_erroroff, NULL);
    if ( regex_compiled == NULL ) {
        Log("ERROR: could not compile regex '%s': %s\n", regex, regex_errorstr);
        Log("                               %*s^\n",     regex_erroroff, ""); // point to the error
        Log("                               %*sError here\n", regex_erroroff, "");
	return -1;
    }

    // Optimize regex
    pcre_extra *regex_extra = pcre_study(regex_compiled, 0, &regex_errorstr);
    if ( regex_errorstr != NULL ) {
        pcre_free(regex_compiled);  // don't leak compiled regex
        Log("ERROR: Could not study regex '%s': %s\n", regex, regex_errorstr);
	return -1;
    }

    // Now see if we can match string
    int *substrvec = NULL; // pcre_exec()'s captured substrings (NULL=disinterest)
    int nsubstrvec = 0;    // number of elements in substrvec (0=disinterest)
    int soff = 0;          // starting offset (0=start of string)
    int opts = 0;          // pcre_exec()'s options (0=none)
    int ret = pcre_exec(regex_compiled, regex_extra, match, strlen(match), soff, opts, substrvec, nsubstrvec);

    // Free up compiled regex
    pcre_free(regex_compiled);
    pcre_free(regex_extra);

    // Check match results..
    if ( ret < 0 ) {
	switch (ret) {
	    case PCRE_ERROR_NOMATCH:
                return 0;  // string didn't match
	    default:
                Log("ERROR: bad regex '%s'\n", regex);
                return -1;
	}
    }
    return 1;   // string matched
}

// Append letter to specified file
int AppendMailToFile(const char *mail_from,
                     const char *rcpt_to,
                     const vector<string>& letter,
                     const string& filename) {
    FILE *fp;
    if ( (fp = fopen(filename.c_str(), "a")) == NULL) {
        Log("ERROR: can't append to %s: %s\n", filename.c_str(), strerror(errno));
        return -1;  // fail
    }
    fprintf(fp, "From %s\n", mail_from);
    for ( size_t t=0; t<letter.size(); t++ ) {
        fprintf(fp, "%s\n", letter[t].c_str());
    }
    fclose(fp);
    return 1;       // success
}

// Pipe letter to specified shell command
int PipeMailToCommand(const char *mail_from,
                      const char *rcpt_to,
                      const vector<string>& letter,
                      const string& command) {
    FILE *fp;
    if ( (fp = popen(command.c_str(), "w")) == NULL) {
        Log("ERROR: can't popen(%s): %s\n", command.c_str(), strerror(errno));
        return -1;  // fail
    }
    fprintf(fp, "From %s\n", mail_from);
    for ( size_t t=0; t<letter.size(); t++ ) {
        fprintf(fp, "%s\n", letter[t].c_str());
    }
    pclose(fp);
    return 1;       // success
}

// mailrecv's configuration file class
class Configure {
    int maxsecs;                                    // maximum seconds program should run before stopping
    string domain;                                  // domain our server should know itself as (e.g. "example.com")
                                                    // and accept mail for.
    string deadletter_file;                         // file to append messages to that have no 'deliver'

    vector<string> deliver_rcpt_to_pipe_address;    // configured rcpt_to addresses to pipe to a shell command
    vector<string> deliver_rcpt_to_pipe_command;    // rcpt_to shell command to pipe matching mail to address

    vector<string> deliver_rcpt_to_file_address;    // rcpt_to file addresses we allow
    vector<string> deliver_rcpt_to_file_filename;   // rcpt_to file filename we append letters to

    vector<string> replace_rcpt_to_regex;           // rcpt_to regex to search for
    vector<string> replace_rcpt_to_after;           // rcpt_to regex match replacement string

    vector<string> allow_remotehost_regex;          // allowed remotehost name regex
    vector<string> allow_remoteip_regex;            // allowed remoteip address regex

public:
    Configure() {
        maxsecs = 300;
        domain  = "example.com";
        deadletter_file = "/dev/null";              // must be "something"
    }

    // Accessors
    int MaxSecs() const { return maxsecs; }
    const char *Domain() const { return domain.c_str(); }
    const char *DeadLetterFile() const { return deadletter_file.c_str(); }

    // Load the specified config file
    //     Returns 0 on success, -1 on error (reason printed on stderr)
    //
    int Load(const char *conffile) {
        int err = 0;
        FILE *fp;
        if ( (fp = fopen(conffile, "r")) == NULL) {
            Log("ERROR: can't open %s: %s\n", conffile, strerror(errno));
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

            // Show each line loaded if debugging..
            if ( G_debug) Log("DEBUG: Loading config: %s", line);   // line includes \n

            // Handle config commands..
            //
            //     Note: Our combo of fgets() and sscanf() with just %s is safe from overruns;
            //     line[] is limited to LINE_LEN by fgets(), so arg1/arg2 must be shorter.
            //
            if ( sscanf(line, "domain %s", arg1) == 1 ) {
                domain = arg1;
            } else if ( sscanf(line, "deadletter_file %s", arg1) == 1 ) {
                deadletter_file = arg1;
            } else if ( sscanf(line, "deliver rcpt_to %s append %s", arg1, arg2) == 2 ) {
                deliver_rcpt_to_file_address.push_back(arg1);
                deliver_rcpt_to_file_filename.push_back(arg2);
            } else if ( sscanf(line, "deliver rcpt_to %s pipe %[^\n]", arg1, arg2) == 2 ) {
                deliver_rcpt_to_pipe_address.push_back(arg1);
                deliver_rcpt_to_pipe_command.push_back(arg2);
            } else if ( sscanf(line, "replace rcpt_to %s %s", arg1, arg2) == 2 ) {
                // Make sure regex compiles..
                if ( RegexMatch(arg1, "x") == -1 ) {
                    Log("ERROR: '%s' (LINE %d): bad replace rcpt_to regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                }
                replace_rcpt_to_regex.push_back(arg1);
                replace_rcpt_to_after.push_back(arg2);
            } else if ( sscanf(line, "allow remotehost %s", arg1) == 1 ) {
                // Make sure regex compiles..
                if ( RegexMatch(arg1, "x") == -1 ) {
                    Log("ERROR: '%s' (LINE %d): bad remotehost regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                }
                allow_remotehost_regex.push_back(arg1);
            } else if ( sscanf(line, "allow remoteip %s", arg1) == 1 ) {
                // Make sure regex compiles..
                if ( RegexMatch(arg1, "x") == -1 ) {
                    Log("ERROR: '%s' (LINE %d): bad remoteip regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                }
                allow_remoteip_regex.push_back(arg1);
            } else {
                Log("ERROR: '%s' (LINE %d): ignoring unknown config command: %s\n", conffile, linenum, line);
                err = -1;
            }
        }
        fclose(fp);

        // Debugging enabled via command line?
        //     Show what we loaded..
        //
        if ( G_debug ) {
            Log("DEBUG: --- Config file:\n");
            Log("DEBUG:    maxsecs: %d\n", MaxSecs());
            Log("DEBUG:    domain: '%s'\n", Domain());
            Log("DEBUG:    deadletter_file: '%s'\n", DeadLetterFile());
            size_t t;
            for ( t=0; t<deliver_rcpt_to_file_address.size(); t++ ) {
                Log("DEBUG:    deliver rcpt_to: address='%s', which writes to file='%s'\n",
                    deliver_rcpt_to_file_address[t].c_str(),
                    deliver_rcpt_to_file_filename[t].c_str());
            }
            for ( t=0; t<deliver_rcpt_to_pipe_address.size(); t++ ) {
                Log("DEBUG:    deliver rcpt_to: address='%s', which pipes to cmd='%s'\n",
                    deliver_rcpt_to_pipe_address[t].c_str(),
                    deliver_rcpt_to_pipe_command[t].c_str());
            }
            for ( t=0; t<allow_remotehost_regex.size(); t++ ) {
                Log("DEBUG:    allow remote hostnames that match perl regex '%s'\n", allow_remotehost_regex[t].c_str());
            }
            for ( t=0; t<allow_remoteip_regex.size(); t++ ) {
                Log("DEBUG:    allow remote IP addresses that match perl regex '%s'\n", allow_remoteip_regex[t].c_str());
            }
            Log("DEBUG: ---\n");
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
            if ( G_debug) {
                Log("DEBUG: There are no checks configured for remotehost/remoteip"
                                " (allowing anyone to connect)\n");
            }
            return 0;
        }

        // If one or both configured, must have at least one match

        // See if remote hostname allowed to connect to us
        for ( size_t t=0; t<allow_remotehost_regex.size(); t++ ) {
            if ( G_debug) Log("DEBUG: Checking '%s' against '%s'..\n",
                              allow_remotehost_regex[t].c_str(), remotehost);
            if ( RegexMatch(allow_remotehost_regex[t].c_str(), remotehost) == 1 ) {
                if ( G_debug) Log("DEBUG:     Matched!\n");
                return 0;   // match
            }
            if ( G_debug) Log("DEBUG:     No match.\n");
        }

        // Check if remote IP allowed to connect to us
        for ( size_t t=0; t<allow_remoteip_regex.size(); t++ ) {
            if ( G_debug) Log("DEBUG: Checking '%s' against '%s'..\n",
                              allow_remoteip_regex[t].c_str(), remoteip);
            if ( RegexMatch(allow_remoteip_regex[t].c_str(), remoteip) == 1 ) {
                if ( G_debug) Log("DEBUG:     Matched!\n");
                return 0;   // match
            }
            if ( G_debug) Log("DEBUG:     No match.\n");
        }

        return -1;          // No match? Failed
    }

    // Deliver mail to recipient.
    //     If there's no configured recipient, write to deadletter file.
    //     Returns 1 on success, -1 on error (reason printed to stderr).
    //
    int DeliverMail(const char* mail_from,
                    const char *rcpt_to,
                    const vector<string>& letter) {
        size_t t;

        // Check for 'append to file' recipient..
        for ( t=0; t<deliver_rcpt_to_file_address.size(); t++ ) {
            if ( strcmp(rcpt_to, deliver_rcpt_to_file_address[t].c_str()) == 0 ) {
                AppendMailToFile(mail_from, rcpt_to, letter, deliver_rcpt_to_file_filename[t]);
                return 1;   // delivered
            }
        }
        // Check for 'pipe to command' recipient..
        for ( t=0; t<deliver_rcpt_to_pipe_address.size(); t++ ) {
            if ( strcmp(rcpt_to, deliver_rcpt_to_pipe_address[t].c_str()) == 0 ) {
                PipeMailToCommand(mail_from, rcpt_to, letter, deliver_rcpt_to_pipe_command[t]);
                return 1;   // delivered
            }
        }
        // If we're here, nothing matched.. write to deadletter file
        AppendMailToFile(mail_from, rcpt_to, letter, deadletter_file);
        return 1;   // delivered
    }

};

Configure G_conf;

// TODO: Put a timer on this entire program.
//       Abort if we're running longer than G_config.MaxSecs()

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
        if ( G_debug ) Log("DEBUG: Letter: '%s'\n", s);
        // End of letter? done
        if ( strcmp(s, ".") == 0 ) return 0;
        // Otherwise append lines with CRLF removed to letter
        letter.push_back(s);
    }
    return -1;                  // premature end of input
}

// Handle a complete SMTP session with the remote on stdin/stdout
int HandleSMTP(const char *remotehost, const char *remoteip) {
    vector<string> letter;
    char line[LINE_LEN+1],              // raw line buffer
         cmd[LINE_LEN+1],               // cmd received
         arg1[LINE_LEN+1],              // arg1 received
         arg2[LINE_LEN+1],              // arg2 received
         mail_from[LINE_LEN+1],         // The remote's "MAIL FROM:" value
         rcpt_to[LINE_LEN+1];           // The remote's "RCPT TO:" value
    const char *domain = G_conf.Domain();

    // WE IMPLEMENT RFC 822 HELO PROTOCOL ONLY
    printf("220 %s SMTP (RFC 822) mailrecv\n", domain);
    fflush(stdout);

    int quit = 0;
    while (!quit && fgets(line, LINE_LEN-1, stdin)) {
        line[LINE_LEN] = 0;        // extra caution
        StripCRLF(line);
        if ( G_debug ) 
            Log("DEBUG: SMTP from %s [%s]: %s\n", remotehost, remoteip, line);

        // Break up command into args
        arg1[0] = arg2[0] = 0;
        if ( sscanf(line, "%s%s%s", cmd, arg1, arg2) < 1 ) continue;
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
                Log("ERROR: unknown MAIL argument '%s' from %s [%s]\n", arg1, remotehost, remoteip);
            }
        } else if ( ISCMD("RCPT") ) {
            if ( ISARG1("TO:") ) {
                strcpy(rcpt_to, arg2);
                // TODO: If recipient fails, return "550 unknown local user"
                printf("250 %s... recipient ok%s", rcpt_to, CRLF);
            } else {
                printf("501 Unknown argument '%s'%s", arg1, CRLF);
                Log("ERROR: unknown RCPT argument '%s' from %s [%s]\n",
		    arg1, remotehost, remoteip);
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
                    Log("ERROR: Premature end of input for DATA command from %s [%s]\n",
		        remotehost, remoteip);
                    break;              // break fgets() loop
                }
		if ( letter.size() < 3 ) {
		    // Even a one line email has more header lines than this
		    printf("554 Message data was too short%s", CRLF);
		} else {
		    // Handle mail delivery
		    printf("250 Message accepted for delivery%s", CRLF);
		    G_conf.DeliverMail(mail_from, rcpt_to, letter);
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
            // COMMANDS WE DON'T SUPPORT
            printf("502 Command not implemented or disabled%s", CRLF);
            Log("ERROR: Remote tried '%s', we don't support it from %s [%s]\n",
	        cmd, remotehost, remoteip);
        } else {
            printf("500 Unknown command%s", CRLF);
            Log("ERROR: Remote tried '%s', unknown command from %s [%s]\n",
	        cmd, remotehost, remoteip);
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
        Log("ERROR: Premature end of input for SMTP commands from %s [%s]\n",
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

    // Force bourne shell for popen(command)..
    setenv("SHELL", "/bin/sh", 1);

    // Initial config file
    const char *conffile = CONFIG_FILE;

    // Parse command line, possibly override default conffile, etc.
    for (int t=1; t<argc; t++) {
        if (strcmp(argv[t], "-c") == 0) {
	    if (++t >= argc) {
	        Log("ERROR: expected filename after '-c'\n");
                return 1;
	    }
            conffile = argv[t];
	}
	else if (strcmp(argv[t], "-d") == 0) {
            G_debug = 1;
        } else if (strncmp(argv[t], "-h", 2) == 0) {
	    HelpAndExit();
        } else {
	    Log("ERROR: unknown argument '%s'\n", argv[t]);
            HelpAndExit();
        }
    }

    // Load config file
    if ( G_conf.Load(conffile) < 0 ) {
        // Tell remote we can't receive SMTP at this time
        printf("221 Cannot receive messages at this time.\n");
        fflush(stdout);
        Log("ERROR: config file has errors (see above)\n");
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
        Log("DENIED: Connection from %s [%s] not in allow_remotehost/ip lists\n", remotehost, remoteip);
        return 1;
    }

    // Handle the SMTP session with the remote
    return HandleSMTP(remotehost, remoteip);
}
