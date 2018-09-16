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
#include <errno.h>      // errno
#include <stdlib.h>     // exit()
#include <stdarg.h>     // vargs
#include <syslog.h>     // syslog()
#include <pcre.h>       // perl regular expressions API (see 'man pcreapi(3)')
#include <sys/socket.h> // getpeername()
#include <netdb.h>      // gethostbyaddr()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

using namespace std;

#define LINE_LEN        4096
#define CRLF            "\r\n"
#define CONFIG_FILE     "/etc/mailrecv.conf"

// Check for log flags
#define ISLOG(s) if (G_debugflags[0] && (G_debugflags[0]=='a'||strpbrk(G_debugflags, s)))

// Log flags.
//    Can be one or more of these single letter flags.
//    An empty string disables all optional logging.
//
//    a -- all (enables all optional flags)
//    c -- show config file loading process
//    s -- SMTP commands
//    l -- show letter as it's received
//    r -- show regex pattern match checks
//    f -- show file/pipe open/save/close
//    w -- log non-essential warnings
//
const char *G_debugflags = "";

// Log a message...
//     In addition to the usual printf() behavior, %m is replaced with strerror(errno)
//     due to syslog(3).
//
void Log(const char *msg, ...) {
    va_list ap;
    va_start(ap, msg);
    vsyslog(LOG_ERR, msg, ap);
    va_end(ap);
}

// Do a regular expression match test
//
//     regex[in] -- regular expression to match against string
//     match[in] -- string to be matched
//
// Returns:
//     1: string matched
//     0: string didn't match
//    -1: an error occurred (reason was printed to stderr)
//
int RegexMatch(const char*regex, const char *match) {
    const char *regex_errorstr;         // returned error if any
    int         regex_erroroff;         // offset in string where error occurred

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

// Append email to the specified file
int AppendMailToFile(const char *mail_from,         // SMTP 'mail from:'
                     const char *rcpt_to,           // SMTP 'rcpt to:'
                     const vector<string>& letter,  // email contents, including headers, blank line, body
                     const string& filename) {      // filename to append to
    FILE *fp;
    ISLOG("f") { Log("DEBUG: fopen(%s,'a')\n", filename.c_str()); }
    if ( (fp = fopen(filename.c_str(), "a")) == NULL) {
        Log("ERROR: can't append to %s: %m\n", filename.c_str());   // %m: see syslog(3)
        return -1;  // fail
    }
    fprintf(fp, "From %s\n", mail_from);            // XXX: perhaps unneeded; useful as a message separator
    for ( size_t t=0; t<letter.size(); t++ ) {
        fprintf(fp, "%s\n", letter[t].c_str());
    }
    int ret = fclose(fp);
    ISLOG("f") { Log("DEBUG: fclose() returned %d\n", ret); }
    return 1;       // success
}

// Pipe letter to specified shell command
int PipeMailToCommand(const char *mail_from,        // SMTP 'mail from:'
                      const char *rcpt_to,          // SMTP 'rcpt to:'
                      const vector<string>& letter, // email contents, including headers, blank line, body
                      const string& command) {      // unix shell command to write to
    ISLOG("f") { Log("DEBUG: popen(%s,'w')..\n", command.c_str()); }
    FILE *fp;
    if ( (fp = popen(command.c_str(), "w")) == NULL) {
        Log("ERROR: can't popen(%s): %m\n", command.c_str());
        return -1;  // fail
    }
    fprintf(fp, "From %s\n", mail_from);            // XXX: might not be needed
    for ( size_t t=0; t<letter.size(); t++ ) {
        fprintf(fp, "%s\n", letter[t].c_str());
    }
    int ret = pclose(fp);
    ISLOG("f") { Log("DEBUG: pclose() returned %d\n", ret); }
    return 1;       // success
}

// mailrecv's configuration file class
//     TODO: This should be moved to a separate file.
//
class Configure {
    int maxsecs;                                    // maximum seconds program should run before stopping
    string domain;                                  // domain our server should know itself as (e.g. "example.com")
                                                    // and accept mail for.
    string deadletter_file;                         // file to append messages to that have no 'deliver'

    vector<string> deliver_rcpt_to_pipe_address;    // configured rcpt_to addresses to pipe to a shell command (TODO: Should be regex instead?)
    vector<string> deliver_rcpt_to_pipe_command;    // rcpt_to shell command to pipe matching mail to address

    vector<string> deliver_rcpt_to_file_address;    // rcpt_to file addresses we allow (TODO: Should be regex instead?)
    vector<string> deliver_rcpt_to_file_filename;   // rcpt_to file filename we append letters to

    vector<string> errors_rcpt_to_regex;            // error address to match
    vector<string> errors_rcpt_to_message;          // error message to send remote on match

    vector<string> replace_rcpt_to_regex;           // rcpt_to regex to search for (TODO: NOT YET IMPLEMENTED)
    vector<string> replace_rcpt_to_after;           // rcpt_to regex match replacement string (TODO: NOT YET IMPLEMENTED)

    vector<string> allow_remotehost_regex;          // allowed remotehost name regex
    vector<string> allow_remoteip_regex;            // allowed remoteip address regex

public:
    Configure() {
        maxsecs = 300;
        domain  = "example.com";
        deadletter_file = "/dev/null";              // must be set to "something"
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
        ISLOG("fc") { Log("DEBUG: fopen(%s,'r')..\n", conffile); }
        if ( (fp = fopen(conffile, "r")) == NULL) {
            Log("ERROR: can't open %s: %m\n", conffile);
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
            ISLOG("c") { Log("DEBUG: Loading config: %s", line); }   // line includes \n

            // Handle config commands..
            //
            //     Note: Our combo of fgets() and sscanf() with just %s is safe from overruns;
            //     line[] is limited to LINE_LEN by fgets(), so arg1/arg2 must be shorter.
            //
            if ( sscanf(line, "domain %s", arg1) == 1 ) {
                domain = arg1;
            } else if ( sscanf(line, "debug %s", arg1) == 1 ) {
                if ( !G_debugflags[0] ) {   // no command line override?
                    if ( strcmp(arg1, "-") != 0 ) {
                        G_debugflags = (const char*)strdup(arg1);
                    }
                }
            } else if ( sscanf(line, "deadletter_file %s", arg1) == 1 ) {
                deadletter_file = arg1;
            } else if ( sscanf(line, "deliver rcpt_to %s append %s", arg1, arg2) == 2 ) {
                deliver_rcpt_to_file_address.push_back(arg1);
                deliver_rcpt_to_file_filename.push_back(arg2);
            } else if ( sscanf(line, "deliver rcpt_to %s pipe %[^\n]", arg1, arg2) == 2 ) {
                deliver_rcpt_to_pipe_address.push_back(arg1);
                deliver_rcpt_to_pipe_command.push_back(arg2);
            } else if ( sscanf(line, "error rcpt_to %s %[^\n]", arg1, arg2) == 2 ) {
                int ecode;
                // Make sure error message includes 3 digit SMTP error code
                if ( sscanf(arg2, "%d", &ecode) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): missing 3 digit SMTP error message '%s'", conffile, linenum, arg2);
                    err = -1;
                    continue;
                }
                if ( RegexMatch(arg1, "x") == -1 ) { // Make sure regex compiles..
                    Log("ERROR: '%s' (LINE %d): bad 'error rcpt_to' regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                errors_rcpt_to_regex.push_back(arg1);
                errors_rcpt_to_message.push_back(arg2);
            } else if ( sscanf(line, "replace rcpt_to %s %s", arg1, arg2) == 2 ) {
                // Make sure regex compiles..
                if ( RegexMatch(arg1, "x") == -1 ) {
                    Log("ERROR: '%s' (LINE %d): bad 'replace rcpt_to' regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                }
                replace_rcpt_to_regex.push_back(arg1);
                replace_rcpt_to_after.push_back(arg2);
            } else if ( sscanf(line, "allow remotehost %s", arg1) == 1 ) {
                // Make sure regex compiles..
                if ( RegexMatch(arg1, "x") == -1 ) {
                    Log("ERROR: '%s' (LINE %d): bad 'allow remotehost' regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                }
                allow_remotehost_regex.push_back(arg1);
            } else if ( sscanf(line, "allow remoteip %s", arg1) == 1 ) {
                // Make sure regex compiles..
                if ( RegexMatch(arg1, "x") == -1 ) {
                    Log("ERROR: '%s' (LINE %d): bad 'allow remoteip' regex '%s'\n", conffile, linenum, arg1);
                    err = -1;
                }
                allow_remoteip_regex.push_back(arg1);
            } else {
                Log("ERROR: '%s' (LINE %d): ignoring unknown config command: %s\n", conffile, linenum, line);
                err = -1;
            }
        }
        int ret = fclose(fp);
        ISLOG("f") { Log("DEBUG: fclose() returned %d\n", ret); }

        // Show everything we actually loaded..
        ISLOG("c") {
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
    // Returns:
    //     0 -- Remote is allowed
    //    -1 -- Remote is NOT allowed
    //
    int CheckRemote(const char *remotehost,     // remote's hostname
                    const char *remoteip) {     // remote's IP address string
        // Nothing configured? Allow anyone
        if ( allow_remotehost_regex.size() == 0 &&
             allow_remoteip_regex.size()   == 0 ) {
            ISLOG("r") {
                Log("DEBUG: There are no checks configured for remotehost/remoteip"
                                " (allowing anyone to connect)\n");
            }
            return 0;
        }

        // If one or both configured, must have at least one match

        // See if remote hostname allowed to connect to us
        for ( size_t t=0; t<allow_remotehost_regex.size(); t++ ) {
            ISLOG("r") {
                Log("DEBUG: Checking '%s' against '%s'..\n",
                    allow_remotehost_regex[t].c_str(), remotehost);
            }
            if ( RegexMatch(allow_remotehost_regex[t].c_str(), remotehost) == 1 ) {
                ISLOG("r") { Log("DEBUG:     Matched!\n"); }
                return 0;   // match
            }
            ISLOG("r") { Log("DEBUG:     No match.\n"); }
        }

        // Check if remote IP allowed to connect to us
        for ( size_t t=0; t<allow_remoteip_regex.size(); t++ ) {
            ISLOG("r") {
                Log("DEBUG: Checking '%s' against '%s'..\n",
                    allow_remoteip_regex[t].c_str(), remoteip);
            }
            if ( RegexMatch(allow_remoteip_regex[t].c_str(), remoteip) == 1 ) {
                ISLOG("r") { Log("DEBUG:     Matched!\n"); }
                return 0;   // match
            }
            ISLOG("r") { Log("DEBUG:     No match.!\n"); }
        }

        return -1;          // No match? Failed
    }

    // Deliver mail to recipient.
    //     If there's no configured recipient, write to deadletter file.
    //
    // Returns:
    //     1 on success
    //    -1 on error (reason printed to stderr).
    //
    int DeliverMail(const char* mail_from,          // SMTP 'mail from:'
                    const char *rcpt_to,            // SMTP 'rcpt to:'
                    const vector<string>& letter) { // email contents, including headers, blank line, body
        size_t t;

        // Check for 'append to file' recipient..
        for ( t=0; t<deliver_rcpt_to_file_address.size(); t++ ) {
            if ( strcmp(rcpt_to, deliver_rcpt_to_file_address[t].c_str()) == 0 ) {
                // TODO: Check error return of AppendMailToFile(), fall thru to deadletter?
                AppendMailToFile(mail_from, rcpt_to, letter, deliver_rcpt_to_file_filename[t]);
                return 1;   // delivered
            }
        }

        // Check for 'pipe to command' recipient..
        for ( t=0; t<deliver_rcpt_to_pipe_address.size(); t++ ) {
            if ( strcmp(rcpt_to, deliver_rcpt_to_pipe_address[t].c_str()) == 0 ) {
                // TODO: Check error return of PipeMailToCommand(), fall thru to deadletter?
                PipeMailToCommand(mail_from, rcpt_to, letter, deliver_rcpt_to_pipe_command[t]);
                return 1;   // delivered
            }
        }

        // If we're here, nothing matched.. write to deadletter file
        //
        // TODO: Return -1 if deadletter append failed
        //
        // TODO: Pass back actual OS error to remote as part of SMTP response
        //
        if ( AppendMailToFile(mail_from, rcpt_to, letter, deadletter_file) < 0 )
            return -1;    // failed deadletter delivery? Tell remote we can't deliver

        return 1;   // delivered
    }

    // See if address is an error address
    //
    // Returns:
    //    0 -- OK to deliver -- not an error address
    //   -1 -- Error address -- caller should send 'emsg' to remote, and skip delivery
    //
    int CheckErrorAddress(const char *address, string& emsg) {
        for ( int i=0; i<errors_rcpt_to_regex.size(); i++ ) {
            if ( RegexMatch(errors_rcpt_to_regex[i].c_str(), address) == 1 ) {
                emsg = errors_rcpt_to_message[i];
                return -1;  // NOT OK to deliver -- emsg has error to send remote
            }
        }
        return 0;           // OK to deliver
    }
};

Configure G_conf;

// TODO: Put a timer on this entire program.
//       Abort if we're running longer than G_config.MaxSecs()

// Minimum commands we must support:
//      HELO MAIL RCPT DATA RSET NOOP QUIT VRFY

// Remote's hostname + ip address
char G_remotehost[256];
char G_remoteip[80];

// Return with remote's ip address + hostname in globals
//    Sets globals: G_remotehost, G_remoteip
//
//    fp -- tcp connection as a FILE* (typically stdin because xinetd invoked us)
//
// Returns:
//     0 -- success (got IP for sure, may or may not have gotten remote hostname)
//    -1 -- could not determine any remote info
//
// TODO: Allow remote hostname lookups to be optional (as it adds DNS lookup load).
// TODO: Such an option would need to be automatically enabled if the conf file
// TODO: "allow remotehost .." is specified.
//
int GetRemoteHostInfo(FILE *fp) {
    struct sockaddr_in raddr;
    socklen_t raddr_size = sizeof(raddr);
    if ( getpeername(fileno(fp), (struct sockaddr*)&raddr, &raddr_size) == 0 ) {
        // Get remote IP address string
        sprintf(G_remoteip, "%.*s", int(sizeof(G_remoteip))-1, inet_ntoa(raddr.sin_addr));

        // Get remote Hostname string
        struct hostent *he;
        if ( he = gethostbyaddr((struct addr_in*)&(raddr.sin_addr),
                                sizeof(raddr.sin_addr), AF_INET) ) {
            sprintf(G_remotehost, "%.*s", int(sizeof(G_remotehost))-1, he->h_name);
        } else {
            strcpy(G_remotehost, "???");
        }
        return 0;
    } else {
        // Non-fatal, i.e. if testing from a shell
        Log("WARNING: getpeername() couldn't determine remote IP address: %m");
        strcpy(G_remotehost, "???");
        strcpy(G_remoteip,   "?.?.?.?");
        return -1;
    }
    return 0;
}

// TRUNCATE STRING AT FIRST CR OR LF
void StripCRLF(char *s) {
    char *eol;
    if ( (eol = strchr(s, '\r')) ) { *eol = 0; }
    if ( (eol = strchr(s, '\n')) ) { *eol = 0; }
}

#define ISCMD(x)        !strcasecmp(cmd, x)
#define ISARG1(x)       !strcasecmp(arg1, x)

// READ LETTER'S DATA FROM THE REMOTE
//     Assumes an SMTP "DATA" command was just received.
//
//     TODO: Should insert a "Received:" block into the headers, above the first one
//     TODO: encountered, e.g. 
//     TODO:    Received: from <HELO_FROM> (remotehost [remoteIP])
//     TODO:              by ourdomain.com (mailrecv) with SMTP id ?????
//     TODO:              for <rcpt_to>; Sat,  8 Sep 2018 23:44:11 -0400 (EDT)
//
// Returns:
//     0 on success
//    -1 on premature end of input.
//
int ReadLetter(FILE *fp,                    // [in] connection to remote
               vector<string>& letter) {    // [in] array for saved letter
    char s[LINE_LEN+1];
    while (fgets(s, LINE_LEN, stdin)) {
        StripCRLF(s);
        ISLOG("l") { Log("DEBUG: Letter: '%s'\n", s); }
        // End of letter? done
        if ( strcmp(s, ".") == 0 ) return 0;
        // Otherwise append lines with CRLF removed to letter
        letter.push_back(s);
    }
    return -1;                  // premature end of input
}

// Handle a complete SMTP session with the remote on stdin/stdout
int HandleSMTP() {
    vector<string> letter;              // array for received email (SMTP "DATA")
    char line[LINE_LEN+1],              // raw line buffer
         cmd[LINE_LEN+1],               // cmd received
         arg1[LINE_LEN+1],              // arg1 received
         arg2[LINE_LEN+1],              // arg2 received
         mail_from[LINE_LEN+1] = "",    // The remote's "MAIL FROM:" value
         rcpt_to[LINE_LEN+1]   = "";    // The remote's "RCPT TO:" value (TODO: Should be array; there can be more than one per transaction)
    const char *our_domain = G_conf.Domain();

    // We implement RFC 822 "HELO" protocol only.. no fancy EHLO stuff.
    printf("220 %s SMTP (RFC 822) mailrecv\n", our_domain);
    fflush(stdout);

    // READ ALL SMTP COMMANDS FROM REMOTE UNTIL "QUIT" OR EOF
    int quit = 0;
    while (!quit && fgets(line, LINE_LEN-1, stdin)) {
        line[LINE_LEN] = 0;        // extra caution
        StripCRLF(line);
        ISLOG("s") { Log("DEBUG: SMTP cmd: %s\n", line); }

        // Break up command into args
        //    note: fgets() already ensures LINE_LEN max, so
        //          sscanf() does not need to re-enforce length max.
        //
        arg1[0] = arg2[0] = 0;
        if ( sscanf(line, "%s%s%s", cmd, arg1, arg2) < 1 ) continue;
        arg1[LINE_LEN] = 0;     // extra caution
        arg2[LINE_LEN] = 0;

        if ( ISCMD("QUIT") ) {
            quit = 1;
            printf("221 %s closing connection%s", our_domain, CRLF);
        } else if ( ISCMD("HELO") ) {
            printf("250 %s Hello %s [%s]%s", our_domain, G_remotehost, G_remoteip, CRLF);
        } else if ( ISCMD("MAIL") ) {
            if ( ISARG1("FROM:")) {                         // "MAIL FROM: foo@bar.com"? (space after ":")
                strcpy(mail_from, arg2);
                printf("250 '%s': Sender ok%s", mail_from, CRLF);
            } else {
                if ( strncasecmp(arg1,"FROM:", 5) == 0 ) {  // "MAIL FROM:foo@bar.com"? (NO space after ":")
                    strcpy(mail_from, arg1+5);              // get address after the ":"
                    printf("250 '%s': Sender ok%s", mail_from, CRLF);
                } else {
                    printf("501 Unknown argument '%s'%s", arg1, CRLF);
                    Log("ERROR: unknown MAIL argument '%s'\n", arg1);
                }
            }
        } else if ( ISCMD("RCPT") ) {
            string emsg;
            if ( ISARG1("TO:") ) {
                const char *address = arg2;
                if ( G_conf.CheckErrorAddress(address, emsg) < 0 ) {
                    printf("%s\n", emsg.c_str());       // Failed send error, don't deliver
                } else {
                    strcpy(rcpt_to, address);           // Passed: ok to deliver
                    printf("250 %s... recipient ok%s", rcpt_to, CRLF);
                }
            } else if ( strncasecmp(arg1, "TO:", 3) == 0 ) {   // "RCPT TO:foo@bar.com"? (NO space after ":")
                const char *address = arg1 + 3;         // get address after the ":"
                if ( G_conf.CheckErrorAddress(address, emsg) < 0 ) {
                    printf("%s\n", emsg.c_str());       // Failed: send error, don't deliver
                } else {
                    strcpy(rcpt_to, address);           // Passed: ok to deliver
                    printf("250 %s... recipient ok%s", rcpt_to, CRLF);
                }
            } else {
                printf("501 Unknown RCPT argument '%s'%s", arg1, CRLF);
                Log("ERROR: unknown RCPT argument '%s'\n", arg1);
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
                    Log("ERROR: Premature end of input for DATA command\n");
                    break;              // break fgets() loop
                }
                if ( letter.size() < 3 ) {
                    // Even a one line email has more header lines than this
                    printf("554 Message data was too short%s", CRLF);
                } else {
                    // Handle mail delivery
                    G_conf.DeliverMail(mail_from, rcpt_to, letter);
                    // TODO: Check error return of DeliverMail(), on failure
                    // TODO: log error and either (a) tell remote an error occurred
                    // TODO: and drop msg, or (b) append to dead_letter and let remote
                    // TODO: think it was delivered.
                    //
                    printf("250 Message accepted for delivery%s", CRLF);
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
            Log("ERROR: Remote tried '%s', we don't support it\n", cmd);
        } else {
            printf("500 Unknown command%s", CRLF);
            Log("ERROR: Remote tried '%s', unknown command\n", cmd);
        }

        // All commands end up here, successful or not
        fflush(stdout);
    }

    if ( quit ) {
        // Normal end to session
        return 0;
    } else {
        // If we're here, connection closed with no "QUIT".
        ISLOG("w") { Log("WARNING: Premature end of input for SMTP commands\n"); }
        return 1;               // indicate a possible network error occurred
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
    GetRemoteHostInfo(stdin);

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
            if (++t >= argc) {
                G_debugflags = "a";
            } else {
                if ( strcmp(argv[t], "-") == 0 ) {
                    G_debugflags = "";
                } else {
                    G_debugflags = argv[t];
                }
            }
        } else if (strncmp(argv[t], "-h", 2) == 0) {
            HelpAndExit();
        } else {
            Log("ERROR: unknown argument '%s'\n", argv[t]);
            HelpAndExit();
        }
    }

    // Log remote host connection
    Log("SMTP connection from remote host %s [%s]\n", G_remotehost, G_remoteip);

    // Load config file
    if ( G_conf.Load(conffile) < 0 ) {
        // Tell remote we can't receive SMTP at this time
        printf("221 Cannot receive messages at this time.\n");
        fflush(stdout);
        Log("ERROR: Config file has errors (above): "
            "told remote we can't receive emails at this time\n");
        return 1;       // fail
    }

    // Check if remote allowed to connect to us
    if ( G_conf.CheckRemote(G_remotehost, G_remoteip) < 0 ) {
        printf("221 Cannot receive messages from %s [%s] at this time.\n", G_remotehost, G_remoteip);
        fflush(stdout);
        Log("DENIED: Connection from %s [%s] not in allow_remotehost/ip lists\n", G_remotehost, G_remoteip);
        return 1;
    }

    // Handle the SMTP session with the remote
    return HandleSMTP();
}
