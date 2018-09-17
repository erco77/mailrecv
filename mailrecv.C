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
#include <unistd.h>     // sleep()
#include <stdarg.h>     // vargs
#include <syslog.h>     // syslog()
#include <pcre.h>       // perl regular expressions API (see 'man pcreapi(3)')
#include <sys/socket.h> // getpeername()
#include <netdb.h>      // gethostbyaddr()
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>    // pthread_create() for execution timer
#include <string>
#include <vector>
#include <sstream>

using namespace std;

#define LINE_LEN        4096
#define CRLF            "\r\n"
#define CONFIG_FILE     "/etc/mailrecv.conf"

// Check for log flags
#define ISLOG(s) if (G_debugflags[0] && (G_debugflags[0]=='a'||strpbrk(G_debugflags, s)))

///// GLOBALS /////
const char *G_debugflags = "";         // debug logging flags (see mailrecv.conf for description)
char        G_remotehost[256];         // Remote's hostname
char        G_remoteip[80];            // Remote's IP address

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

// Log a debug message only if logging enabled for 'flags'.
void DebugLog(const char *flags, const char *msg, ...) {
    if ( G_debugflags[0] && (G_debugflags[0]=='a'||strpbrk(G_debugflags,flags))) {
        va_list ap;
        va_start(ap, msg);
        vsyslog(LOG_ERR, msg, ap);
        va_end(ap);
    }
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
    DebugLog("f", "DEBUG: fopen(%s,'a')\n", filename.c_str());
    if ( (fp = fopen(filename.c_str(), "a")) == NULL) {
        Log("ERROR: can't append to %s: %m\n", filename.c_str());   // %m: see syslog(3)
        return -1;  // fail
    }
    fprintf(fp, "From %s\n", mail_from);            // XXX: perhaps unneeded; useful as a message separator
    for ( size_t t=0; t<letter.size(); t++ ) {
        fprintf(fp, "%s\n", letter[t].c_str());
    }
    int ret = fclose(fp);
    DebugLog("f", "DEBUG: fclose() returned %d\n", ret);
    return 1;       // success
}

// Pipe letter to specified shell command
int PipeMailToCommand(const char *mail_from,        // SMTP 'mail from:'
                      const char *rcpt_to,          // SMTP 'rcpt to:'
                      const vector<string>& letter, // email contents, including headers, blank line, body
                      const string& command) {      // unix shell command to write to
    DebugLog("f", "DEBUG: popen(%s,'w')..\n", command.c_str());
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
    DebugLog("f", "DEBUG: pclose() returned %d\n", ret);
    return 1;       // success
}

// Remove surrounding <>'s from email addresses
void RemoveAngleBrackets(char* address) {
    for ( char *p = address; *p; p++ ) {
        if ( *p == '<' ) continue;
        if ( *p == '>' ) break;
        *address++ = *p;
    }
    *address++ = 0;
}

// Class to manage a group of regex patterns
struct AllowGroup {
    string name;                // group name, e.g. "+aservers"
    vector<string> regexes;     // array of regex patterns to match (e.g. "mail[1234].server.com")
};

// mailrecv's configuration file class
//     TODO: This should be moved to a separate file.
//
class Configure {
    int maxsecs;                                    // maximum seconds program should run before stopping
    string domain;                                  // domain our server should know itself as (e.g. "example.com")
                                                    // and accept email messages for.
    string deadletter_file;                         // file to append messages to that have no 'deliver'

    // Limits..
    long limit_smtp_commands;          // limit on # smtp commands per session
    long limit_smtp_unknowncmd;        // limit on # unknown smtp commands per session
    long limit_smtp_failcmds;          // limit on # failed smtp commands
    long limit_connection_secs;        // limit connection time (in secs)
    long limit_smtp_data_size;         // limit on #bytes DATA command can receive
    long limit_smtp_rcpt_to;           // limit on # "RCPT TO:" commands we can receive
    // Error strings for each limit..
    string limit_smtp_commands_emsg;   // limit on # smtp commands per session
    string limit_smtp_unknowncmd_emsg; // limit on # unknown smtp commands per session
    string limit_smtp_failcmds_emsg;   // limit on # failed smtp commands
    string limit_connection_secs_emsg; // limit connection time (in secs)
    string limit_smtp_data_size_emsg;  // limit on #bytes DATA command can receive
    string limit_smtp_rcpt_to_emsg;    // limit on # "RCPT TO:" commands we can receive

    vector<AllowGroup> allowgroups;                 // "allow groups"
    vector<string> deliver_rcpt_to_pipe_allowgroups;// hosts allowed to send to this address (TODO: NOT YET IMPLEMENTED)
    vector<string> deliver_rcpt_to_pipe_address;    // configured rcpt_to addresses to pipe to a shell command (TODO: Should be regex instead?)
    vector<string> deliver_rcpt_to_pipe_command;    // rcpt_to shell command to pipe matching mail to address

    vector<string> deliver_rcpt_to_file_allowgroups;// hosts allowed to send to this address (TODO: NOT YET IMPLEMENTED)
    vector<string> deliver_rcpt_to_file_address;    // rcpt_to file addresses we allow (TODO: Should be regex instead?)
    vector<string> deliver_rcpt_to_file_filename;   // rcpt_to file filename we append letters to

    //NO vector<string> errors_rcpt_to_allowgroups; // we don't need this; always OK to send remote an error ;)
    vector<string> errors_rcpt_to_regex;            // error address to match
    vector<string> errors_rcpt_to_message;          // error message to send remote on match

    vector<string> replace_rcpt_to_regex;           // rcpt_to regex to search for (TODO: NOT YET IMPLEMENTED)
    vector<string> replace_rcpt_to_after;           // rcpt_to regex match replacement string (TODO: NOT YET IMPLEMENTED)

    vector<string> allow_remotehost_regex;          // allowed remotehost regex

public:
    Configure() {
        maxsecs = 300;
        domain  = "example.com";
        deadletter_file = "/dev/null";              // must be set to "something"
        limit_smtp_commands        = 25;
        limit_smtp_commands_emsg   = "500 Too many SMTP commands received in session.";
        limit_smtp_unknowncmd      = 4;
        limit_smtp_unknowncmd_emsg = "500 Too many bad commands.";
        limit_smtp_failcmds        = 4;
        limit_smtp_failcmds_emsg   = "500 Too many failed commands.";
        limit_connection_secs      = 600;
        limit_connection_secs_emsg = "500 Connection timeout.";
        limit_smtp_data_size       = 24000000;
        limit_smtp_data_size_emsg  = "552 Too much mail data.";
        limit_smtp_rcpt_to         = 5;
        limit_smtp_rcpt_to_emsg    = "452 Too many recipients.";    // RFC 2821 4.5.3.1
    }

    // Accessors
    int MaxSecs() const { return maxsecs; }
    const char *Domain() const { return domain.c_str(); }
    const char *DeadLetterFile() const { return deadletter_file.c_str(); }

    // Limit checks
    // Returns:
    //     0 -- if OK.
    //    -1 -- if limit reached, emsg has error to send remote.
    //
    int CheckLimit(long val, string limit_name, string& emsg) {
        if ( limit_name == "smtp_commands" ) {
            if ( val < limit_smtp_commands ) return 0;
            emsg = limit_smtp_commands_emsg;
            return -1; 
        } else if ( limit_name == "smtp_unknowncmd" ) {
            if ( val < limit_smtp_unknowncmd ) return 0;
            emsg = limit_smtp_unknowncmd_emsg;
            return -1; 
        } else if ( limit_name == "smtp_failcmds" ) {
            if ( val < limit_smtp_failcmds ) return 0;
            emsg = limit_smtp_failcmds_emsg;
            return -1; 
        } else if ( limit_name == "connection_secs" ) {
            if ( val < limit_connection_secs ) return 0;
            emsg = limit_connection_secs_emsg;
            return -1; 
        } else if ( limit_name == "smtp_data_size" ) {
            if ( val < limit_smtp_data_size ) return 0;
            emsg = limit_smtp_data_size_emsg;
            return -1; 
        } else if ( limit_name == "smtp_rcpt_to" ) {
            if ( val < limit_smtp_rcpt_to ) return 0;
            emsg = limit_smtp_rcpt_to_emsg;
            return -1; 
        }
        // Shouldn't happen -- if we get here, there's an error in the source code!
        emsg = "500 Program config error";
        return -1;
    }

    // See if 'regex' matches remote hostname/ip 's'
    // Returns:
    //     1 -- match
    //     0 -- no match
    //
    int IsMatch(const char *regex, const char *s) {
        ostringstream logmsg;
        if ( RegexMatch(regex, s) == 1 ) {
            DebugLog("r", "DEBUG: Checking '%s' ~= '%s': Matched!", s, regex);
            return 1;   // match
        }
        DebugLog("r", "DEBUG: Checking '%s' ~= '%s': no", s, regex);
        return 0;
    }

    // See if remote host/ip allowed by specified regex
    // Returns:
    //     1 -- Remote is allowed
    //     0 -- Remote is NOT allowed
    //
    int IsRemoteAllowed(const char *regex) {
        if ( IsMatch(regex, G_remotehost) ) return 1;    // match? allowed
        if ( IsMatch(regex, G_remoteip  ) ) return 1;    // match? allowed
        return 0; // no match? not allowed
    }

    // See if remote allowed by global allow
    // Returns:
    //     1 -- Remote is allowed
    //     0 -- Remote is NOT allowed
    //
    int IsRemoteAllowed() {
        // Nothing configured? Allow anyone
        if ( allow_remotehost_regex.size() == 0 ) {
            DebugLog("w", "NOTE: All remotes allowed by default");
            return 1;
        } else {
            // If one or both configured, must have at least one match
            for ( size_t t=0; t<allow_remotehost_regex.size(); t++ )
                if ( IsRemoteAllowed(allow_remotehost_regex[t].c_str() ) )
                    return 1;   // match? allowed
            return 0;           // no match? not allowed
        }
    }

    // See if remote host is allowed by group.
    // Returns:
    //    1 -- Remote host is allowed by the group
    //    0 -- Remote host is not allowed
    //
    int IsRemoteAllowedByGroup(const string& groupname) {
        if ( groupname == "*" ) return 1;                       // '*' means always allow
        for ( int t=0; t<allowgroups.size(); t++ ) {            // find the group..
            AllowGroup &ag = allowgroups[t];
            if ( ag.name != groupname ) continue;               // no match, keep looking
            for ( int i=0; i<ag.regexes.size(); i++ )           // found group, check remote against all regexes in group
                if ( IsRemoteAllowed(ag.regexes[i].c_str()) )   // check remote hostname/ip
                    return 1;   // match found!
            return 0;           // no match; not allowed
        }
        // Didn't find allowgroup -- admin config error!
        Log("ERROR: group '%s' is referenced but not defined (fix your mailrecv.conf!)",
            groupname.c_str());
        return 0;
    }

    // Add allow group definition
    //    If name exists, add regex to that allowgroup.
    //    If name doesn't exist, add a new AllowGroup with that name+regex
    //
    // Returns:
    //     0 on success
    //    -1 on error (emsg has reason)
    //
    int AddAllowGroup(const char *name, const char *regex, string& emsg) {
        // Make sure regex compiles..
        if ( RegexMatch(regex, "x") == -1 ) {
            emsg = string("'") + string(regex) + "': bad perl regular expression";
            return -1;
        }
        // See if group name exists. If so, append regex, done.
        for ( int i=0; i<allowgroups.size(); i++ ) {
            AllowGroup &agroup = allowgroups[i];
            if ( agroup.name == name ) {
                agroup.regexes.push_back(regex); // append to existing
                return 0;                        // done
            }
        }
        // Not found? Create new..
        AllowGroup agroup;
        agroup.name = name;
        agroup.regexes.push_back(regex);
        allowgroups.push_back(agroup);
        return 0;
    }

    // See if allowgroup is defined
    int IsAllowGroupDefined(const char *groupname) {
        for ( int i=0; i<allowgroups.size(); i++ )
            if ( allowgroups[i].name == groupname )
                return 1; // yep
        return -1;  // nope
    }

    // Load the specified config file
    //     Returns 0 on success, -1 on error (reason printed on stderr)
    //
    int Load(const char *conffile) {
        int err = 0;
        FILE *fp;
        DebugLog("fc", "DEBUG: fopen(%s,'r')..\n", conffile);
        if ( (fp = fopen(conffile, "r")) == NULL) {
            Log("ERROR: can't open %s: %m\n", conffile);
            return -1;
        }
        char line[LINE_LEN+1], arg1[LINE_LEN+1], arg2[LINE_LEN+1], arg3[LINE_LEN+1];
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
            DebugLog("c", "DEBUG: Loading config: %s", line);   // line includes \n

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
            } else if ( sscanf(line, "limit.smtp_commands %s %[^\n]", arg1, arg2) == 2 ) {
                if ( sscanf(arg1, "%ld", &limit_smtp_commands) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): '%s' not an integer", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                limit_smtp_commands_emsg = arg2;
            } else if ( sscanf(line, "limit.smtp_unknowncmd %s %[^\n]", arg1, arg2) == 2 ) {
                if ( sscanf(arg1, "%ld", &limit_smtp_unknowncmd) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): '%s' not an integer", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                limit_smtp_unknowncmd_emsg = arg2;
            } else if ( sscanf(line, "limit.smtp_failcmds %s %[^\n]", arg1, arg2) == 2 ) {
                if ( sscanf(arg1, "%ld", &limit_smtp_failcmds) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): '%s' not an integer", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                limit_smtp_failcmds_emsg = arg2;
            } else if ( sscanf(line, "limit.connection_secs %s %[^\n]", arg1, arg2) == 2 ) {
                if ( sscanf(arg1, "%ld", &limit_connection_secs) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): '%s' not an integer", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                limit_connection_secs_emsg = arg2;
            } else if ( sscanf(line, "limit.smtp_data_size %s %[^\n]", arg1, arg2) == 2 ) {
                if ( sscanf(arg1, "%ld", &limit_smtp_data_size) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): '%s' not an integer", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                limit_smtp_data_size_emsg = arg2;
            } else if ( sscanf(line, "limit.smtp_rcpt_to %s %[^\n]", arg1, arg2) == 2 ) {
                if ( sscanf(arg1, "%ld", &limit_smtp_rcpt_to) != 1 ) {
                    Log("ERROR: '%s' (LINE %d): '%s' not an integer", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                limit_smtp_rcpt_to_emsg = arg2;
            } else if ( sscanf(line, "deadletter_file %s", arg1) == 1 ) {
                deadletter_file = arg1;
            } else if ( sscanf(line, "allowgroup %s %s", arg1, arg2) == 2 ) {
                string emsg;
                if ( AddAllowGroup(arg1, arg2, emsg) < 0 ) {
                    Log("ERROR: '%s' (LINE %d): %s", conffile, linenum, emsg.c_str());
                    err = -1;
                    continue;
                }
            } else if ( sscanf(line, "deliver rcpt_to %s append %s", arg1, arg2) == 2 ) {
                deliver_rcpt_to_file_allowgroups.push_back("*");
                deliver_rcpt_to_file_address.push_back(arg1);
                deliver_rcpt_to_file_filename.push_back(arg2);
            } else if ( sscanf(line, "deliver allowgroup %s rcpt_to %s append %s", arg1, arg2, arg3) == 3 ) {
                if ( IsAllowGroupDefined(arg1) < 0 ) {
                    Log("ERROR: '%s' (LINE %d): allowgroup '%s' is undefined", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                deliver_rcpt_to_file_allowgroups.push_back(arg1);
                deliver_rcpt_to_file_address.push_back(arg2);
                deliver_rcpt_to_file_filename.push_back(arg3);
            } else if ( sscanf(line, "deliver rcpt_to %s pipe %[^\n]", arg1, arg2) == 2 ) {
                deliver_rcpt_to_pipe_allowgroups.push_back("*");
                deliver_rcpt_to_pipe_address.push_back(arg1);
                deliver_rcpt_to_pipe_command.push_back(arg2);
            } else if ( sscanf(line, "deliver allowgroup %s rcpt_to %s pipe %[^\n]", arg1, arg2, arg3) == 3 ) {
                if ( IsAllowGroupDefined(arg1) < 0 ) {
                    Log("ERROR: '%s' (LINE %d): allowgroup '%s' is undefined", conffile, linenum, arg1);
                    err = -1;
                    continue;
                }
                deliver_rcpt_to_pipe_allowgroups.push_back(arg1);
                deliver_rcpt_to_pipe_address.push_back(arg2);
                deliver_rcpt_to_pipe_command.push_back(arg3);
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
            } else {
                Log("ERROR: '%s' (LINE %d): ignoring unknown config command: %s\n", conffile, linenum, line);
                err = -1;
            }
        }
        int ret = fclose(fp);
        DebugLog("f", "DEBUG: fclose() returned %d\n", ret);

        // Show everything we actually loaded..
        ISLOG("c") {
            Log("DEBUG: --- Config file:\n");
            Log("DEBUG:    maxsecs: %d\n", MaxSecs());
            Log("DEBUG:    domain: '%s'\n", Domain());
            Log("DEBUG:    deadletter_file: '%s'\n", DeadLetterFile());
            Log("DEBUG:    limit_smtp_commands    max=%ld msg=%s\n", limit_smtp_commands,   limit_smtp_commands_emsg.c_str());
            Log("DEBUG:    limit_smtp_unknowncmd  max=%ld msg=%s\n", limit_smtp_unknowncmd, limit_smtp_unknowncmd_emsg.c_str());
            Log("DEBUG:    limit_smtp_failcmds    max=%ld msg=%s\n", limit_smtp_failcmds,   limit_smtp_failcmds_emsg.c_str());
            Log("DEBUG:    limit_connection_secs  max=%ld msg=%s\n", limit_connection_secs, limit_connection_secs_emsg.c_str());
            Log("DEBUG:    limit_smtp_data_size   max=%ld msg=%s\n", limit_smtp_data_size,  limit_smtp_data_size_emsg.c_str());
            Log("DEBUG:    limit_smtp_rcpt_to     max=%ld msg=%s\n", limit_smtp_rcpt_to,    limit_smtp_rcpt_to_emsg.c_str());

            size_t t;
            // Allowgroups..
            for ( t=0; t<allowgroups.size(); t++ ) {
                ostringstream os;
                AllowGroup &ag = allowgroups[t];
                os << "DEBUG:    allowgroup '" << ag.name << "': ";
                for ( int i=0; i<ag.regexes.size(); i++ )
                    { os << (i>0?", ":"") << "'" << ag.regexes[i] << "'"; }
                Log("%s\n", os.str().c_str());
            }
            // deliver to file..
            for ( t=0; t<deliver_rcpt_to_file_address.size(); t++ ) {
                Log("DEBUG:    deliver rcpt_to: allowgroup='%s' address='%s', which writes to file='%s'\n",
                    deliver_rcpt_to_file_allowgroups[t].c_str(),
                    deliver_rcpt_to_file_address[t].c_str(),
                    deliver_rcpt_to_file_filename[t].c_str());
            }
            // deliver to pipe..
            for ( t=0; t<deliver_rcpt_to_pipe_address.size(); t++ ) {
                Log("DEBUG:    deliver rcpt_to: allowgroup='%s' address='%s', which pipes to cmd='%s'\n",
                    deliver_rcpt_to_pipe_allowgroups[t].c_str(),
                    deliver_rcpt_to_pipe_address[t].c_str(),
                    deliver_rcpt_to_pipe_command[t].c_str());
            }
            // global allow remotes..
            for ( t=0; t<allow_remotehost_regex.size(); t++ ) {
                Log("DEBUG:    allow remote hostnames that match perl regex '%s'\n", allow_remotehost_regex[t].c_str());
            }
            Log("DEBUG: ---\n");
        }
        return err;     // let caller decide what to do
    }

    // Deliver mail to recipient.
    //     If there's no configured recipient, write to deadletter file.
    //
    // Returns:
    //     0 on success
    //    -1 on error (reason sent to server on stdout).
    //
    int DeliverMail(const char* mail_from,          // SMTP 'mail from:'
                    const char *rcpt_to,            // SMTP 'rcpt to:'
                    const vector<string>& letter) { // email contents, including headers, blank line, body
        size_t t;

        // Check for 'append to file' recipient..
        for ( t=0; t<deliver_rcpt_to_file_address.size(); t++ ) {
            const string& groupname = deliver_rcpt_to_file_allowgroups[t];
            if ( strcmp(rcpt_to, deliver_rcpt_to_file_address[t].c_str()) == 0 ) {
                if ( IsRemoteAllowedByGroup(groupname) ) {
                    // TODO: Check error return of AppendMailToFile(), fall thru to deadletter?
                    AppendMailToFile(mail_from, rcpt_to, letter, deliver_rcpt_to_file_filename[t]);
                    Log("Mail from=%s to=%s [append to '%s']", 
                         mail_from, rcpt_to, deliver_rcpt_to_file_filename[t].c_str());
                    return 0;   // delivered
                }
                Log("'%s': remote server %s [%s] not allowed to send to this address",
                    rcpt_to, G_remotehost, G_remoteip);
                printf("550 Server not allowed to send to this address%s", CRLF);
                return -1;
            }
        }

        // Check for 'pipe to command' recipient..
        for ( t=0; t<deliver_rcpt_to_pipe_address.size(); t++ ) {
            const string& groupname = deliver_rcpt_to_pipe_allowgroups[t];
            if ( strcmp(rcpt_to, deliver_rcpt_to_pipe_address[t].c_str()) == 0 ) {
                // Check allowgroup ('*' matches everything)
                if ( IsRemoteAllowedByGroup(groupname) ) {
                    // TODO: Check error return of PipeMailToCommand(), fall thru to deadletter?
                    PipeMailToCommand(mail_from, rcpt_to, letter, deliver_rcpt_to_pipe_command[t]);
                    Log("Mail from=%s to=%s [pipe to '%s']", 
                         mail_from, rcpt_to, deliver_rcpt_to_pipe_command[t].c_str());
                    return 0;   // delivered
                }
                Log("'%s': remote server %s [%s] not allowed to send to this address",
                    rcpt_to, G_remotehost, G_remoteip);
                printf("550 Server not allowed to send to this address%s",CRLF);
                return -1;
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

        Log("Mail from=%s to=%s [append to deadletter file '%s']",
            mail_from, rcpt_to, deadletter_file.c_str());
        return 0;   // delivered
    }

    // See if address is an error address, or if server not allowed
    //
    // Returns:
    //    0 -- OK to deliver -- not an error address
    //   -1 -- Reject delivery -- send error message in 'emsg' to remote
    //
    int CheckErrorAddress(const char *address, string& emsg) {
        int t;
        // First, ignore address configured for regular delivery..
        // ..rcpt_to file?
        for ( int t=0; t<deliver_rcpt_to_file_address.size(); t++ )
            if ( strcmp(address, deliver_rcpt_to_file_address[t].c_str()) == 0 )
                if ( IsRemoteAllowedByGroup(deliver_rcpt_to_file_allowgroups[t].c_str()) )
                    { return 0; }     // OK to deliver
                else
                    { emsg = "550 Remote not configured to deliver for this address"; return -1; }
        // ..rcpt_to pipe?
        for ( int t=0; t<deliver_rcpt_to_pipe_address.size(); t++ )
            if ( strcmp(address, deliver_rcpt_to_pipe_address[t].c_str()) == 0 )
                if ( IsRemoteAllowedByGroup(deliver_rcpt_to_pipe_allowgroups[t].c_str()) )
                    { return 0; }     // OK to deliver
                else
                    { emsg = "550 Remote not configured to deliver for this address"; return -1; }

        // Check error addresses last
        for ( int i=0; i<errors_rcpt_to_regex.size(); i++ )
            if ( RegexMatch(errors_rcpt_to_regex[i].c_str(), address) == 1 ) // reject address configured?
                { emsg = errors_rcpt_to_message[i]; return -1; }             // return error msg
        return 0;           // OK to deliver
    }

    // CHILD THREAD FOR EXECUTION TIMER
    static void *ChildExecutionTimer(void *data) {
        long secs = long(data);
        sleep(secs);
        // Timer expired? Send message to remote and exit immediately
        const char *emsg = "500 Connection timeout (forcing close)\n";
        write(1, emsg, strlen(emsg));
        exit(0);
    }

    // Start execution timer thread
    void StartExecutionTimer() {
        static pthread_t dataready_tid = 0;
        if ( dataready_tid != 0 ) return;   // only run once
        pthread_create(&dataready_tid,
                       NULL,
                       ChildExecutionTimer,
                       (void*)limit_connection_secs);
    }
};

Configure G_conf;

// TODO: Put a timer on this entire program.
//       Abort if we're running longer than G_config.MaxSecs()

// Minimum commands we must support:
//      HELO MAIL RCPT DATA RSET NOOP QUIT VRFY

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
//    -1 general failure (premature end of input, limit reached)
//       emsg has error to send remote.
//
int ReadLetter(FILE *fp,                    // [in] connection to remote
               vector<string>& letter,      // [in] array for saved letter
               string &emsg) {              // [out] error to send remote on return -1
    char s[LINE_LEN+1];
    long bytecount = 0;
    while (fgets(s, LINE_LEN, stdin)) {
        StripCRLF(s);
        DebugLog("l", "DEBUG: Letter: '%s'\n", s);
        // End of letter? done
        if ( strcmp(s, ".") == 0 ) return 0;
        // Check limit
        bytecount += strlen(s);
        if ( G_conf.CheckLimit(bytecount, "smtp_data_size", emsg) < 0 ) {
            Log("SMTP DATA limit reached (%d)", bytecount);
            return -1;
        }
        // Otherwise append lines with CRLF removed to letter
        letter.push_back(s);
    }
    // Unexpected end of input
    Log("Premature end of input while receiving email from remote");
    emsg = "550 End of input during DATA command";
    return -1;                  // premature end of input
}

// Handle a complete SMTP session with the remote on stdin/stdout
// Returns main() exit code:
//     0 -- success
//     1 -- failure
//
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
    printf("220 %s SMTP (RFC 822)%s", our_domain, CRLF);    // TODO -- allow custom identity to be specified
    fflush(stdout);

    // Limit counters
    int smtp_commands_count = 0;
    int smtp_unknowncmd_count = 0;
    int smtp_fail_commands_count = 0;
    int smtp_rcpt_to_count = 0;
    // CheckLimit() returned error msg, if any
    string emsg;
    int quit = 0;
    // READ ALL SMTP COMMANDS FROM REMOTE UNTIL "QUIT" OR EOF
    while (!quit && fgets(line, LINE_LEN-1, stdin)) {
        line[LINE_LEN] = 0;        // extra caution
        StripCRLF(line);

        DebugLog("s", "DEBUG: SMTP cmd: %s\n", line);
        DebugLog("s", "DEBUG: SMTP cmd: cmdcount=%d, unknowncount=%d, failcount=%d\n",
                         smtp_commands_count, smtp_unknowncmd_count, smtp_fail_commands_count);

        // LIMIT CHECK: # SMTP COMMANDS
        //    NOTE: Empty lines count towards the command counter..
        //
        if ( G_conf.CheckLimit(++smtp_commands_count, "smtp_commands", emsg) < 0 ) {
            Log("SMTP #commands limit reached (%d)", smtp_commands_count);
            printf("%s\n", emsg.c_str());
            break;      // end session
        }

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
                    ++smtp_fail_commands_count;
                    printf("501 Unknown argument '%s'%s", arg1, CRLF);
                    Log("ERROR: unknown MAIL argument '%s'\n", arg1);
                }
            }
        } else if ( ISCMD("RCPT") ) {
            char *address;
            if ( ISARG1("TO:") ) {
                address = arg2;
                goto rcpt_to;
            } else if ( strncasecmp(arg1, "TO:", 3) == 0 ) {   // "RCPT TO:foo@bar.com"? (NO space after ":")
                address = arg1 + 3;                            // get address after the ":"
rcpt_to:
                RemoveAngleBrackets(address);                  // "<foo@bar.com>" -> "foo@bar.com"

                // LIMIT CHECK: # RCPT TO COMMANDS
                if ( G_conf.CheckLimit(++smtp_rcpt_to_count, "smtp_rcpt_to", emsg) < 0 ) {
                    Log("SMTP Number of 'rcpt to' recipients limit reached (%d)", smtp_rcpt_to_count);
                    printf("%s\n", emsg.c_str());
                    break;  // end session
                }
                if ( G_conf.CheckErrorAddress(address, emsg) < 0 ) {
                    ++smtp_fail_commands_count;
                    printf("%s\n", emsg.c_str());              // Failed: send error, don't deliver
                } else {
                    strcpy(rcpt_to, address);                  // Passed: ok to deliver
                    printf("250 %s... recipient ok%s", rcpt_to, CRLF);
                }
            } else {
                ++smtp_fail_commands_count;
                printf("501 Unknown RCPT argument '%s'%s", arg1, CRLF);
                Log("ERROR: unknown RCPT argument '%s'\n", arg1);
            }
        } else if ( ISCMD("DATA") ) {
            if ( rcpt_to[0] == 0 ) {
                ++smtp_fail_commands_count;
                printf("503 Bad sequence of commands -- missing RCPT TO%s", CRLF);
            } else if ( mail_from[0] == 0 ) {
                ++smtp_fail_commands_count;
                printf("503 Bad sequence of commands -- missing MAIL FROM%s", CRLF);
            } else {
                printf("354 Start mail input; end with <CRLF>.<CRLF>%s", CRLF);
                fflush(stdout);
                if ( ReadLetter(stdin, letter, emsg) == -1 ) {
                    ++smtp_fail_commands_count;
                    printf("%s\n", emsg.c_str());
                    break;              // break fgets() loop
                }
                if ( letter.size() < 3 ) {
                    // Even a one line email has more header lines than this
                    printf("554 Message data was too short%s", CRLF);
                    ++smtp_fail_commands_count;
                } else {
                    // Handle mail delivery
                    if ( G_conf.DeliverMail(mail_from, rcpt_to, letter) == 0 ) {
                        printf("250 Message accepted for delivery%s", CRLF);
                    } else {
                        ++smtp_fail_commands_count;
                    }
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
            ++smtp_fail_commands_count;
            printf("502 Command not implemented or disabled%s", CRLF);
            Log("ERROR: Remote tried '%s', we don't support it\n", cmd);
        } else {
            ++smtp_fail_commands_count;
            printf("500 Unknown command%s", CRLF);
            Log("ERROR: Remote tried '%s', unknown command\n", cmd);

            // LIMIT CHECK: # UNKNOWN SMTP COMMANDS
            if ( G_conf.CheckLimit(++smtp_unknowncmd_count, "smtp_unknowncmd", emsg) < 0 ) {
                Log("SMTP #unknown commands limit reached (%d)", smtp_unknowncmd_count);
                printf("%s\n", emsg.c_str());
                break;  // end session
            }
        }

        // All commands end up here, successful or not
        fflush(stdout);

        // LIMIT CHECK: # UNKNOWN SMTP COMMANDS
        if ( G_conf.CheckLimit(smtp_fail_commands_count, "smtp_failcmds", emsg) < 0 ) {
            Log("SMTP #failed commands limit reached (%d)", smtp_fail_commands_count);
            printf("%s\n", emsg.c_str());
            break;  // end session
        }
    }

    // Flush any closing responses to remote
    fflush(stdout);

    if ( quit ) {
        // Normal end to session
        return 0;
    } else {
        // If we're here, connection closed with no "QUIT".
        DebugLog("w", "WARNING: Premature end of input for SMTP commands\n");
        return 1;               // indicate a possible network error occurred
    }
}

// Show help and exit
void HelpAndExit() {
    fputs("mailrecv - a simple SMTP xinetd daemon (V " VERSION ")\n"
          "        See LICENSE file packaged with newsd for license/copyright info.\n"
          "\n"
          "Options\n"
          "    -c config-file     -- Use 'config-file' instead of default (" CONFIG_FILE ")\n"
          "    -d <logflags|->    -- Enable debugging logging flags.\n"
          "\n"
          "Log Flags\n"
          "    Can be one or more of these single letter flags:\n"
          "        - -- disables all debug logging\n"
          "        a -- all (enables all optional flags)\n"
          "        c -- show config file loading process\n"
          "        s -- show SMTP commands remote sent us\n"
          "        l -- show email contents as it's received (SMTP 'DATA' command's input)\n"
          "        r -- show regex pattern match checks\n"
          "        f -- show all open/close operations on files/pipes\n"
          "        w -- log non-essential warnings\n"
          "\n"
          "Example:\n"
          "    mailrecv -d sr -c mailrecv-test.conf\n"
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
        printf("221 Cannot receive messages at this time.%s", CRLF);
        fflush(stdout);
        Log("ERROR: '%s' has errors (above): told remote 'Cannot receive email at this time'\n", conffile);
        return 1;       // fail
    }

    // Check if remote allowed to connect to us
    if ( ! G_conf.IsRemoteAllowed() ) {
        printf("221 Cannot receive messages from %s [%s] at this time.%s", G_remotehost, G_remoteip, CRLF);
        fflush(stdout);
        Log("DENIED: Connection from %s [%s] not in allow_remotehost/ip lists\n", G_remotehost, G_remoteip);
        return 1;
    }

    // Start execution timer
    G_conf.StartExecutionTimer();

    // Handle the SMTP session with the remote
    return HandleSMTP();
}
