// vim: autoindent tabstop=8 shiftwidth=4 expandtab softtabstop=4

#include <stdio.h>
#include <ctype.h>      // toupper()
#include <time.h>       // time(), localtime()..
#include <string.h>     // strchr()
#include <errno.h>      // errno
#include <stdlib.h>     // exit()
#include <unistd.h>     // sleep(), gethostname()
#include <stdarg.h>     // vargs
#include <syslog.h>     // syslog()
#include <pcre.h>       // perl regex API (see 'man pcreapi(3)')
#include <sys/socket.h> // getpeername()
#include <netdb.h>      // gethostbyaddr(), NI_MAXHOST..
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/file.h>   // flock()
#include <pthread.h>    // pthread_create() for execution timer

// STL
#include <string>
#include <cctype>       // std::toupper()
#include <vector>
#include <sstream>
#include <iomanip>

using namespace std;

char G_localhost[256];                   // local hostname
char G_remotehost[256] = "some_remote";  // Remote's hostname
char G_remoteip[NI_MAXHOST] = "1.2.3.4"; // Remote's IP address

// Return date as e.g. 'Fri, 24 Apr 2026 16:28:03 -0700 (PDT)'
//                      |    |  |   |    |  |  |   |      |
//                      %a   %d %b  %G   %H %M %S  %z     %Z
string GetRFCDate() {
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    ostringstream os; os << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S %z (%Z)");
    string s = os.str();
    s[0] = std::toupper(static_cast<unsigned char>(s[0]));
    return s;
}

// Return date string in current locale format, e.g. 'Thu May  7 08:54:15 PDT 2026'
string GetLogDate() {
    std::time_t t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    ostringstream os; os << std::put_time(&tm, "%c");    // POSIX locale, usually: "%a %b %e %H:%M:%S %Y"
    return os.str();
}

// Isolate email address in 's'
//     "Foo Bar <foo@bar.com>" -> "foo@bar.com"
//     "<foo@bar.com>" -> "foo@bar.com"
//     "foo@bar.com" -> "foo@bar.com"
//
void IsolateAddress(string& s) {
    size_t i;
    // Skip leading white
    while (s[0] == ' ' || s[0] == '\t') s.erase(0,1);
    while ((i = s.find('<')) != string::npos) {  // any '<'s? skip possible "Full Name"
        s.erase(0, i+1);                         // erase up to and including '<'
    }
    if ((i = s.find('>')) != string::npos) {     // find closing '>'?
        s.erase(i);                              // erase from index to eos
    }
    return;
}

// Modify 'letter', inserting Return-Path:/Received: headers (RFC 821, 4.1.1 'DATA')
void AddReturnPath(vector<string>& letter, const char* in_mail_from) {
    ostringstream return_path;
    ostringstream received;
    string mail_from = in_mail_from; IsolateAddress(mail_from);
    return_path << "Return-Path: <" << mail_from << ">";
    received    << "Received: from " << G_remotehost << " by " << G_localhost
                << " via mailrecv (V " << VERSION << ") ; " << GetRFCDate();
    letter.insert(letter.begin()+0, return_path.str());
    letter.insert(letter.begin()+1, received.str());
}

// Show letter on stdout
void ShowLetter(const char *msg, vector<string>& letter) {
    printf("%s\n", msg);
    for (size_t t=0; t<letter.size(); t++) {
        printf("%s\n", letter[t].c_str());
    }
}

// Return localhost in 'hostname', not to exceed 'size'
//     Errors sent to Log()
//
void GetLocalHostname(char *hostname, int len) {
    if (gethostname(hostname, len) < 0) {       // unistd
        printf("gethostname() failed: can't determine localhost name\n");
        strcpy(hostname, "LOCALHOST");
    }
    hostname[len-1] = 0;        // POSIX.1 re: truncation
}

int main() {

    GetLocalHostname(G_localhost, sizeof(G_localhost));

    vector<string> letter;
    // Test letter
    letter.push_back("From: joe@foo.com");
    letter.push_back("To: fred@bar.com");
    letter.push_back("Subject: something");
    letter.push_back("");
    letter.push_back("Line one");
    letter.push_back("Line two");
    ShowLetter("--- BEFORE:", letter);
    printf("<EOL>\n\n");

    // Add return path headers
    AddReturnPath(letter, "JOE@FOO.COM");
    ShowLetter("--- AFTER:", letter);
    printf("<EOL>\n\n");

    // Show log date
    printf("GetLogDate(): '%s'\n", GetLogDate().c_str());
    return 0;
}
