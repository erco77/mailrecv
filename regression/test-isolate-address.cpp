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
#include <iostream>     // std::cin
#include <iomanip>

using namespace std;

#define RED    (isatty(1)?"\033[31m":"")
#define GREEN  (isatty(1)?"\033[32m":"")
#define NORMAL (isatty(1)?"\033[0m":"")

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

void Test(string s, const string expect) {
    printf("BEFORE: '%s'\n", s.c_str());
    IsolateAddress(s);
    printf(" AFTER: '%s'\n\n", s.c_str());
    if (s != expect) {
        printf("%s", RED);
        printf("*** FAIL *** expected '%s'\n", expect.c_str());
        printf("                  got '%s'\n", s.c_str());
        printf("%s", NORMAL);
        exit(1);
    }
}

int main() {
    Test("a@b",               "a@b");
    Test("  <a@bcd>",         "a@bcd");
    Test("    ",              "");
    Test("<foo@bar>",         "foo@bar");
    Test("   <<<foo@bar>",    "foo@bar");
    Test("<<<foo@bar>",       "foo@bar");
    Test("<foo@bar>>>",       "foo@bar");
    Test("Foo Bar <foo@bar>", "foo@bar");
    Test("<f@b",              "f@b");
    Test("f@b>",              "f@b");
    Test("<>",                "");
    Test("aaaaaaaaa",         "aaaaaaaaa");
    Test("  <>",              "");
    printf("%s*** PASSED ***%s\n", GREEN, NORMAL);
/***
    while ( std::getline(std::cin, s)) {
        Test(s):
        printf("BEFORE: '%s'\n", s.c_str());
        IsolateAddress(s);
        printf(" AFTER: '%s'\n", s.c_str());
    }
***/
    return 0;
}
