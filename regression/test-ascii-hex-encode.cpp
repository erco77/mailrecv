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
#include <vector>
#include <sstream>
#include <iomanip>

using namespace std;

#define GREEN  (isatty(1)?"\033[32m":"")
#define NORMAL (isatty(1)?"\033[0m":"")

// Return ASCII only version of string 's', with binary encoded as hex <0x##>
//     NOTE: in the following, "ASCII" is defined as per RFC 822 4.1.2.
//
string AsciiHexEncode(const char *s, bool allow_crlf=false) {
    ostringstream out;
    for (; *s; s++) {
        if (*s >= 0x20 && *s <= 0x7e) {
            out << *s;
        } else if (allow_crlf && (*s == '\r' || *s == '\n')) {
            out << *s;
        } else {
            // Show binary data as <0x##>
            out << "<0x" << std::hex << std::setw(2) 
                << std::setfill('0') << (((unsigned int)*s) & 0xff) << std::dec << ">";
        }
    }
    return out.str();
}

// Escape "From .." with ">From .."
void EscapeFrom(char *s) {
    string out = string(">") + string(s);
    strcpy(s, out.c_str());
}

void TestHexEncode(string before, string expect, bool allow_crlf) {
    string after = AsciiHexEncode(before.c_str(), allow_crlf);
    printf("BEFORE: '%s'\n", before.c_str());
    printf(" AFTER: '%s'\n", after.c_str());
    if (after != expect) {
        printf("*** FAIL *** expected '%s'\n", expect.c_str());
        printf("                  got '%s'\n", after.c_str());
        exit(1);
    }
}

int main() {
    // Test Hex Encode
    {
        bool allow_crlf = true;
        bool no_crlf    = false;

        const char *test1        = "This is \x03 a test \x80 \x81.";
        const char *test1_expect = "This is <0x03> a test <0x80> <0x81>.";

        const char *test2                   = "This is \x03 a test \x80 \x81 of line 0001.\r\nLine 0002\r\n";
        const char *test2_expect_allow_crlf = "This is <0x03> a test <0x80> <0x81> of line 0001.\r\nLine 0002\r\n";
        const char *test2_expect_no_crlf    = "This is <0x03> a test <0x80> <0x81> of line 0001.<0x0d><0x0a>Line 0002<0x0d><0x0a>";

        TestHexEncode(test1, test1_expect, no_crlf);
        printf("--- Allow CRLF\n");
        TestHexEncode(test2, test2_expect_allow_crlf, allow_crlf);
        printf("--- NO CRLF\n");
        TestHexEncode(test2, test2_expect_no_crlf, no_crlf);
    }

    // Test "From" escape
    {
        char s[80]; strcpy(s, "From <someone@foo.com>");
        printf("Test 'From' escaping\n");
        printf("BEFORE: %s\n", s);
        EscapeFrom(s);
        printf(" AFTER: %s\n", s);
        if (strcmp(s, ">From <someone@foo.com>") != 0) {
            printf("*** FAIL ***\n");
            exit(1);
        }
    }
    printf("%s*** PASS ***%s\n", GREEN, NORMAL);
    return 0;
}
