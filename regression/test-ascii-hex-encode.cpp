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

int main() {
    bool allow_crlf = true;
    bool no_crlf    = false;
    const char *test1 = "This is \x03 a test \x80 \x81.";
    const char *test2 = "This is \x03 a test \x80 \x81 of line 0001.\r\nLine 0002\r\n";

    printf("BEFORE: '%s'\n", test1);
    printf(" AFTER: '%s'\n", AsciiHexEncode(test1, no_crlf).c_str());
    printf("\n");

    printf("--- Allow CRLF\n");
    printf("BEFORE:\n%s", test2);
    printf(" AFTER:\n'%s'\n", AsciiHexEncode(test2, allow_crlf).c_str());
    printf("\n");

    printf("--- NO CRLF\n");
    printf("BEFORE:\n%s", test2);
    printf(" AFTER:\n'%s'\n", AsciiHexEncode(test2, no_crlf).c_str());
    printf("\n");

    return 0;
}
