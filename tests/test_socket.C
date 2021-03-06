
#include <iostream>
#include <cyberprobe/network/socket.h>
#include <assert.h>

using namespace cyberprobe;

int main(int argc, char** argv)
{

    tcpip::ip4_address a1("1.2.3.4");

    std::string out;
    a1.to_string(out);

    assert(out == "1.2.3.4");

    tcpip::ip4_address a2 = a1 & 24;
    a2.to_string(out);
    assert(out == "1.2.3.0");

    tcpip::ip4_address a3("249.89.32.127");

    a2 = a3 & 8;
    a2.to_string(out);
    assert(out == "249.0.0.0");

    a2 = a3 & 11;
    a2.to_string(out);
    assert(out == "249.64.0.0");

    a2 = a3 & 20;
    a2.to_string(out);
    assert(out == "249.89.32.0");

    tcpip::ip6_address a4("aabb:bbcc:ddcc:86dd:a3ee:dfdf:6767:9191");
    a4.to_string(out);
    assert(out == "aabb:bbcc:ddcc:86dd:a3ee:dfdf:6767:9191");

    tcpip::ip6_address a5 = a4 & 32;
    a5.to_string(out);
    assert(out == "aabb:bbcc::");

    a5 = a4 & 64;
    a5.to_string(out);
    assert(out == "aabb:bbcc:ddcc:86dd::");

    a5 = a4 & 96;
    a5.to_string(out);
    assert(out == "aabb:bbcc:ddcc:86dd:a3ee:dfdf::");

    a5 = a4 & 56;
    a5.to_string(out);
    assert(out == "aabb:bbcc:ddcc:8600::");

    tcpip::ip6_address a6("aabb:bbcc:ddcc:86dd:a3ee::9191");
    a6.to_string(out);
    assert(out == "aabb:bbcc:ddcc:86dd:a3ee::9191");

}

