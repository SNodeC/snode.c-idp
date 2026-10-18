#include "auth/HttpExchange.h"
#include "core/SNodeC.h"

#include <cstdlib>
#include <iostream>

int main(int argc, char** argv) {
    core::SNodeC::init(argc, argv);
    int status = 0;
    int completions = 0;
    snodec::auth::httpExchange(std::getenv("TEST_URL"), "GET", "", {}, [&](snodec::auth::HttpResult response) {
        status = response.status;
        ++completions;
        core::SNodeC::stop();
    });
    core::SNodeC::start();
    std::cout << "RESULT " << status << " " << completions << '\n';
    return completions == 1 ? 0 : 1;
}
