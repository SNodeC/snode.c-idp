cmake_minimum_required(VERSION 3.18)
project(minimal-mfa-app LANGUAGES CXX)
if(NOT TARGET auth-client)
    find_package(snodec-auth 2 REQUIRED)
endif()
find_package(snodec REQUIRED COMPONENTS http-server-express-tls-in)
add_executable(minimal-mfa-app main.cpp)
target_link_libraries(
    minimal-mfa-app PRIVATE snodec::http-server-express-tls-in
)
target_compile_features(minimal-mfa-app PRIVATE cxx_std_20)
if(TARGET auth-client)
    target_link_libraries(minimal-mfa-app PRIVATE auth-client)
else()
    target_link_libraries(minimal-mfa-app PRIVATE snodec-auth::auth-client)
endif()
include(GNUInstallDirs)
install(TARGETS minimal-mfa-app RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                                        COMPONENT example
)
install(
    DIRECTORY public pages
    DESTINATION ${CMAKE_INSTALL_DATADIR}/snodec-idp/example
    COMPONENT example
)
