cmake_minimum_required(VERSION 3.18)

include(cmake/Version.cmake)

project(
    snodec-auth-idp
    DESCRIPTION
        "SNode.C Identity Provider: OAuth2 + PKCE + TOTP MFA + JWT RS256"
    VERSION ${RELEASE_VERSION}
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Compiler flags (match SNode.C upstream settings) ─────────────────────────
add_compile_options(
    -Wall
    -Wextra
    -Wconversion
    -Wuninitialized
    -Wunreachable-code
    -Wfloat-equal
    -fexec-charset=UTF-8
    -Wno-shadow
    -Wno-psabi
)

if(NOT APPLE)
    add_link_options(LINKER:--as-needed)
endif()

include(GNUInstallDirs)

# ─────────────────────────────────────────────────────────────────────────────
# Standalone build against an INSTALLED vanilla upstream SNode.C.
#
# This project no longer requires the SSO/MFA fork of snode.c. It consumes the
# upstream framework via find_package(snodec) and carries its own previously
# fork-only pieces locally: - the SQLite wrapper  (db-sqlite,
# src/database/sqlite/) - the Nayuki QR lib   (snodec::nayuki-qrcodegen,
# src/supplement/qrcodegen/)
#
# Build:  cmake -S . -B build -DCMAKE_PREFIX_PATH=<snodec-install-prefix>
# ─────────────────────────────────────────────────────────────────────────────

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(format)

# Build ONLY the relying-party client subset (auth-client + the consumable
# snodec-auth package). Skips the IdP server executable, the SQLite wrapper, the
# QR generator and the TOTP/server-signing code, so a relying party (e.g. the
# mqttsuite broker) can verify IdP-issued JWTs without pulling in the full
# Identity Provider. Default OFF → the IdP builds exactly as before.
option(AUTH_CLIENT_ONLY "Build only the relying-party auth-client" OFF)

# Upstream SNode.C framework (installed). KEEP find_package(snodec ...
# http-server-express ...). This is how the standalone IdP pulls in the
# framework. Each component must be requested explicitly to load its imported
# target: http-server-express-legacy-in provides Express, transport, core,
# utilities and the logger target through its dependency graph.
find_package(
    snodec REQUIRED COMPONENTS http-server-express-legacy-in http-client
                               net-in-stream-tls
)

find_package(OpenSSL 3 REQUIRED)
find_package(nlohmann_json 3.11 REQUIRED)

if(NOT AUTH_CLIENT_ONLY)
    find_package(SQLite3 REQUIRED)

    # ── Vendored: Project Nayuki QR generator (MIT, src/supplement/qrcodegen/)
    # ──── Local replacement for the fork's snodec::nayuki-qrcodegen. Keeping
    # the same target + alias name means the auth library's link list is
    # unchanged.
    add_library(nayuki-qrcodegen STATIC src/supplement/qrcodegen/qrcodegen.cpp)
    add_library(snodec::nayuki-qrcodegen ALIAS nayuki-qrcodegen)
    target_include_directories(
        nayuki-qrcodegen
        PUBLIC
            "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/supplement/qrcodegen>"
    )
    target_compile_features(nayuki-qrcodegen PUBLIC cxx_std_17)
    set_property(TARGET nayuki-qrcodegen PROPERTY POSITION_INDEPENDENT_CODE ON)

    # ── Vendored: SQLite wrapper (db-sqlite, src/database/sqlite/)
    # ──────────────── Local replacement for the fork's db-sqlite.
    # SQLite3::SQLite3 comes from CMake's canonical find_package(SQLite3); no
    # pkg-config aliasing needed.
    add_library(db-sqlite STATIC src/database/sqlite/SqliteDatabase.cpp)
    # Link via FindSQLite3's result variables rather than the SQLite3::SQLite3
    # imported target: find_package(snodec) transitively resolves SQLite3 too,
    # which can leave the imported target out of this directory's scope even
    # though the variables are set ("-- Found SQLite3 ..."). Variables are
    # always in scope.
    target_link_libraries(db-sqlite PUBLIC ${SQLite3_LIBRARIES})
    target_include_directories(
        db-sqlite PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
                         ${SQLite3_INCLUDE_DIRS}
    )
    set_property(TARGET db-sqlite PROPERTY POSITION_INDEPENDENT_CODE ON)
endif() # NOT AUTH_CLIENT_ONLY (qrcodegen + db-sqlite)

# ── auth-client: relying-party JWT subset ─────────────────────────────────────
# What a relying party (e.g. mqtt-suite, protected_webapp) needs to accept IdP
# tokens: JwtVerifier + UserContext + the express auth middleware (and the
# header-only JwtAuthMiddleware.h / OAuth2CallbackHandler.h). Deliberately FREE
# of the IdP's signing/TOTP/QR/SQLite code so a relying party stays lightweight.
add_library(
    auth-client STATIC
    src/auth/JwtVerifier.cpp src/auth/UserContext.cpp
    src/auth/AuthMiddleware.cpp src/auth/OAuthClient.cpp
    src/auth/HttpExchange.cpp
)
target_link_libraries(
    auth-client
    PUBLIC snodec::http-server-express-legacy-in snodec::logger
           snodec::http-client snodec::net-in-stream-tls
           nlohmann_json::nlohmann_json ${OPENSSL_LIBRARIES}
)
target_include_directories(
    auth-client
    PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
           "$<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIRS}>"
           "$<INSTALL_INTERFACE:include/snodec-auth>"
)
set_property(TARGET auth-client PROPERTY POSITION_INDEPENDENT_CODE ON)

if(NOT AUTH_CLIENT_ONLY)
    # ── auth-idp: IdP server-side library
    # ───────────────────────────────────────── Token signing, TOTP and QR
    # generation and the reusable IdpMiddleware router.
    add_library(
        auth-idp STATIC
        src/auth/JwtSigner.cpp src/auth/Totp.cpp src/auth/QrCodeGenerator.cpp
        src/auth/AuthStore.cpp src/auth/IdpMiddleware.cpp
    )
    target_link_libraries(
        auth-idp PUBLIC auth-client db-sqlite snodec::http-server-express
                        snodec::nayuki-qrcodegen ${OPENSSL_LIBRARIES}
    )
    target_include_directories(
        auth-idp PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>"
                        "$<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIRS}>"
    )

    # ── auth_idp executable
    # ───────────────────────────────────────────────────────
    add_executable(auth_idp src/apps/auth_idp/IdpServer.cpp)
    if(NOT DEFINED AUTH_REVISION)
        execute_process(
            COMMAND git describe --always --dirty --abbrev=40
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
            OUTPUT_VARIABLE AUTH_REVISION
            OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET
        )
    endif()
    if(NOT AUTH_REVISION)
        set(AUTH_REVISION "unknown")
    endif()
    target_compile_definitions(
        auth-idp PRIVATE AUTH_VERSION="${PROJECT_VERSION}"
                         AUTH_REVISION="${AUTH_REVISION}"
    )

    target_link_libraries(auth_idp PRIVATE auth-idp)

    install(
        TARGETS auth-idp db-sqlite nayuki-qrcodegen
        EXPORT snodec-idp-targets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT auth-idp
    )
    install(
        FILES src/auth/IdpMiddleware.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/snodec-auth/auth
        COMPONENT auth-idp
    )
    install(
        EXPORT snodec-idp-targets
        FILE snodec-idp-targets.cmake
        NAMESPACE snodec-auth::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snodec-auth
        COMPONENT auth-idp
    )
    install(TARGETS auth_idp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                                     COMPONENT auth_idp
    )
endif() # NOT AUTH_CLIENT_ONLY (auth-idp library + auth_idp executable)

# ─────────────────────────────────────────────────────────────────────────────
# Install auth-client as a consumable CMake package: snodec-auth. A relying
# party (e.g. the mqtt-suite fork) then does: find_package(snodec-auth REQUIRED)
# target_link_libraries(<app> PRIVATE snodec-auth::auth-client) and gets
# JwtVerifier / JwtAuthMiddleware / OAuth2CallbackHandler without any of the
# IdP's server-side code.
# ─────────────────────────────────────────────────────────────────────────────
include(CMakePackageConfigHelpers)

install(
    TARGETS auth-client
    EXPORT snodec-auth-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT auth-client
)
install(
    FILES src/auth/JwtVerifier.h
          src/auth/UserContext.h
          src/auth/Security.h
          src/auth/HttpEncode.h
          src/auth/HttpExchange.h
          src/auth/OAuthClient.h
          src/auth/AuthMiddleware.h
          src/auth/JwtAuthMiddleware.h
          src/auth/OAuth2CallbackHandler.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/snodec-auth/auth
    COMPONENT auth-client
)
install(
    EXPORT snodec-auth-targets
    FILE snodec-auth-targets.cmake
    NAMESPACE snodec-auth::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snodec-auth
    COMPONENT auth-client
)

file(
    WRITE "${CMAKE_CURRENT_BINARY_DIR}/snodec-auth-config.cmake.in"
    "@PACKAGE_INIT@\n\
include(CMakeFindDependencyMacro)\n\
find_dependency(OpenSSL 3)\n\
find_dependency(nlohmann_json 3.11)\n\
find_dependency(snodec COMPONENTS http-server-express-legacy-in http-client net-in-stream-tls)\n\
include(\"\${CMAKE_CURRENT_LIST_DIR}/snodec-auth-targets.cmake\")\n\
if(EXISTS \"\${CMAKE_CURRENT_LIST_DIR}/snodec-idp-targets.cmake\")\n\
    find_dependency(SQLite3)\n\
    include(\"\${CMAKE_CURRENT_LIST_DIR}/snodec-idp-targets.cmake\")\n\
endif()\n"
)

configure_package_config_file(
    "${CMAKE_CURRENT_BINARY_DIR}/snodec-auth-config.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/snodec-auth-config.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snodec-auth
)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/snodec-auth-config-version.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMinorVersion
)
install(
    FILES "${CMAKE_CURRENT_BINARY_DIR}/snodec-auth-config.cmake"
          "${CMAKE_CURRENT_BINARY_DIR}/snodec-auth-config-version.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snodec-auth
    COMPONENT auth-client
)

include(CTest)
if(BUILD_TESTING AND NOT AUTH_CLIENT_ONLY)
    add_executable(authentication-test tests/authentication.cpp)
    target_link_libraries(authentication-test PRIVATE auth-idp)
    add_test(NAME authentication COMMAND authentication-test)
    add_executable(encoding-test tests/encoding.cpp)
    target_link_libraries(encoding-test PRIVATE auth-idp)
    add_test(NAME encoding COMMAND encoding-test
                                   "${CMAKE_CURRENT_BINARY_DIR}/encoding-"
    )
    find_package(
        Python3
        COMPONENTS Interpreter
        REQUIRED
    )
    add_test(
        NAME png-validation
        COMMAND
            "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/check_png.py"
            "${CMAKE_CURRENT_BINARY_DIR}/encoding-"
    )
    set_tests_properties(png-validation PROPERTIES DEPENDS encoding)
    add_test(NAME deployment
             COMMAND "${Python3_EXECUTABLE}"
                     "${CMAKE_CURRENT_SOURCE_DIR}/tests/deployment.py"
    )
endif()

option(AUTH_BUILD_EXAMPLE "Build the styled relying-party example" OFF)
if(AUTH_BUILD_EXAMPLE)
    add_subdirectory(examples/minimal-mfa-app)
endif()
include(Packing)
