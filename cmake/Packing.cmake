# Existing install components are also the package ownership boundary.
set(CPACK_PACKAGE_NAME "snodec-idp")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT "Volker Christian <me@vchrist.at>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY
    "SNode.C identity provider and MFA client"
)
set(CPACK_PACKAGE_VENDOR "SNodeC")
set(CPACK_VERBATIM_VARIABLES YES)
set(CPACK_STRIP_FILES YES)
set(CPACK_OUTPUT_FILE_PREFIX "${CMAKE_BINARY_DIR}/_packages")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_RPM_FILE_NAME RPM-DEFAULT)
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_GROUPING IGNORE)
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_RPM_PACKAGE_LICENSE "MIT")
set(CPACK_RPM_PACKAGE_RELEASE 1)
set(CPACK_RPM_PACKAGE_RELEASE_DIST OFF)
set(CPACK_RPM_PACKAGE_RELOCATABLE OFF)
list(APPEND CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION "/usr/sbin")
set(CPACK_DEBIAN_AUTH-CLIENT_PACKAGE_NAME "snodec-idp-client-dev")
set(CPACK_RPM_AUTH-CLIENT_PACKAGE_NAME "snodec-idp-client-dev")
set(CPACK_DEBIAN_AUTH-IDP_PACKAGE_NAME "snodec-idp-server-dev")
set(CPACK_RPM_AUTH-IDP_PACKAGE_NAME "snodec-idp-server-dev")
set(CPACK_DEBIAN_AUTH_IDP_PACKAGE_NAME "snodec-idp")
set(CPACK_RPM_AUTH_IDP_PACKAGE_NAME "snodec-idp")
set(CPACK_DEBIAN_EXAMPLE_PACKAGE_NAME "snodec-idp-example")
set(CPACK_RPM_EXAMPLE_PACKAGE_NAME "snodec-idp-example")
set(CPACK_DEBIAN_AUTH-CLIENT_PACKAGE_DEPENDS
    "snodec-http-server-express-legacy-in, snodec-http-client, snodec-net-in-stream-tls, libssl-dev, nlohmann-json3-dev"
)
set(CPACK_RPM_AUTH-CLIENT_PACKAGE_REQUIRES
    "snodec-http-server-express-legacy-in, snodec-http-client, snodec-net-in-stream-tls, openssl-devel, json-devel"
)
set(CPACK_DEBIAN_AUTH_IDP_PACKAGE_DEPENDS "python3, openssl, systemd, nginx")
set(CPACK_RPM_AUTH_IDP_PACKAGE_REQUIRES "python3, openssl, systemd, nginx")
if(NOT AUTH_CLIENT_ONLY)
    configure_file(packaging/snodec-idp.service.in snodec-idp.service @ONLY)
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/snodec-idp.service"
        DESTINATION lib/systemd/system
        COMPONENT auth_idp
    )
    install(
        PROGRAMS scripts/deploy.py
        DESTINATION ${CMAKE_INSTALL_SBINDIR}
        RENAME snodec-idp-deploy
        COMPONENT auth_idp
    )
    install(
        FILES packaging/deployment.example.json
        DESTINATION ${CMAKE_INSTALL_DATADIR}/snodec-idp
        COMPONENT auth_idp
    )
endif()
if(AUTH_BUILD_EXAMPLE)
    configure_file(
        packaging/snodec-idp-example.service.in snodec-idp-example.service
        @ONLY
    )
    install(
        FILES "${CMAKE_CURRENT_BINARY_DIR}/snodec-idp-example.service"
        DESTINATION lib/systemd/system
        COMPONENT example
    )
endif()
set(CPACK_SOURCE_IGNORE_FILES
    "/build/;/checkouts/;/.git/;/.qtcreator/;/__pycache__/;/keys/;/data/;[.]pem$;[.]key$;/.env"
)
set(CPACK_PROJECT_CONFIG_FILE "${CMAKE_CURRENT_LIST_DIR}/PackageConfig.cmake")
get_cmake_property(CPACK_COMPONENTS_ALL COMPONENTS)
include(CPack)
