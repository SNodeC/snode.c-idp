# Resolve exact dependencies after CI has applied its distribution version.
set(CPACK_DEBIAN_AUTH-IDP_PACKAGE_DEPENDS
    "snodec-idp-client-dev (= ${CPACK_PACKAGE_VERSION}), libsqlite3-dev"
)
set(CPACK_RPM_AUTH-IDP_PACKAGE_REQUIRES
    "snodec-idp-client-dev = ${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}, sqlite-devel"
)
set(names "")
foreach(component IN LISTS CPACK_COMPONENTS_ALL)
    string(TOUPPER "${component}" upper)
    string(APPEND names "${CPACK_DEBIAN_${upper}_PACKAGE_NAME}\n")
endforeach()
file(MAKE_DIRECTORY "${CPACK_OUTPUT_FILE_PREFIX}")
file(WRITE "${CPACK_OUTPUT_FILE_PREFIX}/snodec-idp.packages" "${names}")
