# Resolve exact dependencies after CI has applied its distribution version.
set(CPACK_DEBIAN_AUTH-IDP_PACKAGE_DEPENDS
    "snodec-idp-client-dev (= ${CPACK_PACKAGE_VERSION}), libsqlite3-dev"
)
set(CPACK_RPM_AUTH-IDP_PACKAGE_REQUIRES
    "snodec-idp-client-dev = ${CPACK_PACKAGE_VERSION}-${CPACK_RPM_PACKAGE_RELEASE}, sqlite-devel"
)
# Native metadata records the exact dependency selection frozen in the wave.
if(DEFINED ENV{DEPENDENCIES_JSON})
    set(dependencies "$ENV{DEPENDENCIES_JSON}")
    string(JSON count LENGTH "${dependencies}")
    if(NOT count EQUAL 1)
        message(FATAL_ERROR "Expected the resolved snodec dependency")
    endif()
    string(JSON package GET "${dependencies}" 0 package)
    string(JSON version GET "${dependencies}" 0 version)
    string(JSON revision GET "${dependencies}" 0 revision)
    if(NOT package STREQUAL "snodec")
        message(FATAL_ERROR "Unexpected resolved dependency: ${package}")
    endif()
    if(CPACK_GENERATOR STREQUAL "DEB")
        string(JSON codename GET "$ENV{TARGET_JSON}" codename)
        set(bound " (= ${version}-${revision}~${codename})")
        set(variable CPACK_DEBIAN_AUTH-CLIENT_PACKAGE_DEPENDS)
    else()
        string(JSON disttag GET "$ENV{TARGET_JSON}" disttag)
        set(bound " = ${version}-${revision}.${disttag}")
        set(variable CPACK_RPM_AUTH-CLIENT_PACKAGE_REQUIRES)
    endif()
    foreach(name snodec-http-server-express-legacy-in snodec-http-client
                 snodec-net-in-stream-tls
    )
        string(REPLACE "${name}" "${name}${bound}" ${variable} "${${variable}}")
    endforeach()
endif()
set(names "")
foreach(component IN LISTS CPACK_COMPONENTS_ALL)
    string(TOUPPER "${component}" upper)
    string(APPEND names "${CPACK_DEBIAN_${upper}_PACKAGE_NAME}\n")
endforeach()
file(MAKE_DIRECTORY "${CPACK_OUTPUT_FILE_PREFIX}")
file(WRITE "${CPACK_OUTPUT_FILE_PREFIX}/snodec-idp.packages" "${names}")
