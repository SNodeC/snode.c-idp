#!/usr/bin/env bash
# Product dependencies and build policy are versioned with this source.
if [ "$format" = DEB ]; then
    apt-get install -y libbluetooth-dev libmagic-dev libmariadb-dev libssl-dev openssl libncurses-dev nlohmann-json3-dev libsqlite3-dev
else
    dnf install -y bluez-libs-devel file-devel mariadb-connector-c-devel openssl-devel openssl ncurses-devel json-devel sqlite-devel
fi
options=(-DAUTH_BUILD_EXAMPLE=ON -DCMAKE_CXX_FLAGS=-Werror)
revision=$(python3 -c 'import json; refs=json.load(open("bundle/sources.json"))["snode.c-idp"]; print(next((v for k,v in refs.items() if k.endswith("^{}")), next(iter(refs.values()))))')
options+=("-DAUTH_REVISION=$revision")
cmake -S "sources/$BUILD_PROJECT" -B build-product -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_INSTALL_LIBDIR="$libdir" -DCMAKE_INSTALL_SYSCONFDIR=/etc "${options[@]}"
cmake --build build-product --parallel 4
chown -R snodec-test:snodec-test build-product
runuser -u snodec-test -- ctest --test-dir build-product --output-on-failure
package build-product
if [ "$format" = DEB ]; then
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod +x /usr/sbin/policy-rc.d
fi
install_packages /work/packages/snodec-idp*."${format,,}"
cmake -S sources/snode.c-idp/tests/live -B build-consumer -G Ninja
cmake --build build-consumer --parallel 4
cmake -S sources/snode.c-idp -B build-client -G Ninja -DAUTH_CLIENT_ONLY=ON -DCMAKE_CXX_FLAGS=-Werror
cmake --build build-client --parallel 4
