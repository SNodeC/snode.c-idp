#!/bin/sh
# Source-owned build policy; dependency installation belongs to trusted preparation.
set -eu
: "${SOURCE_DIR:?}" "${TARGET_JSON:?}" "${OUTPUT_DIR:?}"
format=$(python3 -c 'import json,os; print(json.load(open(os.environ["TARGET_JSON"]))["build"]["format"])')
if [ "$format" = deb ]; then
    libdir="lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH)"
else
    libdir=lib64
    if [ -f /opt/rh/gcc-toolset-14/enable ]; then
        . /opt/rh/gcc-toolset-14/enable
    fi
fi
build=/work/build-product
cmake -S "$SOURCE_DIR" -B "$build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_INSTALL_LIBDIR="$libdir" -DCMAKE_INSTALL_SYSCONFDIR=/etc \
    -DAUTH_BUILD_EXAMPLE=ON -DCMAKE_CXX_FLAGS=-Werror -DAUTH_REVISION="$SOURCE_COMMIT"
cmake --build "$build" --parallel 2
ctest --test-dir "$build" --output-on-failure --output-junit core-ci-tests.xml
python3 /tool/native_container.py --package "$build"
DESTDIR=/work/installed cmake --install "$build"
export CMAKE_PREFIX_PATH="/work/installed/usr${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
export LD_LIBRARY_PATH="/work/installed/usr/$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cmake -S "$SOURCE_DIR/tests/live" -B /work/build-consumer -G Ninja
cmake --build /work/build-consumer --parallel 2
cmake -S "$SOURCE_DIR" -B /work/build-client -G Ninja \
    -DAUTH_CLIENT_ONLY=ON -DCMAKE_CXX_FLAGS=-Werror -DAUTH_REVISION="$SOURCE_COMMIT"
cmake --build /work/build-client --parallel 2
