#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
SPARSE_FLAGS=""
EXTRA_OPTS="--enable-Werror"

function install_dpdk()
{
    local DPDK_VER=$1
    local VERSION_FILE="dpdk-dir/cached-version"
    local DPDK_OPTS=""
    local DPDK_LIB=$(pwd)/dpdk-dir/build/lib/x86_64-linux-gnu

    if [ "$DPDK_SHARED" ]; then
        EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=shared"
        export LD_LIBRARY_PATH=$DPDK_LIB/:$LD_LIBRARY_PATH
    else
        EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=static"
    fi

    # Export the following path for pkg-config to find the .pc file.
    export PKG_CONFIG_PATH=$DPDK_LIB/pkgconfig/:$PKG_CONFIG_PATH

    if [ "${DPDK_VER##refs/*/}" != "${DPDK_VER}" ]; then
        # Avoid using cache for git tree build.
        rm -rf dpdk-dir

        DPDK_GIT=${DPDK_GIT:-https://dpdk.org/git/dpdk}
        git clone --single-branch $DPDK_GIT dpdk-dir -b "${DPDK_VER##refs/*/}"
        pushd dpdk-dir
        git log -1 --oneline
    else
        if [ -f "${VERSION_FILE}" ]; then
            VER=$(cat ${VERSION_FILE})
            if [ "${VER}" = "${DPDK_VER}" ]; then
                # Update the library paths.
                sudo ldconfig
                echo "Found cached DPDK ${VER} build in $(pwd)/dpdk-dir"
                return
            fi
        fi
        # No cache or version mismatch.
        rm -rf dpdk-dir
        wget https://fast.dpdk.org/rel/dpdk-$1.tar.xz
        tar xvf dpdk-$1.tar.xz > /dev/null
        DIR_NAME=$(tar -tf dpdk-$1.tar.xz | head -1 | cut -f1 -d"/")
        mv ${DIR_NAME} dpdk-dir
        pushd dpdk-dir
    fi

    # Switching to 'default' machine to make dpdk-dir cache usable on
    # different CPUs. We can't be sure that all CI machines are exactly same.
    DPDK_OPTS="$DPDK_OPTS -Dmachine=default"

    # Disable building DPDK unit tests. Not needed for OVS build or tests.
    DPDK_OPTS="$DPDK_OPTS -Dtests=false"

    # Disable DPDK developer mode, this results in less build checks and less
    # meson verbose outputs.
    DPDK_OPTS="$DPDK_OPTS -Ddeveloper_mode=disabled"

    # OVS compilation and "normal" unit tests (run in the CI) do not depend on
    # any DPDK driver being present.
    # We can disable all drivers to save compilation time.
    DPDK_OPTS="$DPDK_OPTS -Ddisable_drivers=*/*"

    # Install DPDK using prefix.
    DPDK_OPTS="$DPDK_OPTS --prefix=$(pwd)/build"

    CC=gcc meson $DPDK_OPTS build
    ninja -C build
    ninja -C build install

    # Update the library paths.
    sudo ldconfig


    echo "Installed DPDK source in $(pwd)"
    popd
    echo "${DPDK_VER}" > ${VERSION_FILE}
}

function configure_ovs()
{
    ./boot.sh
    ./configure CFLAGS="${CFLAGS_FOR_OVS}" $*
}

function build_ovs()
{
    configure_ovs $OPTS
    make selinux-policy

    make -j4
}

if [ "$DEB_PACKAGE" ]; then
    ./boot.sh && ./configure --with-dpdk=$DPDK && make debian
    mk-build-deps --install --root-cmd sudo --remove debian/control
    dpkg-checkbuilddeps
    make debian-deb
    packages=$(ls $(pwd)/../*.deb)
    deps=""
    for pkg in $packages; do
        _ifs=$IFS
        IFS=","
        for dep in $(dpkg-deb -f $pkg Depends); do
            dep_name=$(echo "$dep"|awk '{print$1}')
            # Don't install internal package inter-dependencies from apt
            echo $dep_name | grep -q openvswitch && continue
            deps+=" $dep_name"
        done
        IFS=$_ifs
    done
    # install package dependencies from apt
    echo $deps | xargs sudo apt -y install
    # install the locally built openvswitch packages
    sudo dpkg -i $packages

    # Check that python C extension is built correctly.
    python3 -c "
from ovs import _json
import ovs.json
assert ovs.json.from_string('{\"a\": 42}') == {'a': 42}"

    exit 0
fi

if [ "$DPDK" ] || [ "$DPDK_SHARED" ]; then
    if [ -z "$DPDK_VER" ]; then
        DPDK_VER="22.11.1"
    fi
    install_dpdk $DPDK_VER
fi

if [ "$CC" = "clang" ]; then
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} -Wno-error=unused-command-line-argument"
elif [ "$M32" ]; then
    # Not using sparse for 32bit builds on 64bit machine.
    # Adding m32 flag directly to CC to avoid any posiible issues with API/ABI
    # difference on 'configure' and 'make' stages.
    export CC="$CC -m32"
else
    EXTRA_OPTS="$EXTRA_OPTS --enable-sparse"
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${SPARSE_FLAGS}"
fi

if [ "$SANITIZERS" ]; then
    # This will override the default ASAN_OPTIONS configured in
    # tests/atlocal.in, however, it will use the defined UBSAN_OPTIONS.
    export ASAN_OPTIONS='detect_leaks=1'
    CFLAGS_ASAN="-fno-omit-frame-pointer -fno-common -fsanitize=address"
    CFLAGS_UBSAN="-fsanitize=undefined"
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} ${CFLAGS_ASAN} ${CFLAGS_UBSAN}"
fi

OPTS="${EXTRA_OPTS} ${OPTS} $*"

if [ "$TESTSUITE" ]; then
    # 'distcheck' will reconfigure with required options.
    # Now we only need to prepare the Makefile without sparse-wrapped CC.
    configure_ovs

    export DISTCHECK_CONFIGURE_FLAGS="$OPTS"
    make distcheck -j4 CFLAGS="${CFLAGS_FOR_OVS}" \
        TESTSUITEFLAGS=-j4 RECHECK=yes
else
    build_ovs
fi

exit 0
