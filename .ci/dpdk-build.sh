#!/bin/bash

set -o errexit
set -x

function build_dpdk()
{
    local VERSION_FILE="dpdk-dir/cached-version"
    local DPDK_VER=$1
    local DPDK_OPTS=""

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
                echo "Found already built DPDK ${VER} build in $(pwd)/dpdk-dir"
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

    meson $DPDK_OPTS build
    ninja -C build
    ninja -C build install

    echo "Installed DPDK source in $(pwd)"
    popd
    echo "${DPDK_VER}" > ${VERSION_FILE}
}

build_dpdk $DPDK_VER
