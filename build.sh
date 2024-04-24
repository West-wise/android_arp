#!bin/bash

ARCHITECTURE=$1

# Clean up previous build-related files
rm -rf CMakeCache.txt CMakeFiles cmake_install.cmake Makefile

if [ -z "$ARCHITECTURE" ]; then
    cmake .
    exit 0
fi

if [[ "$ARCHITECTURE" == "arm64" ]]; then
    if ! cmake -DCMAKE_TOOLCHAIN_FILE=$Android .; then
        echo "CMake Error: Failed to configure the arm64 build"
        exit 1
    else
        make
    fi

elif [[ "$ARCHITECTURE" == "arm32" ]]; then
    if ! cmake -DCMAKE_TOOLCHAIN_FILE=$Android -DBIT=32 .; then
        echo "CMake Error: Failed to configure the arm32 build"
        exit 1
    else
        make
    fi
else
    # If an unsupported architecture is provided
    echo "Error: Unsupported architecture specified"
    exit 1
fi

