#!/bin/bash
set -e

echo "Building dynamic library lib.dylib..."
clang++ -dynamiclib -g -O0 -std=c++17 -arch arm64 lib.cpp -o lib.dylib

echo "Building main executable..."
clang++ -std=c++17 -arch arm64 main.cpp -o main

echo "Building test executable..."
clang++ -std=c++17 -arch arm64 test.cpp -o test

echo "Build complete."
