#!/bin/bash
echo "Building dynamic library lib.dylib..."
clang++ -dynamiclib -arch arm64 -mmacosx-version-min=14.0 lib.cpp -o lib.dylib

echo "Building main executable..."
clang++ -std=c++11 -arch arm64 -mmacosx-version-min=14.0 main.cpp -o main

echo "Building test executable..."
clang++ -arch arm64 -mmacosx-version-min=14.0 test.cpp -o test

echo "Build complete."