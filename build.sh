#!/bin/bash

# Exit on any error
set -e

# Assuming Gradle is used for building
if [ -f "build.gradle" ]; then
  echo "Building extension with Gradle..."
  ./gradlew build
fi

echo "Extension packaging complete."
