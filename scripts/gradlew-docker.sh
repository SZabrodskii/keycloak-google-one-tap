#!/usr/bin/env bash
# Runs the Gradle wrapper inside a JDK 17 container for machines without a local JDK.
# Usage: scripts/gradlew-docker.sh test shadowJar
set -euo pipefail
cd "$(dirname "$0")/.."
GRADLE_CACHE="${GRADLE_CACHE:-$HOME/.cache/keycloak-google-one-tap-gradle}"
mkdir -p "$GRADLE_CACHE"
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e GRADLE_USER_HOME=/gradle-home \
  -v "$GRADLE_CACHE:/gradle-home" \
  -v "$PWD:/work" -w /work \
  eclipse-temurin:17-jdk \
  ./gradlew --no-daemon --console=plain "$@"
