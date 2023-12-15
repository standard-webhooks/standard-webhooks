#!/usr/bin/env sh
set -ex

autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place standardwebhooks tests --exclude=__init__.py
isort standardwebhooks tests
black standardwebhooks tests
