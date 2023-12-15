#!/usr/bin/env sh
set -ex

mypy standardwebhooks tests
isort --check-only standardwebhooks tests
black standardwebhooks tests --check
flake8 standardwebhooks tests
