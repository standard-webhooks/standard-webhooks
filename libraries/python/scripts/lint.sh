#!/usr/bin/env bash

set -ex

mypy standardwebhooks
isort --check-only standardwebhooks
black standardwebhooks --check
flake8 standardwebhooks
