#!/bin/sh -e
set -x

autoflake --remove-all-unused-imports --recursive --remove-unused-variables --in-place standardwebhooks --exclude=__init__.py
isort standardwebhooks
black standardwebhooks
