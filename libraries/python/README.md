Python library for Standard Webhooks

# Standard Webhook Specification

Visit [Standard Webhook Specification](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md) to understand webhooks specification details.

To debug or simulate webhooks messages check [webhooks tools](https://www.standardwebhooks.com/#tools).


# Example

Verifying a webhook payload:

```python
import os

from standardwebhooks import Webhook


WEBHOOK_SECRET_B64 = os.getenv('WEBHOOK_SECRET_B64')

wh = Webhook(WEBHOOK_SECRET_B64)

try:
    # request_payload - JSON encoded request body
    payload = wh.verify(request_payload, request_headers)
except Exception as e:
    print(repr(e))
```

# Installation

[Python 3](https://www.python.org/downloads/) is required!

## Installation From PyPI

The package is available on [PyPI](https://pypi.org/project/standardwebhooks/).

```shell
pip install standardwebhooks
```

## Installation From GitHub

Install `standardwebhooks` package directly from github repository.

```sh
pip install git+https://github.com/standard-webhooks/standard-webhooks.git#subdirectory="libraries/python"
```

If you want to install `standardwebhooks` from `requirements.txt` add this line to the file.

```
git+https://github.com/standard-webhooks/standard-webhooks.git#subdirectory=libraries/python
```

## Installation From Source Code

Install `standardwebhooks` package from source code. This method assumes that python package [venv](https://docs.python.org/3/library/venv.html) is installed.

```sh
# Clone repo
git clone git@github.com:standard-webhooks/standard-webhooks.git

# Setup and activate virtual environment
cd standard-webhooks/libraries/python/
python3 -m venv .venv
. .venv/bin/activate

# Install package locally
pip install -r requirements.txt && pip install -r requirements-dev.txt

# Deactivate virtual environment
deactivate
```

# Tests

In package directory run `pytest`.

```sh
pytest
```

# Contributing

**Before opening a PR be sure to format your code!**

```sh
./scripts/format.sh
```
