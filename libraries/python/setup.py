import codecs
import os
import re

from setuptools import find_packages, setup


def read_file(filepath):
    """Read content from a UTF-8 encoded text file."""
    with codecs.open(filepath, "rb", "utf-8") as file_handle:
        return file_handle.read()


PKG_NAME = "standardwebhooks"
PKG_DIR = os.path.abspath(os.path.dirname(__file__))
META_PATH = os.path.join(PKG_DIR, PKG_NAME, "__init__.py")
META_CONTENTS = read_file(META_PATH)
PKG_REQUIRES = [
    "attrs >= 21.3.0",
    "Deprecated",
    "httpx >= 0.23.0",
    "python-dateutil",
    "types-Deprecated",
    "types-python-dateutil",
]


def find_meta(meta):
    """Extract __*meta*__ from META_CONTENTS."""
    meta_match = re.search(r"^__{meta}__\s+=\s+['\"]([^'\"]*)['\"]".format(meta=meta), META_CONTENTS, re.M)
    if meta_match:
        return meta_match.group(1)

    raise RuntimeError(f"Unable to find __{meta}__ string in package meta file")


def is_canonical_version(version):
    """Check if a version string is in the canonical format of PEP 440."""
    pattern = (
        r"^([1-9][0-9]*!)?(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*))"
        r"*((a|b|rc)(0|[1-9][0-9]*))?(\.post(0|[1-9][0-9]*))"
        r"?(\.dev(0|[1-9][0-9]*))?$"
    )

    return re.match(pattern, version) is not None


def get_version_string():
    """Return package version as listed in `__version__` in meta file."""
    # Parse version string
    version_string = find_meta("version")

    # Check validity
    if not is_canonical_version(version_string):
        message = f"The detected version string {version_string} is not in canonical format as defined in PEP 440."
        raise ValueError(message)

    return version_string


PKG_README = read_file(os.path.join(os.path.dirname(__file__), "README.md"))

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name=PKG_NAME,
    version=get_version_string(),
    description="Standard Webhooks",
    author="Standard Webhooks",
    license="MIT",
    keywords=[
        "webhooks",
    ],
    classifiers=[
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development",
        "Typing :: Typed",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.6",
    install_requires=PKG_REQUIRES,
    zip_safe=False,
    packages=find_packages(exclude=["test", "tests"]),
    package_data={
        "": ["py.typed"],
    },
    long_description=PKG_README,
    long_description_content_type="text/markdown",
)
