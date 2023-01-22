#!/usr/bin/env python
# -*- coding: utf-8 -*-
from setuptools import find_packages, setup

extras_require = {
    "test": [  # `test` GitHub Action jobs uses this
        "pytest>=6.0",  # Core testing package
        "pytest-xdist",  # multi-process runner
        "pytest-cov",  # Coverage analyzer plugin
        "hypothesis>=6.2.0,<7.0",  # Strategy-based fuzzer
    ],
    "lint": [
        "black>=22.10.0",  # auto-formatter and linter
        "mypy>=0.982",  # Static type analyzer
        "types-setuptools",  # Needed for mypy type shed
        "flake8>=5.0.4",  # Style linter
        "isort>=5.10.1",  # Import sorting linter
    ],
    "release": [  # `release` GitHub Action job uses this
        "setuptools",  # Installation tool
        "wheel",  # Packaging tool
        "twine",  # Package upload tool
    ],
    "dev": [
        "commitizen",  # Manage commits and publishing releases
        "pre-commit",  # Ensure that linters are run prior to commiting
        "pytest-watch",  # `ptw` test watcher/runner
        "IPython",  # Console for interacting
        "ipdb",  # Debugger (Must use `export PYTHONBREAKPOINT=ipdb.set_trace`)
    ],
}

# NOTE: `pip install -e .[dev]` to install package
extras_require["dev"] = (
    extras_require["test"]
    + extras_require["lint"]
    + extras_require["release"]
    + extras_require["dev"]
)

with open("./README.md") as readme:
    long_description = readme.read()


setup(
    name="ape-manticore",
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    description="""ape-manticore: ape wrapper for manticore symbolic execution engine""",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Hamza Hamud",
    url="https://github.com/hhamud/ape-manticore",
    include_package_data=True,
    install_requires=[
        "pyyaml",
        "protobuf>=4.21.6",
        # evm dependencies
        "pysha3",
        "prettytable",
        "ply",
        "rlp",
        "intervaltree",
        "crytic-compile>=0.2.2",
        "dataclasses; python_version < '3.7'",
        "pyevmasm>=0.2.3",
        "py-evm",
        "z3-solver",
        "keystone-engine",
        "capstone==5.0.0rc2",
        "pyevmasm>=0.2.3",
        # ape dependencies
        # "eth-ape @ git+ssh://git@github.com/ApeWorX/ape@v0.5.9#egg=eth-ape",
        "eth-ape>=0.5.6,<0.6",
        "ape-foundry",
        "ape-alchemy",
    ],
    python_requires=">=3.8,<4",
    extras_require=extras_require,
    py_modules=["ape_manticore"],
    license="Apache-2.0",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(exclude=["tests", "tests.*"]),
    package_data={"ape-manticore": ["py.typed"]},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
