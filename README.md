## Development
The present software package shares similarities with the original Manticore-based package, but its latest version facilitates the establishment of a connection with a provider, such as Alchemy or Infura.

However, development on this project has come to a halt due to a disruptive change in python v3.7 that has altered the functioning of forks and processes. To upgrade this package to a more recent python version, the underlying issues need to be resolved, requiring a comprehensive and thorough refactoring process, which currently poses time constraints.

The primary objective of developing this package was to employ it as an educational tool to achieve a deeper understanding of how symbolic execution engines operate. Moreover, I aimed to enhance the package's functionality by connecting it to a live blockchain system, thereby streamlining the data loading process and minimizing manual setup requirements.

As the project is still in the development phase, it is important to note that the current version should be considered a beta version.

## Dependencies

* [python3](https://www.python.org/downloads) version 3.10 or greater, python3-dev

## Installation

### via `pip`

You can install the latest release via [`pip`](https://pypi.org/project/pip/):

```bash
git clone https://github.com/hhamud/ape-manticore.git
cd ape-manticore
pip install .
```

### via `setuptools`

You can clone the repository and use [`setuptools`](https://github.com/pypa/setuptools) for the most up-to-date version:

```bash
git clone https://github.com/hhamud/ape-manticore.git
cd ape-manticore
python3 setup.py install
```

