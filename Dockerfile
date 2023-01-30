############################### Base ###############################
FROM ubuntu:20.04 as base

RUN apt-get -y update && DEBIAN_FRONTEND=noninteractive apt-get -y install python3.10 python3-pip git wget

# Install solc 0.4.25 and validate it
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.25/solc-static-linux \
 && chmod +x solc-static-linux \
 && mv solc-static-linux /usr/bin/solc

RUN pip install -U pip

COPY setup.py README.md pyproject.toml ape_manticore.egg-info /app/

WORKDIR /app

RUN pip install .[dev]

COPY . ./app


############################### Debugger ###############################
From base as debug

RUN pip install debugpy


#CMD ["python3", "-m", "debugpy", "--listen", "0.0.0.0:5678", "--wait-for-client", "tests/ethereum/test_sha3.py"]

# python3 -m debugpy --listen 0.0.0.0:5678 --wait-for-client tests/ethereum/test_sha3.py
