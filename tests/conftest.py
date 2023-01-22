import pytest
import ape
from ape_manticore.manticore.utils import log


@pytest.fixture(scope="session")
def networks():
    return ape.networks


@pytest.fixture
def alchemy(networks):
    with networks.parse_network_choice("ethereum:mainnet:alchemy") as provider:
        yield provider


@pytest.fixture
def fork(networks):
    with networks.parse_network_choice("ethereum:mainnet-fork:foundry") as provider:
        yield provider


@pytest.fixture(scope="session", autouse=True)
def initialize_manticore_logging(request):
    """Initialize Manticore's logger for all tests"""
    log.init_logging()
