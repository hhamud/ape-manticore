from ape.api import ProviderAPI
import pytest
from ape_manticore.manticore.core.smtlib.constraints import ConstraintSet
from ape_manticore.manticore.ethereum import ManticoreEVM
from ape_manticore.manticore.platforms.evm.evmworld import EVMWorld
from web3 import Web3

USDC_ADDRESS = 0xA0B86991C6218B36C1D19D4A2E9EB0CE3606EB48
DAI_ADDRESS = 0x6B175474E89094C44DA98B954EEDEAC495271D0F
WETH_ADDRESS = 0xC02AAA39B223FE8D0A0E5C4F27EAD9083C756CC2
RANDOM_ADDRESS = 0x98E6E4A3856049FEC1272F61127EC30A96F77256


def test_networks(networks, alchemy):
    assert networks.active_provider.name == "alchemy"
    assert networks.active_provider.network.name == "mainnet"
    assert (
        networks.active_provider.get_balance(address=Web3.toChecksumAddress(RANDOM_ADDRESS))
        == 124228533118105779
    )


def test_provider_world(networks, alchemy):
    constraints = ConstraintSet()
    world = EVMWorld(constraints=constraints, provider=networks.active_provider)
    assert isinstance(world._world_state.provider, ProviderAPI)


def test_create_account(networks, alchemy):
    constraints = ConstraintSet()
    world = EVMWorld(constraints=constraints, provider=networks.active_provider)
    world.create_account(RANDOM_ADDRESS)
    assert (RANDOM_ADDRESS in world._world_state.accounts_state.keys()) == True


def test_fork_world(networks, alchemy):
    constraints = ConstraintSet()
    world = EVMWorld(constraints=constraints, provider=networks.active_provider)
    world.create_account(RANDOM_ADDRESS)
    eth_balance = world._world_state.accounts_state[RANDOM_ADDRESS].get_balance()
    assert eth_balance == 124228533118105779


def test_world_balance(networks, alchemy):
    constraints = ConstraintSet()
    world = EVMWorld(constraints=constraints, provider=networks.active_provider)
    world.create_account(RANDOM_ADDRESS)
    eth_balance = world.get_balance(RANDOM_ADDRESS)
    assert eth_balance == 124228533118105779
