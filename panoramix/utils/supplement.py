import json
import logging
import lzma
import os
import sys
import time
from pathlib import Path
from zipfile import ZipFile
from typing import Optional
import shelve
from panoramix.utils.helpers import (
    cache_dir,
    cached,
)

"""
    a module for management of bytes4 signatures from the database

     db schema:

     hash - 0x12345678
     name - transferFrom
     folded_name - transferFrom(address,address,uint256)
     cooccurs - comma-dellimeted list of hashes: `0x12312312,0xabababab...`
     params - json: `[
            {
              "type": "address",
              "name": "_from"
            },
            {
              "type": "address",
              "name": "_to"
            },
            {
              "type": "uint256",
              "name": "_value"
            }
          ]`

"""

logger = logging.getLogger(__name__)

LOCAL_SIGS_BULK_PATH = Path(__file__).parent.parent / "data" / "local_sigs.json"
LOCAL_SIGS_BULK = None

LOCAL_SIGS = {
    "0x06fdde03": {
        "name": "name",
        "inputs": [],
    },
    "0x95d89b41": {
        "name": "symbol",
        "inputs": [],
    },
    "0x313ce567": {
        "name": "decimals",
        "inputs": [],
    },
    "0x18160ddd": {
        "name": "totalSupply",
        "inputs": [],
    },
    "0x70a08231": {
        "name": "balanceOf",
        "inputs": [{"type": "address", "name": "account"}],
    },
    "0xdd62ed3e": {
        "name": "allowance",
        "inputs": [
            {"type": "address", "name": "owner"},
            {"type": "address", "name": "spender"},
        ],
    },
    "0xa9059cbb": {
        "name": "transfer",
        "inputs": [
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "amount"},
        ],
    },
    "0x095ea7b3": {
        "name": "approve",
        "inputs": [
            {"type": "address", "name": "spender"},
            {"type": "uint256", "name": "amount"},
        ],
    },
    "0x23b872dd": {
        "name": "transferFrom",
        "inputs": [
            {"type": "address", "name": "from"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "amount"},
        ],
    },
    "0x38d52e0f": {
        "name": "asset",
        "inputs": [],
    },
    "0x01e1d114": {
        "name": "totalAssets",
        "inputs": [],
    },
    "0xc6e6f592": {
        "name": "convertToShares",
        "inputs": [{"type": "uint256", "name": "assets"}],
    },
    "0x07a2d13a": {
        "name": "convertToAssets",
        "inputs": [{"type": "uint256", "name": "shares"}],
    },
    "0x402d267d": {
        "name": "maxDeposit",
        "inputs": [{"type": "address", "name": "receiver"}],
    },
    "0xef8b30f7": {
        "name": "previewDeposit",
        "inputs": [{"type": "uint256", "name": "assets"}],
    },
    "0x6e553f65": {
        "name": "deposit",
        "inputs": [
            {"type": "uint256", "name": "assets"},
            {"type": "address", "name": "receiver"},
        ],
    },
    "0xc63d75b6": {
        "name": "maxMint",
        "inputs": [{"type": "address", "name": "receiver"}],
    },
    "0xb3d7f6b9": {
        "name": "previewMint",
        "inputs": [{"type": "uint256", "name": "shares"}],
    },
    "0x94bf804d": {
        "name": "mint",
        "inputs": [
            {"type": "uint256", "name": "shares"},
            {"type": "address", "name": "receiver"},
        ],
    },
    "0xce96cb77": {
        "name": "maxWithdraw",
        "inputs": [{"type": "address", "name": "owner"}],
    },
    "0x0a28a477": {
        "name": "previewWithdraw",
        "inputs": [{"type": "uint256", "name": "assets"}],
    },
    "0xb460af94": {
        "name": "withdraw",
        "inputs": [
            {"type": "uint256", "name": "assets"},
            {"type": "address", "name": "receiver"},
            {"type": "address", "name": "owner"},
        ],
    },
    "0xd905777e": {
        "name": "maxRedeem",
        "inputs": [{"type": "address", "name": "owner"}],
    },
    "0x4cdad506": {
        "name": "previewRedeem",
        "inputs": [{"type": "uint256", "name": "shares"}],
    },
    "0xba087652": {
        "name": "redeem",
        "inputs": [
            {"type": "uint256", "name": "shares"},
            {"type": "address", "name": "receiver"},
            {"type": "address", "name": "owner"},
        ],
    },
    "0xe8eda9df": {
        "name": "deposit",
        "inputs": [
            {"type": "address", "name": "asset"},
            {"type": "uint256", "name": "amount"},
            {"type": "address", "name": "onBehalfOf"},
            {"type": "uint16", "name": "referralCode"},
        ],
    },
    "0x617ba037": {
        "name": "supply",
        "inputs": [
            {"type": "address", "name": "asset"},
            {"type": "uint256", "name": "amount"},
            {"type": "address", "name": "onBehalfOf"},
            {"type": "uint16", "name": "referralCode"},
        ],
    },
    "0x69328dec": {
        "name": "withdraw",
        "inputs": [
            {"type": "address", "name": "asset"},
            {"type": "uint256", "name": "amount"},
            {"type": "address", "name": "to"},
        ],
    },
    "0xa415bcad": {
        "name": "borrow",
        "inputs": [
            {"type": "address", "name": "asset"},
            {"type": "uint256", "name": "amount"},
            {"type": "uint256", "name": "interestRateMode"},
            {"type": "uint16", "name": "referralCode"},
            {"type": "address", "name": "onBehalfOf"},
        ],
    },
    "0x573ade81": {
        "name": "repay",
        "inputs": [
            {"type": "address", "name": "asset"},
            {"type": "uint256", "name": "amount"},
            {"type": "uint256", "name": "rateMode"},
            {"type": "address", "name": "onBehalfOf"},
        ],
    },
    "0xab9c4b5d": {
        "name": "flashLoan",
        "inputs": [
            {"type": "address", "name": "receiverAddress"},
            {"type": "address[]", "name": "assets"},
            {"type": "uint256[]", "name": "amounts"},
            {"type": "uint256[]", "name": "modes"},
            {"type": "address", "name": "onBehalfOf"},
            {"type": "bytes", "name": "params"},
            {"type": "uint16", "name": "referralCode"},
        ],
    },
    "0x42b0b77c": {
        "name": "flashLoanSimple",
        "inputs": [
            {"type": "address", "name": "receiverAddress"},
            {"type": "address", "name": "asset"},
            {"type": "uint256", "name": "amount"},
            {"type": "bytes", "name": "params"},
            {"type": "uint16", "name": "referralCode"},
        ],
    },
    "0xa0712d68": {
        "name": "mint",
        "inputs": [{"type": "uint256", "name": "mintAmount"}],
    },
    "0xdb006a75": {
        "name": "redeem",
        "inputs": [{"type": "uint256", "name": "redeemTokens"}],
    },
    "0x852a12e3": {
        "name": "redeemUnderlying",
        "inputs": [{"type": "uint256", "name": "redeemAmount"}],
    },
    "0xc5ebeaec": {
        "name": "borrow",
        "inputs": [{"type": "uint256", "name": "borrowAmount"}],
    },
    "0x0e752702": {
        "name": "repayBorrow",
        "inputs": [{"type": "uint256", "name": "repayAmount"}],
    },
    "0x2608f818": {
        "name": "repayBorrowBehalf",
        "inputs": [
            {"type": "address", "name": "borrower"},
            {"type": "uint256", "name": "repayAmount"},
        ],
    },
    "0xf5e3c462": {
        "name": "liquidateBorrow",
        "inputs": [
            {"type": "address", "name": "borrower"},
            {"type": "uint256", "name": "repayAmount"},
            {"type": "address", "name": "cTokenCollateral"},
        ],
    },
    "0xbd6d894d": {
        "name": "exchangeRateCurrent",
        "inputs": [],
    },
    "0x182df0f5": {
        "name": "exchangeRateStored",
        "inputs": [],
    },
    "0x3af9e669": {
        "name": "balanceOfUnderlying",
        "inputs": [{"type": "address", "name": "owner"}],
    },
    "0x17bfdfbc": {
        "name": "borrowBalanceCurrent",
        "inputs": [{"type": "address", "name": "account"}],
    },
    "0x95dd9193": {
        "name": "borrowBalanceStored",
        "inputs": [{"type": "address", "name": "account"}],
    },
    "0x5fe3b567": {
        "name": "comptroller",
        "inputs": [],
    },
    "0x6f307dc3": {
        "name": "underlying",
        "inputs": [],
    },
    "0xf3fdb15a": {
        "name": "interestRateModel",
        "inputs": [],
    },
    "0x173b9904": {
        "name": "reserveFactorMantissa",
        "inputs": [],
    },
    "0x47bd3718": {
        "name": "totalBorrows",
        "inputs": [],
    },
    "0x8f840ddd": {
        "name": "totalReserves",
        "inputs": [],
    },
    "0xa694fc3a": {
        "name": "stake",
        "inputs": [{"type": "uint256", "name": "amount"}],
    },
    "0x2e1a7d4d": {
        "name": "withdraw",
        "inputs": [{"type": "uint256", "name": "amount"}],
    },
    "0x3d18b912": {
        "name": "getReward",
        "inputs": [],
    },
    "0x008cc262": {
        "name": "earned",
        "inputs": [{"type": "address", "name": "account"}],
    },
    "0x7b0a47ee": {
        "name": "rewardRate",
        "inputs": [],
    },
    "0x386a9525": {
        "name": "rewardsDuration",
        "inputs": [],
    },
    "0xebe2b12b": {
        "name": "periodFinish",
        "inputs": [],
    },
    "0x80faa57d": {
        "name": "lastTimeRewardApplicable",
        "inputs": [],
    },
    "0xcd3daf9d": {
        "name": "rewardPerToken",
        "inputs": [],
    },
    "0x0902f1ac": {
        "name": "getReserves",
        "inputs": [],
    },
    "0xb6b55f25": {
        "name": "deposit",
        "inputs": [{"type": "uint256", "name": "value"}],
    },
    "0x6e553f65": {
        "name": "deposit",
        "inputs": [
            {"type": "uint256", "name": "value"},
            {"type": "address", "name": "addr"},
        ],
    },
    "0x2e1a7d4d": {
        "name": "withdraw",
        "inputs": [{"type": "uint256", "name": "value"}],
    },
    "0x38d07436": {
        "name": "withdraw",
        "inputs": [
            {"type": "uint256", "name": "value"},
            {"type": "bool", "name": "claim_rewards"},
        ],
    },
    "0xe6f1daf2": {
        "name": "claim_rewards",
        "inputs": [],
    },
    "0x84e9bd7e": {
        "name": "claim_rewards",
        "inputs": [{"type": "address", "name": "addr"}],
    },
    "0x33134583": {
        "name": "claimable_tokens",
        "inputs": [{"type": "address", "name": "addr"}],
    },
    "0x33fd6f74": {
        "name": "claimable_reward",
        "inputs": [
            {"type": "address", "name": "addr"},
            {"type": "address", "name": "token"},
        ],
    },
    "0x54c49fe9": {
        "name": "reward_tokens",
        "inputs": [{"type": "uint256", "name": "i"}],
    },
    "0x01ddabf1": {
        "name": "rewards_receiver",
        "inputs": [{"type": "address", "name": "addr"}],
    },
    "0xbdf98116": {
        "name": "set_rewards_receiver",
        "inputs": [{"type": "address", "name": "addr"}],
    },
    "0x43a0d066": {
        "name": "deposit",
        "inputs": [
            {"type": "uint256", "name": "pid"},
            {"type": "uint256", "name": "amount"},
            {"type": "bool", "name": "stake"},
        ],
    },
    "0x60759fce": {
        "name": "depositAll",
        "inputs": [
            {"type": "uint256", "name": "pid"},
            {"type": "bool", "name": "stake"},
        ],
    },
    "0x441a3e70": {
        "name": "withdraw",
        "inputs": [
            {"type": "uint256", "name": "pid"},
            {"type": "uint256", "name": "amount"},
        ],
    },
    "0x958e2d31": {
        "name": "withdrawAll",
        "inputs": [{"type": "uint256", "name": "pid"}],
    },
    "0x008f33d7": {
        "name": "getReward",
        "inputs": [
            {"type": "uint256", "name": "pid"},
            {"type": "address", "name": "account"},
        ],
    },
    "0xcc956f3f": {
        "name": "earmarkRewards",
        "inputs": [{"type": "uint256", "name": "pid"}],
    },
    "0x1526fe27": {
        "name": "poolInfo",
        "inputs": [{"type": "uint256", "name": "pid"}],
    },
    "0x8dcb4061": {
        "name": "stakeAll",
        "inputs": [],
    },
    "0x2ee40908": {
        "name": "stakeFor",
        "inputs": [
            {"type": "address", "name": "for_"},
            {"type": "uint256", "name": "amount"},
        ],
    },
    "0x1c1c6fe5": {
        "name": "withdrawAll",
        "inputs": [{"type": "bool", "name": "claim"}],
    },
    "0x7050ccd9": {
        "name": "getReward",
        "inputs": [
            {"type": "address", "name": "account"},
            {"type": "bool", "name": "claimExtras"},
        ],
    },
    "0x40c35446": {
        "name": "extraRewards",
        "inputs": [{"type": "uint256", "name": "idx"}],
    },
    "0xd55a23f4": {
        "name": "extraRewardsLength",
        "inputs": [],
    },
    "0xf7c618c1": {
        "name": "rewardToken",
        "inputs": [],
    },
    "0xe9fad8ee": {
        "name": "exit",
        "inputs": [],
    },
    "0x51ed6a30": {
        "name": "stakeToken",
        "inputs": [],
    },
    "0xf851a440": {
        "name": "admin",
        "inputs": [],
    },
    "0x5c60da1b": {
        "name": "implementation",
        "inputs": [],
    },
    "0x8f283970": {
        "name": "changeAdmin",
        "inputs": [{"type": "address", "name": "newAdmin"}],
    },
    "0x3659cfe6": {
        "name": "upgradeTo",
        "inputs": [{"type": "address", "name": "newImplementation"}],
    },
    "0x4f1ef286": {
        "name": "upgradeToAndCall",
        "inputs": [
            {"type": "address", "name": "newImplementation"},
            {"type": "bytes", "name": "data"},
        ],
    },
    "0x52d1902d": {
        "name": "proxiableUUID",
        "inputs": [],
    },
    "0x59659e90": {
        "name": "beacon",
        "inputs": [],
    },
    "0x7a0ed627": {
        "name": "facets",
        "inputs": [],
    },
    "0xadfca15e": {
        "name": "facetFunctionSelectors",
        "inputs": [{"type": "address", "name": "facet"}],
    },
    "0x52ef6b2c": {
        "name": "facetAddresses",
        "inputs": [],
    },
    "0xcdffacc6": {
        "name": "facetAddress",
        "inputs": [{"type": "bytes4", "name": "selector"}],
    },
    "0x1f931c1c": {
        "name": "diamondCut",
        "inputs": [
            {"type": "tuple[]", "name": "_cut"},
            {"type": "address", "name": "_init"},
            {"type": "bytes", "name": "_calldata"},
        ],
    },
    "0x0dfe1681": {
        "name": "token0",
        "inputs": [],
    },
    "0xd21220a7": {
        "name": "token1",
        "inputs": [],
    },
    "0x7464fc3d": {
        "name": "kLast",
        "inputs": [],
    },
    "0x5909c0d5": {
        "name": "price0CumulativeLast",
        "inputs": [],
    },
    "0x5a3d5493": {
        "name": "price1CumulativeLast",
        "inputs": [],
    },
    "0x6a627842": {
        "name": "mint",
        "inputs": [{"type": "address", "name": "to"}],
    },
    "0x89afcb44": {
        "name": "burn",
        "inputs": [{"type": "address", "name": "to"}],
    },
    "0x022c0d9f": {
        "name": "swap",
        "inputs": [
            {"type": "uint256", "name": "amount0Out"},
            {"type": "uint256", "name": "amount1Out"},
            {"type": "address", "name": "to"},
            {"type": "bytes", "name": "data"},
        ],
    },
    "0xbc25cf77": {
        "name": "skim",
        "inputs": [{"type": "address", "name": "to"}],
    },
    "0xfff6cae9": {
        "name": "sync",
        "inputs": [],
    },
    "0xc45a0155": {
        "name": "factory",
        "inputs": [],
    },
    "0x485cc955": {
        "name": "initialize",
        "inputs": [
            {"type": "address", "name": "token0"},
            {"type": "address", "name": "token1"},
        ],
    },
    "0xe8e33700": {
        "name": "addLiquidity",
        "inputs": [
            {"type": "address", "name": "tokenA"},
            {"type": "address", "name": "tokenB"},
            {"type": "uint256", "name": "amountADesired"},
            {"type": "uint256", "name": "amountBDesired"},
            {"type": "uint256", "name": "amountAMin"},
            {"type": "uint256", "name": "amountBMin"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0xf305d719": {
        "name": "addLiquidityETH",
        "inputs": [
            {"type": "address", "name": "token"},
            {"type": "uint256", "name": "amountTokenDesired"},
            {"type": "uint256", "name": "amountTokenMin"},
            {"type": "uint256", "name": "amountETHMin"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0xbaa2abde": {
        "name": "removeLiquidity",
        "inputs": [
            {"type": "address", "name": "tokenA"},
            {"type": "address", "name": "tokenB"},
            {"type": "uint256", "name": "liquidity"},
            {"type": "uint256", "name": "amountAMin"},
            {"type": "uint256", "name": "amountBMin"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0x02751cec": {
        "name": "removeLiquidityETH",
        "inputs": [
            {"type": "address", "name": "token"},
            {"type": "uint256", "name": "liquidity"},
            {"type": "uint256", "name": "amountTokenMin"},
            {"type": "uint256", "name": "amountETHMin"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0x38ed1739": {
        "name": "swapExactTokensForTokens",
        "inputs": [
            {"type": "uint256", "name": "amountIn"},
            {"type": "uint256", "name": "amountOutMin"},
            {"type": "address[]", "name": "path"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0x8803dbee": {
        "name": "swapTokensForExactTokens",
        "inputs": [
            {"type": "uint256", "name": "amountOut"},
            {"type": "uint256", "name": "amountInMax"},
            {"type": "address[]", "name": "path"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0x7ff36ab5": {
        "name": "swapExactETHForTokens",
        "inputs": [
            {"type": "uint256", "name": "amountOutMin"},
            {"type": "address[]", "name": "path"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0x4a25d94a": {
        "name": "swapTokensForExactETH",
        "inputs": [
            {"type": "uint256", "name": "amountOut"},
            {"type": "uint256", "name": "amountInMax"},
            {"type": "address[]", "name": "path"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0x18cbafe5": {
        "name": "swapExactTokensForETH",
        "inputs": [
            {"type": "uint256", "name": "amountIn"},
            {"type": "uint256", "name": "amountOutMin"},
            {"type": "address[]", "name": "path"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0xfb3bdb41": {
        "name": "swapETHForExactTokens",
        "inputs": [
            {"type": "uint256", "name": "amountOut"},
            {"type": "address[]", "name": "path"},
            {"type": "address", "name": "to"},
            {"type": "uint256", "name": "deadline"},
        ],
    },
    "0xd06ca61f": {
        "name": "getAmountsOut",
        "inputs": [
            {"type": "uint256", "name": "amountIn"},
            {"type": "address[]", "name": "path"},
        ],
    },
    "0x1f00ca74": {
        "name": "getAmountsIn",
        "inputs": [
            {"type": "uint256", "name": "amountOut"},
            {"type": "address[]", "name": "path"},
        ],
    },
}


def abi_path():
    return cache_dir() / "abi_db.shelve"


def check_supplements():
    if not abi_path().is_file():
        compressed_supplements = Path(__file__).parent.parent / "data" / "abi_dump.xz"
        logger.info("Loading %s into %s...", compressed_supplements, abi_path())
        with lzma.open(compressed_supplements) as inf, shelve.open(
            str(abi_path())
        ) as out:
            for line in inf:
                line = json.loads(line)
                selector, abi = line["selector"], line["abi"]
                out[selector] = abi

        assert abi_path().is_file()

        logger.info("%s is ready.", abi_path())


@cached
def fetch_sig(hash) -> Optional[dict]:
    check_supplements()

    if type(hash) == str:
        hash = int(hash, 16)
    hash = "{:#010x}".format(hash)
    if hash in LOCAL_SIGS:
        return LOCAL_SIGS[hash]

    with shelve.open(str(abi_path())) as s:
        res = s.get(hash)
        if res:
            return res

    load_local_sigs_bulk()
    if hash in LOCAL_SIGS_BULK:
        return LOCAL_SIGS_BULK[hash]

    return None
def load_local_sigs_bulk():
    global LOCAL_SIGS_BULK
    if LOCAL_SIGS_BULK is not None:
        return
    try:
        if LOCAL_SIGS_BULK_PATH.is_file():
            LOCAL_SIGS_BULK = json.loads(
                LOCAL_SIGS_BULK_PATH.read_text(encoding="utf-8")
            )
        else:
            LOCAL_SIGS_BULK = {}
    except Exception:
        logger.exception("Failed to load local_sigs.json")
        LOCAL_SIGS_BULK = {}
