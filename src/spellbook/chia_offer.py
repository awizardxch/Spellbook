"""Native Chia offer construction, parsing, taking, and cancellation.

Implements the XCH-native offer protocol (the same construction as
chia-blockchain 2.5.2's ``chia.wallet.trading.offer`` / ``trade_manager``)
directly on top of :mod:`spellbook.chia_sign`'s local key derivation and
BLS signing, so Spellbook can make, take, and cancel XCH offers using only
the HTTPS relay for public coin state and broadcast — no Sage RPC
wallet required.

Pipeline (mirrors the reference wallet):

* **make** — select local XCH coins for the offered amount, compute the
  shared nonce (tree hash of the maker coin infos sorted by coin id),
  notarize the requested payments, build maker spends that pay the
  offered XCH to the settlement puzzle and assert the requested
  settlement announcements, sign locally.  The result is a standard
  bech32m offer string (off-chain; nothing is broadcast).
* **parse** — decode any offer string (ours or a third party's) into
  requested payments and maker spends.  Any leg whose driver is not
  native XCH (CAT / NFT / DID / unknown) fails closed with
  :exc:`OfferError` — such legs are never reinterpreted as XCH.
* **take** — re-derive the expected announcements from the maker's coin
  infos and requested payments and require every one to be asserted by
  the maker spends; build the reciprocal taker spends; add settlement
  completion spends; aggregate and sign locally.  The caller broadcasts
  the final bundle.
* **cancel** — build a spend of one of the offer's maker input coins
  back to the wallet.  Spending any single maker input on-chain
  invalidates the whole offer (secure cancellation).

Scope: **native XCH only**.  ``make_offer`` / ``take_offer`` /
``cancel_offer`` accept XCH inputs and XCH legs exclusively.  Parsing
identifies non-XCH legs only to refuse them.

Reference compatibility (verified byte-for-byte against
chia-blockchain 2.5.2):

* ``OFFER_MOD`` / ``OFFER_MOD_HASH`` — ``settlement_payments.clsp``.
* Compression zdict — identical entries and version-6 framing to
  ``chia.wallet.util.puzzle_compression`` (the CAT / NFT mod entries
  exist *only* as decompression dictionary entries so offers minted by
  other wallets still decompress; they are never executed here).
* Shared nonce — ``Program.to(sorted_coin_infos).get_tree_hash()``
  with coins sorted by ``Coin.name()`` (``notarize_payments``).
* Announcement message — ``Program.to((nonce, [payment.as_condition_args()
  ...])).get_tree_hash()`` (``calculate_announcements``).
* Offer identity — ``sha256`` of the canonical serialized bundle, i.e.
  ``SpendBundle.name()`` (``Offer.name()``).
* bech32m offer strings — identical output to the reference
  ``bech32_encode``.

Security notes (Spellbook policy, preserved by the daemon layer):

* Seeds and private keys never leave this module's caller — signing
  happens locally via :mod:`spellbook.chia_sign`.
* Offer taking and cancellation produce bundles for the caller to
  broadcast; broadcast itself (with txid-identity checks and
  unknown-fate handling) stays in the daemon's relay path.
* Every spend's coin record is checked against its puzzle reveal
  (``puzzle_hash == sha256tree(puzzle_reveal)``); a spend whose puzzle
  cannot be tied to its coin record is refused, so unsupported drivers
  can never classify as native XCH.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field

from . import chia_sign as cs


class OfferError(Exception):
    """Raised when an offer cannot be built, parsed, or taken natively."""


# ---------------------------------------------------------------------------
# Puzzle constants
# ---------------------------------------------------------------------------
#
# Compiled CLVM mods, byte-identical to chia-blockchain 2.5.2.  Only
# OFFER_MOD is ever executed here.  The CAT / NFT / legacy entries exist
# solely as the compression zdict (so offers minted by other wallets
# still decompress); CAT/NFT/DID construction is NOT implemented and
# any such leg fails closed at parse/build time.


OFFER_MOD = bytes.fromhex(
    "ff02ffff01ff02ff0affff04ff02ffff04ff03ff80808080ffff04ffff01ffff"
    "333effff02ffff03ff05ffff01ff04ffff04ff0cffff04ffff02ff1effff04ff"
    "02ffff04ff09ff80808080ff808080ffff02ff16ffff04ff02ffff04ff19ffff"
    "04ffff02ff0affff04ff02ffff04ff0dff80808080ff808080808080ff8080ff"
    "0180ffff02ffff03ff05ffff01ff02ffff03ffff15ff29ff8080ffff01ff04ff"
    "ff04ff08ff0980ffff02ff16ffff04ff02ffff04ff0dffff04ff0bff80808080"
    "8080ffff01ff088080ff0180ffff010b80ff0180ff02ffff03ffff07ff0580ff"
    "ff01ff0bffff0102ffff02ff1effff04ff02ffff04ff09ff80808080ffff02ff"
    "1effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101ff058080ff01"
    "80ff018080"
)

# --- decompression-dictionary entries only (never executed) -----------------
# CAT v2 mod (chia-blockchain 2.5.2 cat_v2.clsp).
CAT_MOD = bytes.fromhex(
    "ff02ffff01ff02ff5effff04ff02ffff04ffff04ff05ffff04ffff0bff34ff05"
    "80ffff04ff0bff80808080ffff04ffff02ff17ff2f80ffff04ff5fffff04ffff"
    "02ff2effff04ff02ffff04ff17ff80808080ffff04ffff02ff2affff04ff02ff"
    "ff04ff82027fffff04ff82057fffff04ff820b7fff808080808080ffff04ff81"
    "bfffff04ff82017fffff04ff8202ffffff04ff8205ffffff04ff820bffff8080"
    "8080808080808080808080ffff04ffff01ffffffff3d46ff02ff333cffff0401"
    "ff01ff81cb02ffffff20ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04"
    "ff0dffff04ffff0bff7cffff0bff34ff2480ffff0bff7cffff0bff7cffff0bff"
    "34ff2c80ff0980ffff0bff7cff0bffff0bff34ff8080808080ff8080808080ff"
    "ff010b80ff0180ffff02ffff03ffff22ffff09ffff0dff0580ff2280ffff09ff"
    "ff0dff0b80ff2280ffff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780"
    "ffff01ff088080ff0180ffff02ffff03ff0bffff01ff02ffff03ffff09ffff02"
    "ff2effff04ff02ffff04ff13ff80808080ff820b9f80ffff01ff02ff56ffff04"
    "ff02ffff04ffff02ff13ffff04ff5fffff04ff17ffff04ff2fffff04ff81bfff"
    "ff04ff82017fffff04ff1bff8080808080808080ffff04ff82017fff80808080"
    "80ffff01ff088080ff0180ffff01ff02ffff03ff17ffff01ff02ffff03ffff20"
    "ff81bf80ffff0182017fffff01ff088080ff0180ffff01ff088080ff018080ff"
    "0180ff04ffff04ff05ff2780ffff04ffff10ff0bff5780ff778080ffffff02ff"
    "ff03ff05ffff01ff02ffff03ffff09ffff02ffff03ffff09ff11ff5880ffff01"
    "59ff8080ff0180ffff01818f80ffff01ff02ff26ffff04ff02ffff04ff0dffff"
    "04ff0bffff04ffff04ff81b9ff82017980ff808080808080ffff01ff02ff7aff"
    "ff04ff02ffff04ffff02ffff03ffff09ff11ff5880ffff01ff04ff58ffff04ff"
    "ff02ff76ffff04ff02ffff04ff13ffff04ff29ffff04ffff0bff34ff5b80ffff"
    "04ff2bff80808080808080ff398080ffff01ff02ffff03ffff09ff11ff7880ff"
    "ff01ff02ffff03ffff20ffff02ffff03ffff09ffff0121ffff0dff298080ffff"
    "01ff02ffff03ffff09ffff0cff29ff80ff3480ff5c80ffff01ff0101ff8080ff"
    "0180ff8080ff018080ffff0109ffff01ff088080ff0180ffff010980ff018080"
    "ff0180ffff04ffff02ffff03ffff09ff11ff5880ffff0159ff8080ff0180ffff"
    "04ffff02ff26ffff04ff02ffff04ff0dffff04ff0bffff04ff17ff8080808080"
    "80ff80808080808080ff0180ffff01ff04ff80ffff04ff80ff17808080ff0180"
    "ffff02ffff03ff05ffff01ff04ff09ffff02ff56ffff04ff02ffff04ff0dffff"
    "04ff0bff808080808080ffff010b80ff0180ff0bff7cffff0bff34ff2880ffff"
    "0bff7cffff0bff7cffff0bff34ff2c80ff0580ffff0bff7cffff02ff32ffff04"
    "ff02ffff04ff07ffff04ffff0bff34ff3480ff8080808080ffff0bff34ff8080"
    "808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04"
    "ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff80808080"
    "80ffff01ff0bffff0101ff058080ff0180ffff04ffff04ff30ffff04ff5fff80"
    "8080ffff02ff7effff04ff02ffff04ffff04ffff04ff2fff0580ffff04ff5fff"
    "82017f8080ffff04ffff02ff26ffff04ff02ffff04ff0bffff04ff05ffff01ff"
    "808080808080ffff04ff17ffff04ff81bfffff04ff82017fffff04ffff02ff2a"
    "ffff04ff02ffff04ff8204ffffff04ffff02ff76ffff04ff02ffff04ff09ffff"
    "04ff820affffff04ffff0bff34ff2d80ffff04ff15ff80808080808080ffff04"
    "ff8216ffff808080808080ffff04ff8205ffffff04ff820bffff808080808080"
    "808080808080ff02ff5affff04ff02ffff04ff5fffff04ff3bffff04ffff02ff"
    "ff03ff17ffff01ff09ff2dffff02ff2affff04ff02ffff04ff27ffff04ffff02"
    "ff76ffff04ff02ffff04ff29ffff04ff57ffff04ffff0bff34ff81b980ffff04"
    "ff59ff80808080808080ffff04ff81b7ff80808080808080ff8080ff0180ffff"
    "04ff17ffff04ff05ffff04ff8202ffffff04ffff04ffff04ff78ffff04ffff0e"
    "ff5cffff02ff2effff04ff02ffff04ffff04ff2fffff04ff82017fff808080ff"
    "8080808080ff808080ffff04ffff04ff20ffff04ffff0bff81bfff5cffff02ff"
    "2effff04ff02ffff04ffff04ff15ffff04ffff10ff82017fffff11ff8202dfff"
    "2b80ff8202ff80ff808080ff8080808080ff808080ff138080ff808080808080"
    "80808080ff018080"
)


SINGLETON_TOP_LAYER_MOD = bytes.fromhex(
    "ff02ffff01ff02ffff03ffff18ff2fff3480ffff01ff04ffff04ff20ffff04ff"
    "2fff808080ffff04ffff02ff3effff04ff02ffff04ff05ffff04ffff02ff2aff"
    "ff04ff02ffff04ff27ffff04ffff02ffff03ff77ffff01ff02ff36ffff04ff02"
    "ffff04ff09ffff04ff57ffff04ffff02ff2effff04ff02ffff04ff05ff808080"
    "80ff808080808080ffff011d80ff0180ffff04ffff02ffff03ff77ffff0181b7"
    "ffff015780ff0180ff808080808080ffff04ff77ff808080808080ffff02ff3a"
    "ffff04ff02ffff04ff05ffff04ffff02ff0bff5f80ffff01ff80808080808080"
    "80ffff01ff088080ff0180ffff04ffff01ffffffff4947ff0233ffff0401ff01"
    "02ffffff20ff02ffff03ff05ffff01ff02ff32ffff04ff02ffff04ff0dffff04"
    "ffff0bff3cffff0bff34ff2480ffff0bff3cffff0bff3cffff0bff34ff2c80ff"
    "0980ffff0bff3cff0bffff0bff34ff8080808080ff8080808080ffff010b80ff"
    "0180ffff02ffff03ffff22ffff09ffff0dff0580ff2280ffff09ffff0dff0b80"
    "ff2280ffff15ff17ffff0181ff8080ffff01ff0bff05ff0bff1780ffff01ff08"
    "8080ff0180ff02ffff03ff0bffff01ff02ffff03ffff02ff26ffff04ff02ffff"
    "04ff13ff80808080ffff01ff02ffff03ffff20ff1780ffff01ff02ffff03ffff"
    "09ff81b3ffff01818f80ffff01ff02ff3affff04ff02ffff04ff05ffff04ff1b"
    "ffff04ff34ff808080808080ffff01ff04ffff04ff23ffff04ffff02ff36ffff"
    "04ff02ffff04ff09ffff04ff53ffff04ffff02ff2effff04ff02ffff04ff05ff"
    "80808080ff808080808080ff738080ffff02ff3affff04ff02ffff04ff05ffff"
    "04ff1bffff04ff34ff8080808080808080ff0180ffff01ff088080ff0180ffff"
    "01ff04ff13ffff02ff3affff04ff02ffff04ff05ffff04ff1bffff04ff17ff80"
    "80808080808080ff0180ffff01ff02ffff03ff17ff80ffff01ff088080ff0180"
    "80ff0180ffffff02ffff03ffff09ff09ff3880ffff01ff02ffff03ffff18ff2d"
    "ffff010180ffff01ff0101ff8080ff0180ff8080ff0180ff0bff3cffff0bff34"
    "ff2880ffff0bff3cffff0bff3cffff0bff34ff2c80ff0580ffff0bff3cffff02"
    "ff32ffff04ff02ffff04ff07ffff04ffff0bff34ff3480ff8080808080ffff0b"
    "ff34ff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02"
    "ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff0d"
    "ff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ffff21ff17"
    "ffff09ff0bff158080ffff01ff04ff30ffff04ff0bff808080ffff01ff088080"
    "ff0180ff018080"
)


NFT_STATE_LAYER_MOD = bytes.fromhex(
    "ff02ffff01ff02ff3effff04ff02ffff04ff05ffff04ffff02ff2fff5f80ffff"
    "04ff80ffff04ffff04ffff04ff0bffff04ff17ff808080ffff01ff808080ffff"
    "01ff8080808080808080ffff04ffff01ffffff0233ff04ff0101ffff02ff02ff"
    "ff03ff05ffff01ff02ff1affff04ff02ffff04ff0dffff04ffff0bff12ffff0b"
    "ff2cff1480ffff0bff12ffff0bff12ffff0bff2cff3c80ff0980ffff0bff12ff"
    "0bffff0bff2cff8080808080ff8080808080ffff010b80ff0180ffff0bff12ff"
    "ff0bff2cff1080ffff0bff12ffff0bff12ffff0bff2cff3c80ff0580ffff0bff"
    "12ffff02ff1affff04ff02ffff04ff07ffff04ffff0bff2cff2c80ff80808080"
    "80ffff0bff2cff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff01"
    "02ffff02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ff"
    "ff04ff0dff8080808080ffff01ff0bffff0101ff058080ff0180ff02ffff03ff"
    "0bffff01ff02ffff03ffff09ff23ff1880ffff01ff02ffff03ffff18ff81b3ff"
    "2c80ffff01ff02ffff03ffff20ff1780ffff01ff02ff3effff04ff02ffff04ff"
    "05ffff04ff1bffff04ff33ffff04ff2fffff04ff5fff8080808080808080ffff"
    "01ff088080ff0180ffff01ff04ff13ffff02ff3effff04ff02ffff04ff05ffff"
    "04ff1bffff04ff17ffff04ff2fffff04ff5fff80808080808080808080ff0180"
    "ffff01ff02ffff03ffff09ff23ffff0181e880ffff01ff02ff3effff04ff02ff"
    "ff04ff05ffff04ff1bffff04ff17ffff04ffff02ffff03ffff22ffff09ffff02"
    "ff2effff04ff02ffff04ff53ff80808080ff82014f80ffff20ff5f8080ffff01"
    "ff02ff53ffff04ff818fffff04ff82014fffff04ff81b3ff8080808080ffff01"
    "ff088080ff0180ffff04ff2cff8080808080808080ffff01ff04ff13ffff02ff"
    "3effff04ff02ffff04ff05ffff04ff1bffff04ff17ffff04ff2fffff04ff5fff"
    "80808080808080808080ff018080ff0180ffff01ff04ffff04ff18ffff04ffff"
    "02ff16ffff04ff02ffff04ff05ffff04ff27ffff04ffff0bff2cff82014f80ff"
    "ff04ffff02ff2effff04ff02ffff04ff818fff80808080ffff04ffff0bff2cff"
    "0580ff8080808080808080ff378080ff81af8080ff0180ff018080"
)


NFT_OWNERSHIP_LAYER = bytes.fromhex(
    "ff02ffff01ff02ff26ffff04ff02ffff04ff05ffff04ff17ffff04ff0bffff04"
    "ffff02ff2fff5f80ff80808080808080ffff04ffff01ffffff82ad4cff0233ff"
    "ff3e04ff81f601ffffff0102ffff02ffff03ff05ffff01ff02ff2affff04ff02"
    "ffff04ff0dffff04ffff0bff32ffff0bff3cff3480ffff0bff32ffff0bff32ff"
    "ff0bff3cff2280ff0980ffff0bff32ff0bffff0bff3cff8080808080ff808080"
    "8080ffff010b80ff0180ff04ffff04ff38ffff04ffff02ff36ffff04ff02ffff"
    "04ff05ffff04ff27ffff04ffff02ff2effff04ff02ffff04ffff02ffff03ff81"
    "afffff0181afffff010b80ff0180ff80808080ffff04ffff0bff3cff4f80ffff"
    "04ffff0bff3cff0580ff8080808080808080ff378080ff82016f80ffffff02ff"
    "3effff04ff02ffff04ff05ffff04ff0bffff04ff17ffff04ff2fffff04ff2fff"
    "ff01ff80ff808080808080808080ff0bff32ffff0bff3cff2880ffff0bff32ff"
    "ff0bff32ffff0bff3cff2280ff0580ffff0bff32ffff02ff2affff04ff02ffff"
    "04ff07ffff04ffff0bff3cff3c80ff8080808080ffff0bff3cff8080808080ff"
    "ff02ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff2effff04ff02ffff"
    "04ff09ff80808080ffff02ff2effff04ff02ffff04ff0dff8080808080ffff01"
    "ff0bffff0101ff058080ff0180ff02ffff03ff5fffff01ff02ffff03ffff09ff"
    "82011fff3880ffff01ff02ffff03ffff09ffff18ff82059f80ff3c80ffff01ff"
    "02ffff03ffff20ff81bf80ffff01ff02ff3effff04ff02ffff04ff05ffff04ff"
    "0bffff04ff17ffff04ff2fffff04ff81dfffff04ff82019fffff04ff82017fff"
    "80808080808080808080ffff01ff088080ff0180ffff01ff04ff819fffff02ff"
    "3effff04ff02ffff04ff05ffff04ff0bffff04ff17ffff04ff2fffff04ff81df"
    "ffff04ff81bfffff04ff82017fff808080808080808080808080ff0180ffff01"
    "ff02ffff03ffff09ff82011fff2c80ffff01ff02ffff03ffff20ff82017f80ff"
    "ff01ff04ffff04ff24ffff04ffff0eff10ffff02ff2effff04ff02ffff04ff82"
    "019fff8080808080ff808080ffff02ff3effff04ff02ffff04ff05ffff04ff0b"
    "ffff04ff17ffff04ff2fffff04ff81dfffff04ff81bfffff04ffff02ff0bffff"
    "04ff17ffff04ff2fffff04ff82019fff8080808080ff80808080808080808080"
    "80ffff01ff088080ff0180ffff01ff02ffff03ffff09ff82011fff2480ffff01"
    "ff02ffff03ffff20ffff02ffff03ffff09ffff0122ffff0dff82029f8080ffff"
    "01ff02ffff03ffff09ffff0cff82029fff80ffff010280ff1080ffff01ff0101"
    "ff8080ff0180ff8080ff018080ffff01ff04ff819fffff02ff3effff04ff02ff"
    "ff04ff05ffff04ff0bffff04ff17ffff04ff2fffff04ff81dfffff04ff81bfff"
    "ff04ff82017fff8080808080808080808080ffff01ff088080ff0180ffff01ff"
    "04ff819fffff02ff3effff04ff02ffff04ff05ffff04ff0bffff04ff17ffff04"
    "ff2fffff04ff81dfffff04ff81bfffff04ff82017fff80808080808080808080"
    "8080ff018080ff018080ff0180ffff01ff02ff3affff04ff02ffff04ff05ffff"
    "04ff0bffff04ff81bfffff04ffff02ffff03ff82017fffff0182017fffff01ff"
    "02ff0bffff04ff17ffff04ff2fffff01ff808080808080ff0180ff8080808080"
    "808080ff0180ff018080"
)


NFT_METADATA_UPDATER = bytes.fromhex(
    "ff02ffff01ff04ffff04ffff02ffff03ffff22ff27ff3780ffff01ff02ffff03"
    "ffff21ffff09ff27ffff01826d7580ffff09ff27ffff01826c7580ffff09ff27"
    "ffff01758080ffff01ff02ff02ffff04ff02ffff04ff05ffff04ff27ffff04ff"
    "37ff808080808080ffff010580ff0180ffff010580ff0180ffff04ff0bff8080"
    "80ffff01ff808080ffff04ffff01ff02ffff03ff05ffff01ff02ffff03ffff09"
    "ff11ff0b80ffff01ff04ffff04ff0bffff04ff17ff198080ff0d80ffff01ff04"
    "ff09ffff02ff02ffff04ff02ffff04ff0dffff04ff0bffff04ff17ff80808080"
    "80808080ff0180ff8080ff0180ff018080"
)


NFT_TRANSFER_PROGRAM_DEFAULT = bytes.fromhex(
    "ff02ffff01ff02ffff03ff81bfffff01ff04ff82013fffff04ff80ffff04ffff"
    "02ffff03ffff22ff82013fffff20ffff09ff82013fff2f808080ffff01ff04ff"
    "ff04ff10ffff04ffff0bffff02ff2effff04ff02ffff04ff09ffff04ff8205bf"
    "ffff04ffff02ff3effff04ff02ffff04ffff04ff09ffff04ff82013fff1d8080"
    "ff80808080ff808080808080ff1580ff808080ffff02ff16ffff04ff02ffff04"
    "ff0bffff04ff17ffff04ff8202bfffff04ff15ff8080808080808080ffff01ff"
    "02ff16ffff04ff02ffff04ff0bffff04ff17ffff04ff8202bfffff04ff15ff80"
    "80808080808080ff0180ff80808080ffff01ff04ff2fffff01ff80ff80808080"
    "ff0180ffff04ffff01ffffff3f02ff04ff0101ffff822710ff02ff02ffff03ff"
    "05ffff01ff02ff3affff04ff02ffff04ff0dffff04ffff0bff2affff0bff2cff"
    "1480ffff0bff2affff0bff2affff0bff2cff3c80ff0980ffff0bff2aff0bffff"
    "0bff2cff8080808080ff8080808080ffff010b80ff0180ffff02ffff03ff17ff"
    "ff01ff04ffff04ff10ffff04ffff0bff81a7ffff02ff3effff04ff02ffff04ff"
    "ff04ff2fffff04ffff04ff05ffff04ffff05ffff14ffff12ff47ff0b80ff1280"
    "80ffff04ffff04ff05ff8080ff80808080ff808080ff8080808080ff808080ff"
    "ff02ff16ffff04ff02ffff04ff05ffff04ff0bffff04ff37ffff04ff2fff8080"
    "808080808080ff8080ff0180ffff0bff2affff0bff2cff1880ffff0bff2affff"
    "0bff2affff0bff2cff3c80ff0580ffff0bff2affff02ff3affff04ff02ffff04"
    "ff07ffff04ffff0bff2cff2c80ff8080808080ffff0bff2cff8080808080ff02"
    "ffff03ffff07ff0580ffff01ff0bffff0102ffff02ff3effff04ff02ffff04ff"
    "09ff80808080ffff02ff3effff04ff02ffff04ff0dff8080808080ffff01ff0b"
    "ffff0101ff058080ff0180ff018080"
)


LEGACY_CAT_MOD = bytes.fromhex(
    "ff02ffff01ff02ff5effff04ff02ffff04ffff04ff05ffff04ffff0bff2cff05"
    "80ffff04ff0bff80808080ffff04ffff02ff17ff2f80ffff04ff5fffff04ffff"
    "02ff2effff04ff02ffff04ff17ff80808080ffff04ffff0bff82027fff82057f"
    "ff820b7f80ffff04ff81bfffff04ff82017fffff04ff8202ffffff04ff8205ff"
    "ffff04ff820bffff80808080808080808080808080ffff04ffff01ffffffff81"
    "ca3dff46ff0233ffff3c04ff01ff0181cbffffff02ff02ffff03ff05ffff01ff"
    "02ff32ffff04ff02ffff04ff0dffff04ffff0bff22ffff0bff2cff3480ffff0b"
    "ff22ffff0bff22ffff0bff2cff5c80ff0980ffff0bff22ff0bffff0bff2cff80"
    "80808080ff8080808080ffff010b80ff0180ffff02ffff03ff0bffff01ff02ff"
    "ff03ffff09ffff02ff2effff04ff02ffff04ff13ff80808080ff820b9f80ffff"
    "01ff02ff26ffff04ff02ffff04ffff02ff13ffff04ff5fffff04ff17ffff04ff"
    "2fffff04ff81bfffff04ff82017fffff04ff1bff8080808080808080ffff04ff"
    "82017fff8080808080ffff01ff088080ff0180ffff01ff02ffff03ff17ffff01"
    "ff02ffff03ffff20ff81bf80ffff0182017fffff01ff088080ff0180ffff01ff"
    "088080ff018080ff0180ffff04ffff04ff05ff2780ffff04ffff10ff0bff5780"
    "ff778080ff02ffff03ff05ffff01ff02ffff03ffff09ffff02ffff03ffff09ff"
    "11ff7880ffff0159ff8080ff0180ffff01818f80ffff01ff02ff7affff04ff02"
    "ffff04ff0dffff04ff0bffff04ffff04ff81b9ff82017980ff808080808080ff"
    "ff01ff02ff5affff04ff02ffff04ffff02ffff03ffff09ff11ff7880ffff01ff"
    "04ff78ffff04ffff02ff36ffff04ff02ffff04ff13ffff04ff29ffff04ffff0b"
    "ff2cff5b80ffff04ff2bff80808080808080ff398080ffff01ff02ffff03ffff"
    "09ff11ff2480ffff01ff04ff24ffff04ffff0bff20ff2980ff398080ffff0109"
    "80ff018080ff0180ffff04ffff02ffff03ffff09ff11ff7880ffff0159ff8080"
    "ff0180ffff04ffff02ff7affff04ff02ffff04ff0dffff04ff0bffff04ff17ff"
    "808080808080ff80808080808080ff0180ffff01ff04ff80ffff04ff80ff1780"
    "8080ff0180ffffff02ffff03ff05ffff01ff04ff09ffff02ff26ffff04ff02ff"
    "ff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff0bff22ffff0bff"
    "2cff5880ffff0bff22ffff0bff22ffff0bff2cff5c80ff0580ffff0bff22ffff"
    "02ff32ffff04ff02ffff04ff07ffff04ffff0bff2cff2c80ff8080808080ffff"
    "0bff2cff8080808080ffff02ffff03ffff07ff0580ffff01ff0bffff0102ffff"
    "02ff2effff04ff02ffff04ff09ff80808080ffff02ff2effff04ff02ffff04ff"
    "0dff8080808080ffff01ff0bff2cff058080ff0180ffff04ffff04ff28ffff04"
    "ff5fff808080ffff02ff7effff04ff02ffff04ffff04ffff04ff2fff0580ffff"
    "04ff5fff82017f8080ffff04ffff02ff7affff04ff02ffff04ff0bffff04ff05"
    "ffff01ff808080808080ffff04ff17ffff04ff81bfffff04ff82017fffff04ff"
    "ff0bff8204ffffff02ff36ffff04ff02ffff04ff09ffff04ff820affffff04ff"
    "ff0bff2cff2d80ffff04ff15ff80808080808080ff8216ff80ffff04ff8205ff"
    "ffff04ff820bffff808080808080808080808080ff02ff2affff04ff02ffff04"
    "ff5fffff04ff3bffff04ffff02ffff03ff17ffff01ff09ff2dffff0bff27ffff"
    "02ff36ffff04ff02ffff04ff29ffff04ff57ffff04ffff0bff2cff81b980ffff"
    "04ff59ff80808080808080ff81b78080ff8080ff0180ffff04ff17ffff04ff05"
    "ffff04ff8202ffffff04ffff04ffff04ff24ffff04ffff0bff7cff2fff82017f"
    "80ff808080ffff04ffff04ff30ffff04ffff0bff81bfffff0bff7cff15ffff10"
    "ff82017fffff11ff8202dfff2b80ff8202ff808080ff808080ff138080ff8080"
    "8080808080808080ff018080"
)


OFFER_MOD_OLD = bytes.fromhex(
    "ff02ffff01ff02ff0affff04ff02ffff04ff03ff80808080ffff04ffff01ffff"
    "333effff02ffff03ff05ffff01ff04ffff04ff0cffff04ffff02ff1effff04ff"
    "02ffff04ff09ff80808080ff808080ffff02ff16ffff04ff02ffff04ff19ffff"
    "04ffff02ff0affff04ff02ffff04ff0dff80808080ff808080808080ff8080ff"
    "0180ffff02ffff03ff05ffff01ff04ffff04ff08ff0980ffff02ff16ffff04ff"
    "02ffff04ff0dffff04ff0bff808080808080ffff010b80ff0180ff02ffff03ff"
    "ff07ff0580ffff01ff0bffff0102ffff02ff1effff04ff02ffff04ff09ff8080"
    "8080ffff02ff1effff04ff02ffff04ff0dff8080808080ffff01ff0bffff0101"
    "ff058080ff0180ff018080"
)

OFFER_MOD_HASH = cs.sha256tree(cs.deser(OFFER_MOD))

# Compression zdict, mirroring chia.wallet.util.puzzle_compression.ZDICT
# (entries are concatenated for versions 1..6; our offers always use
# version 6, the highest, matching the reference wallet).
_ZDICT_ENTRIES = (
    cs.P2_DELEGATED_PUZZLE_OR_HIDDEN_PUZZLE + LEGACY_CAT_MOD,
    OFFER_MOD_OLD,
    SINGLETON_TOP_LAYER_MOD
    + NFT_STATE_LAYER_MOD
    + NFT_OWNERSHIP_LAYER
    + NFT_METADATA_UPDATER
    + NFT_TRANSFER_PROGRAM_DEFAULT,
    CAT_MOD,
    OFFER_MOD,
    b"",  # version 6 sentinel: intentionally breaks older-version parsing
)
_COMPRESSION_VERSION = 6


def _zdict_for_version(version: int) -> bytes:
    if not 1 <= version <= len(_ZDICT_ENTRIES):
        raise OfferError(f"bad offer compression version {version}")
    return b"".join(_ZDICT_ENTRIES[:version])


def compress_offer(bundle_bytes: bytes) -> bytes:
    """zlib-compress a serialized offer bundle with the puzzle zdict."""
    zdict = _zdict_for_version(_COMPRESSION_VERSION)
    comp = zlib.compressobj(zdict=zdict)
    return (
        _COMPRESSION_VERSION.to_bytes(2, "big")
        + comp.compress(bundle_bytes)
        + comp.flush()
    )


def decompress_offer(blob: bytes) -> bytes:
    """Inverse of :func:`compress_offer`; strictly rejects garbage.

    Raises OfferError on truncated input, trailing bytes after the zlib
    stream, unknown versions, and oversized output (> 6 MiB, the
    reference cap).
    """
    if len(blob) < 2:
        raise OfferError("offer blob too short")
    version = int.from_bytes(blob[:2], "big")
    if version > len(_ZDICT_ENTRIES):
        raise OfferError(
            f"offer compressed with version {version} — update software and try again"
        )
    try:
        do = zlib.decompressobj(zdict=_zdict_for_version(version))
        out = do.decompress(blob[2:], max_length=6 * 1024 * 1024)
    except Exception as e:
        raise OfferError(f"offer decompression failed: {e}") from e
    if not do.eof:
        raise OfferError("offer blob is truncated")
    if do.unused_data:
        raise OfferError("trailing bytes after offer blob")
    return out


# ---------------------------------------------------------------------------
# CLVM struct helpers
# ---------------------------------------------------------------------------

# Condition opcodes we parse (chia/wallet/util/condition_tools / condition_codes).
_CREATE_COIN = 51
_RESERVE_FEE = 52
_CREATE_PUZZLE_ANNOUNCEMENT = 62
_ASSERT_PUZZLE_ANNOUNCEMENT = 63

_ZERO32 = bytes(32)


def _sexpr_as_list(sexpr) -> list:
    """Walk a CLVM proper list into a Python list; raises OfferError."""
    out = []
    cur = sexpr
    while isinstance(cur, tuple):
        out.append(cur[0])
        cur = cur[1]
    if cur != b"":
        raise OfferError("expected a proper CLVM list")
    return out


def _atom_int(atom: bytes) -> int:
    if not isinstance(atom, bytes):
        raise OfferError("expected an atom")
    return int.from_bytes(atom, "big", signed=True) if atom else 0


def parse_standard_solution(solution: bytes) -> list | None:
    """Parse a standard-puzzle solution into its condition s-exprs.

    The standard solution is ``(None, (q . conditions), ())``.  Returns
    the list of condition s-exprs, or None when the shape does not match.
    """
    try:
        sexpr = cs.deser(solution)
        items = _sexpr_as_list(sexpr)
        if len(items) != 3 or items[0] != b"" or items[2] != b"":
            return None
        quoted = items[1]
        if not (isinstance(quoted, tuple) and quoted[0] == b"\x01"):
            return None
        return _sexpr_as_list(quoted[1])
    except OfferError:
        return None


def parse_conditions(solution: bytes) -> list:
    """Parse a spend's condition s-exprs.

    Only the standard-puzzle solution shape is accepted.  Anything else
    — CAT rings, NFT singletons, DIDs, unknown drivers — fails closed
    with OfferError instead of being misread as XCH.
    """
    conds = parse_standard_solution(solution)
    if conds is None:
        raise OfferError(
            "unsupported spend driver (not a standard XCH solution) — refusing"
        )
    return conds


def _condition_args(cond) -> tuple[int, list]:
    items = _sexpr_as_list(cond)
    if not items or not isinstance(items[0], bytes):
        raise OfferError("bad condition")
    return _atom_int(items[0]), items[1:]


def create_coin_outputs(conditions: list) -> list[tuple[bytes, int]]:
    """(puzzle_hash, amount) for every CREATE_COIN condition."""
    out = []
    for cond in conditions:
        opcode, args = _condition_args(cond)
        if opcode == _CREATE_COIN:
            if len(args) < 2:
                raise OfferError("bad CREATE_COIN condition")
            ph = args[0]
            if not isinstance(ph, bytes) or len(ph) != 32:
                raise OfferError("bad CREATE_COIN puzzle hash")
            out.append((ph, _atom_int(args[1])))
    return out


def asserted_puzzle_announcements(conditions: list) -> list[bytes]:
    """Announcement ids asserted by ASSERT_PUZZLE_ANNOUNCEMENT conditions.

    Each condition carries a single argument: the announcement id
    ``sha256(puzzle_hash + message)``.  Returns the list of ids.
    """
    out = []
    for cond in conditions:
        opcode, args = _condition_args(cond)
        if opcode == _ASSERT_PUZZLE_ANNOUNCEMENT:
            if len(args) != 1 or not isinstance(args[0], bytes) or len(args[0]) != 32:
                raise OfferError("bad ASSERT_PUZZLE_ANNOUNCEMENT condition")
            out.append(args[0])
    return out


def conditions_of_spend(spend: "CoinSpend") -> list:
    """Condition s-exprs of a spend (standard XCH shape only)."""
    return parse_conditions(spend.solution)


def assert_announcements_of_spends(spends: list["CoinSpend"]) -> set[bytes]:
    """Announcement ids asserted across spends."""
    out: set[bytes] = set()
    for spend in spends:
        out.update(asserted_puzzle_announcements(conditions_of_spend(spend)))
    return out


# ---------------------------------------------------------------------------
# SpendBundle (de)serialization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Coin:
    parent_coin_info: bytes
    puzzle_hash: bytes
    amount: int

    def coin_id(self) -> bytes:
        return cs.coin_id(self.parent_coin_info, self.puzzle_hash, self.amount)

    def as_list(self) -> list:
        return [self.parent_coin_info, self.puzzle_hash, self.amount]


@dataclass(frozen=True)
class CoinSpend:
    coin: Coin
    puzzle_reveal: bytes
    solution: bytes


def parse_solutions_bundle(data: bytes) -> tuple[list[CoinSpend], bytes]:
    """Parse a serialized SpendBundle into CoinSpends + 96-byte signature.

    Strict: every coin record's puzzle hash must equal the tree hash of
    its puzzle reveal, and no trailing bytes are allowed.  A spend whose
    puzzle cannot be tied to its coin record is refused — unsupported
    drivers can never classify as native XCH.
    """
    if len(data) < 4 + 96:
        raise OfferError("spend bundle too short")
    (count,) = struct.unpack(">I", data[:4])
    pos = 4
    spends: list[CoinSpend] = []
    for _ in range(count):
        if len(data) < pos + 72:
            raise OfferError("truncated coin in spend bundle")
        parent = data[pos : pos + 32]
        puzzle_hash = data[pos + 32 : pos + 64]
        (amount,) = struct.unpack(">Q", data[pos + 64 : pos + 72])
        pos += 72
        # Puzzle reveal and solution are bare self-delimiting CLVM programs.
        try:
            _, reveal_end = cs.deser_partial(data, pos)
            reveal = data[pos:reveal_end]
            _, solution_end = cs.deser_partial(data, reveal_end)
            solution = data[reveal_end:solution_end]
        except Exception as e:
            raise OfferError(f"bad program in bundle: {e}") from e
        pos = solution_end
        try:
            reveal_hash = cs.sha256tree(cs.deser(reveal))
        except Exception as e:
            raise OfferError(f"bad puzzle reveal in bundle: {e}") from e
        if reveal_hash != puzzle_hash:
            raise OfferError(
                "spend puzzle reveal does not match its coin record — refusing"
            )
        spends.append(
            CoinSpend(Coin(parent, puzzle_hash, amount), reveal, solution)
        )
    if len(data) != pos + 96:
        raise OfferError("trailing bytes in spend bundle")
    return spends, data[pos : pos + 96]


def serialize_bundle(spends: list[CoinSpend], signature: bytes) -> bytes:
    """Serialize CoinSpends + aggregated signature (== cs.spend_bundle_bytes)."""
    if len(signature) != 96:
        raise OfferError("aggregated signature must be 96 bytes")
    try:
        return cs.spend_bundle_bytes(
            [
                cs.coin_spend_bytes(
                    (s.coin.parent_coin_info, s.coin.puzzle_hash, s.coin.amount),
                    s.puzzle_reveal,
                    s.solution,
                )
                for s in spends
            ],
            signature,
        )
    except Exception as e:
        raise OfferError(f"cannot serialize bundle: {e}") from e


def offer_id_for_bundle(bundle_bytes: bytes) -> str:
    """Stable offer id: sha256 of the canonical (dummy-inclusive) bundle.

    This is exactly the reference wallet's ``Offer.name()`` — i.e.
    ``SpendBundle.name()``.
    """
    return hashlib.sha256(bundle_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Offer parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Payment:
    """A requested payment: (puzzle_hash, amount, memos)."""

    puzzle_hash: bytes
    amount: int
    memos: list[bytes] = field(default_factory=list)

    def as_condition_args(self) -> list:
        return [self.puzzle_hash, self.amount, self.memos]


@dataclass(frozen=True)
class ParsedOffer:
    """A decoded offer: requested payments plus the maker's coin spends."""

    requested: dict[str, list[Payment]]  # asset ("native") -> payments
    requested_groups: dict[str, list]  # asset -> raw notarized group sexprs
    nonce: bytes  # shared nonce (must be identical across dummy spends)
    spends: list[CoinSpend]  # maker spends (dummy spends excluded)
    signature: bytes  # aggregated maker signature
    bundle_bytes: bytes  # canonical bundle incl. dummy spends (offer id source)
    offer_id: str


def parse_requested_payments(solution: bytes) -> tuple[bytes, list[Payment], list]:
    """Parse a dummy settlement spend's solution.

    Returns ``(nonce, [Payment], [raw_group_sexprs])``.  The solution is
    a list of ``(nonce . ((puzzle_hash amount memos...) ...))`` groups;
    offers in the wild carry exactly one group per asset.
    """
    groups = _sexpr_as_list(cs.deser(solution))
    if not groups:
        raise OfferError("empty requested-payments solution")
    payments: list[Payment] = []
    nonce: bytes | None = None
    for group in groups:
        if not isinstance(group, tuple):
            raise OfferError("bad requested-payments group")
        g_nonce, g_payments = group
        if not isinstance(g_nonce, bytes) or len(g_nonce) != 32:
            raise OfferError("bad notarized-payment nonce")
        if nonce is None:
            nonce = g_nonce
        elif nonce != g_nonce:
            raise OfferError("mixed nonces in requested payments")
        for p in _sexpr_as_list(g_payments):
            args = _sexpr_as_list(p)
            if len(args) < 2:
                raise OfferError("bad payment")
            ph = args[0]
            if not isinstance(ph, bytes) or len(ph) != 32:
                raise OfferError("bad payment puzzle hash")
            memos = [m for m in _sexpr_as_list(args[2])] if len(args) > 2 else []
            payments.append(Payment(ph, _atom_int(args[1]), memos))
    assert nonce is not None
    return nonce, payments, groups


def parse_offer(offer_str: str) -> ParsedOffer:
    """Decode a bech32m offer string (compressed or, as a fallback, raw).

    Raises OfferError on any malformed input, on maker spends whose
    solution is not the standard XCH shape, and on legs whose asset
    driver is not native XCH (CAT/NFT/DID fail closed here).
    """
    try:
        _hrp, payload = cs.bech32m_decode(offer_str)
    except Exception as e:
        raise OfferError(f"bad offer string: {e}") from e
    try:
        bundle_bytes = decompress_offer(payload)
    except OfferError:
        # Fall back to an uncompressed bundle (valid per the reference
        # wallet's try_offer_decompression, which also accepts raw bytes).
        bundle_bytes = payload
    spends, signature = parse_solutions_bundle(bundle_bytes)
    requested: dict[str, list[Payment]] = {}
    requested_groups: dict[str, list] = {}
    maker_spends: list[CoinSpend] = []
    nonce: bytes | None = None
    for spend in spends:
        if spend.coin.parent_coin_info == _ZERO32:
            # Dummy settlement spend encoding requested payments.
            if spend.puzzle_reveal != OFFER_MOD:
                raise OfferError(
                    "offer requests an asset with an unsupported driver "
                    "(not native XCH settlement) — refusing"
                )
            asset = "native"
            if asset in requested:
                raise OfferError("duplicate requested asset in offer")
            g_nonce, payments, groups = parse_requested_payments(spend.solution)
            if nonce is None:
                nonce = g_nonce
            elif nonce != g_nonce:
                raise OfferError("offer dummy spends use different nonces")
            requested[asset] = payments
            requested_groups[asset] = groups
        else:
            # Fail closed on non-XCH drivers before anything else.
            parse_conditions(spend.solution)
            maker_spends.append(spend)
    if not requested:
        raise OfferError("offer has no requested payments")
    if not maker_spends:
        raise OfferError("offer has no maker spends")
    assert nonce is not None
    return ParsedOffer(
        requested=requested,
        requested_groups=requested_groups,
        nonce=nonce,
        spends=maker_spends,
        signature=signature,
        bundle_bytes=bundle_bytes,
        offer_id=offer_id_for_bundle(bundle_bytes),
    )


def summarize_offer(parsed: ParsedOffer) -> dict:
    """Decode exact give/get legs from a parsed offer.

    Returns ``{"offered": [(asset, amount)], "requested": [(asset, amount)]}``
    where the maker offers ``offered`` and requests ``requested``.
    Only native XCH legs are decoded; anything else already failed
    closed in :func:`parse_offer`.
    """
    offered: dict[str, int] = {}
    for spend in parsed.spends:
        conditions = parse_conditions(spend.solution)
        total = 0
        for ph, amount in create_coin_outputs(conditions):
            if ph == OFFER_MOD_HASH:
                total += amount
        if total <= 0:
            raise OfferError(
                f"maker spend {spend.coin.coin_id().hex()[:16]}… creates no "
                "native settlement output"
            )
        offered["native"] = offered.get("native", 0) + total
    requested = {
        asset: sum(p.amount for p in payments)
        for asset, payments in parsed.requested.items()
    }
    return {
        "offered": sorted(offered.items()),
        "requested": sorted(requested.items()),
    }


# ---------------------------------------------------------------------------
# Nonce, notarization, announcements (reference: Offer.notarize_payments,
# Offer.calculate_announcements)
# ---------------------------------------------------------------------------


def offer_nonce(coins: list[Coin]) -> bytes:
    """Shared nonce: tree hash of the maker coin infos sorted by coin id.

    Matches the reference ``notarize_payments``: coins sorted by
    ``Coin.name()``, ``Program.to([[parent, puzzle_hash, amount], ...])``
    tree-hashed.
    """
    ordered = sorted(coins, key=lambda c: c.coin_id())
    sexpr = cs._list(
        [cs._list([c.parent_coin_info, c.puzzle_hash, cs.int_to_bytes(c.amount)])
         for c in ordered]
    )
    return cs.sha256tree(sexpr)


def notarized_group(
    nonce: bytes, payments: list[Payment]
) -> bytes:
    """One settlement group program: (nonce . ((ph amount memos) ...))."""
    group_payments = [
        cs._list([p.puzzle_hash, cs.int_to_bytes(p.amount), cs._list(p.memos)])
        for p in payments
    ]
    return cs.ser((nonce, cs._list(group_payments)))


def announcement_for_asset(asset: str, nonce: bytes, payments: list[Payment]) -> tuple[bytes, bytes]:
    """(settlement_ph, message) the maker/taker must assert for an asset."""
    if asset != "native":
        raise OfferError(f"unsupported offer asset {asset!r}: native XCH only")
    group = cs.deser(notarized_group(nonce, payments))
    return OFFER_MOD_HASH, cs.sha256tree(group)


def assert_puzzle_announcement_condition(ph: bytes, msg: bytes):
    """ASSERT_PUZZLE_ANNOUNCEMENT condition s-expr.

    Consensus format is a SINGLE argument: the announcement id
    ``sha256(puzzle_hash + message)`` (chia/wallet/conditions.py:
    ``AssertPuzzleAnnouncement.to_program``).  A two-argument
    ``(ph, msg)`` form is malformed and the mempool rejects the bundle
    with INVALID_CONDITION.
    """
    return cs._list(
        [
            cs.int_to_bytes(_ASSERT_PUZZLE_ANNOUNCEMENT),
            hashlib.sha256(ph + msg).digest(),
        ]
    )

# ---------------------------------------------------------------------------
# Offer construction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class XchInput:
    """A standard (XCH) coin owned by the wallet."""

    parent_coin_info: bytes
    puzzle_hash: bytes
    amount: int
    index: int  # derivation index of the standard puzzle locking this coin

    def coin(self) -> Coin:
        return Coin(self.parent_coin_info, self.puzzle_hash, self.amount)


@dataclass(frozen=True)
class RequestedPayment:
    """One payment the maker wants to receive: (puzzle_hash, amount).

    Native XCH only: ``asset`` must be ``"native"``.
    """

    asset: str  # "native"
    puzzle_hash: bytes
    amount: int


@dataclass(frozen=True)
class BuiltOffer:
    """Result of :func:`make_offer`."""

    offer_str: str  # bech32m offer string (off-chain)
    offer_id: str  # sha256 of the canonical bundle (== SpendBundle.name())
    bundle_bytes: bytes  # canonical bundle incl. dummy spends
    # Maker metadata the wallet persists for status/cancellation:
    maker_coins: list[dict]  # [{coin_id, asset, amount, parent, puzzle_hash}]
    offered: list[tuple[str, int]]
    requested: list[tuple[str, int]]
    nonce: bytes


def _standard_inner(master_sk: bytes, index: int) -> tuple[bytes, bytes, bytes]:
    """(reveal, puzzle_hash, synthetic_sk) for a wallet derivation index."""
    wsk = cs.wallet_sk(master_sk, index)
    spk = cs.synthetic_pk(cs.pk_bytes(wsk))
    reveal = cs.standard_puzzle_reveal(spk)
    return reveal, cs.sha256tree(cs.deser(reveal)), cs.synthetic_sk(wsk)


def _check_xch_input(master_sk: bytes, inp: XchInput) -> tuple[bytes, bytes]:
    """Verify an XCH input is really ours; return (inner_reveal, synth_sk)."""
    reveal, ph, ssk = _standard_inner(master_sk, inp.index)
    if ph != inp.puzzle_hash:
        raise OfferError(
            f"XCH input {inp.coin().coin_id().hex()[:16]}… is not locked to "
            f"derivation index {inp.index} — refusing"
        )
    if len(inp.parent_coin_info) != 32 or inp.amount <= 0:
        raise OfferError("bad XCH input coin")
    return reveal, ssk


def _inner_create_coin(ph: bytes, amount: int):
    return cs._list([cs.int_to_bytes(_CREATE_COIN), ph, cs.int_to_bytes(amount)])


def _standard_solution(conditions) -> bytes:
    """Standard solution bytes: (None, (q . conditions), ()).

    ``conditions`` is serialized condition bytes; it is deserialized
    before quoting so the solution commits to the program, not to its
    serialization as an atom.
    """
    if isinstance(conditions, bytes) and conditions != b"":
        conditions = cs.deser(conditions)
    return cs.ser(cs._list([cs.NIL, cs.quote(conditions), cs.NIL]))


def _reserve_fee_cond(fee: int):
    return cs._list([cs.int_to_bytes(_RESERVE_FEE), cs.int_to_bytes(fee)])


def _lazy_to_sexpr(node):
    """Convert a chia_rs LazyNode result to our (bytes | tuple) s-expr."""
    atom = node.atom
    if atom is not None:
        return bytes(atom)
    first, rest = node.pair
    return (_lazy_to_sexpr(first), _lazy_to_sexpr(rest))


def _validate_legs(
    offered: list[tuple[str, int]], requested: list[RequestedPayment]
) -> dict[str, int]:
    """Native-XCH-only leg validation; anything else fails closed."""
    if not offered:
        raise OfferError("offer must offer something")
    if not requested:
        raise OfferError("offer must request something")
    offered_map: dict[str, int] = {}
    for asset, amt in offered:
        if asset != "native":
            raise OfferError(
                f"unsupported offered asset {asset!r}: native XCH only — refusing"
            )
        if amt <= 0:
            raise OfferError("offered amounts must be positive")
        if asset in offered_map:
            raise OfferError(f"duplicate offered asset {asset!r}")
        offered_map[asset] = amt
    seen_req: set[str] = set()
    for r in requested:
        if r.asset != "native":
            raise OfferError(
                f"unsupported requested asset {r.asset!r}: native XCH only — refusing"
            )
        if len(r.puzzle_hash) != 32 or r.amount <= 0:
            raise OfferError("bad requested payment")
        if r.asset in seen_req:
            raise OfferError(f"duplicate requested asset {r.asset!r}")
        seen_req.add(r.asset)
    return offered_map


def _build_side(
    master_sk: bytes,
    network_id: str,
    offered: list[tuple[str, int]],
    requested: list[RequestedPayment],
    xch_inputs: list[XchInput],
    change_ph: bytes | None,
    fee: int,
) -> dict:
    """Build one side of an offer (maker side or taker side).

    Returns a dict with: spends, signatures, settlement (asset ->
    [settlement Coins created]), groups (asset -> [notarized group
    sexprs]), nonce.
    """
    if fee < 0:
        raise OfferError("fee must be non-negative")
    offered_map = _validate_legs(offered, requested)

    xch_checked = [(inp, *_check_xch_input(master_sk, inp)) for inp in xch_inputs]

    # Coverage.
    xch_total = sum(inp.amount for inp, _, _ in xch_checked)
    native_offered = offered_map.get("native", 0)
    if not xch_checked:
        raise OfferError("offer needs at least one XCH input")
    if change_ph is None:
        raise OfferError("XCH change puzzle hash required with XCH inputs")
    need_xch = native_offered + fee
    if xch_total < need_xch:
        raise OfferError(
            f"XCH inputs cover {xch_total}, need {need_xch} (offered + fee)"
        )
    if native_offered == 0 and fee == 0:
        raise OfferError("XCH inputs with no native leg and no fee — refusing")

    # Shared nonce over ALL side coins (reference: notarize_payments).
    all_coins = [inp.coin() for inp, _, _ in xch_checked]
    nonce = offer_nonce(all_coins)

    requested_by_asset: dict[str, list[Payment]] = {}
    for r in requested:
        requested_by_asset.setdefault(r.asset, []).append(
            Payment(r.puzzle_hash, r.amount, [])
        )
    announcements = [
        assert_puzzle_announcement_condition(
            *announcement_for_asset(asset, nonce, payments)
        )
        for asset, payments in requested_by_asset.items()
    ]
    groups = {
        asset: [cs.deser(notarized_group(nonce, payments))]
        for asset, payments in requested_by_asset.items()
    }

    spends: list[CoinSpend] = []
    signatures: list[bytes] = []
    settlement: dict[str, list[Coin]] = {}
    first_spend = True

    def _sign_standard(index: int, coin: Coin, conditions) -> tuple[CoinSpend, bytes]:
        reveal, _, ssk = _standard_inner(master_sk, index)
        solution = _standard_solution(conditions)
        sig = cs.sign_coin_spend(
            ssk,
            (coin.parent_coin_info, coin.puzzle_hash, coin.amount),
            conditions,
            network_id,
        )
        return CoinSpend(coin, reveal, solution), sig

    # --- XCH spends: origin coin creates all outputs, others consolidate.
    xch_sorted = sorted(xch_checked, key=lambda t: t[0].coin().coin_id())
    xch_change = xch_total - native_offered - fee
    for pos, (inp, _reveal, _ssk) in enumerate(xch_sorted):
        coin = inp.coin()
        if pos == 0:
            conds = []
            if native_offered:
                conds.append(_inner_create_coin(OFFER_MOD_HASH, native_offered))
                settlement.setdefault("native", []).append(
                    Coin(coin.coin_id(), OFFER_MOD_HASH, native_offered)
                )
            if xch_change > 0:
                assert change_ph is not None
                conds.append(_inner_create_coin(change_ph, xch_change))
            if fee > 0:
                conds.append(_reserve_fee_cond(fee))
            if first_spend:
                conds.extend(announcements)
                first_spend = False
            conditions = cs._list(conds)
        else:
            # Consolidate: no outputs; value flows into the origin coin's
            # outputs (standard Chia wallet behavior).
            conditions = cs._list([])
        spend, sig = _sign_standard(inp.index, coin, conditions)
        spends.append(spend)
        signatures.append(sig)

    return {
        "spends": spends,
        "signatures": signatures,
        "settlement": settlement,
        "groups": groups,
        "nonce": nonce,
    }


def make_offer(
    master_sk: bytes,
    network_id: str,
    offered: list[tuple[str, int]],
    requested: list[RequestedPayment],
    xch_inputs: list[XchInput],
    change_ph: bytes | None,
    fee: int = 0,
    offer_prefix: str = "offer",
) -> BuiltOffer:
    """Build and locally sign a native XCH offer (nothing is broadcast).

    ``offered``: [(asset, amount)] the maker gives — ``"native"`` only.
    ``requested``: payments the maker wants to receive (XCH only).
    ``change_ph``: XCH change puzzle hash (required).  ``fee`` is paid
    from XCH inputs.
    """
    side = _build_side(
        master_sk, network_id, offered, requested,
        xch_inputs, change_ph, fee,
    )
    # Dummy settlement spends (reference: Offer.to_spend_bundle).
    dummy_spends: list[CoinSpend] = []
    for asset, group_list in side["groups"].items():
        puzzle = OFFER_MOD
        solution = cs.ser(cs._list(group_list))
        coin = Coin(_ZERO32, cs.sha256tree(cs.deser(puzzle)), 0)
        dummy_spends.append(CoinSpend(coin, puzzle, solution))
    bundle_bytes = serialize_bundle(
        dummy_spends + side["spends"],
        cs.aggregate_signatures(side["signatures"]),
    )
    offer_str = cs.bech32m_encode(offer_prefix, compress_offer(bundle_bytes))
    maker_coins = [
        {
            "coin_id": s.coin.coin_id().hex(),
            "asset": "native",
            "amount": s.coin.amount,
            "parent": s.coin.parent_coin_info.hex(),
            "puzzle_hash": s.coin.puzzle_hash.hex(),
        }
        for s in side["spends"]
    ]
    return BuiltOffer(
        offer_str=offer_str,
        offer_id=offer_id_for_bundle(bundle_bytes),
        bundle_bytes=bundle_bytes,
        maker_coins=maker_coins,
        offered=sorted(offered),
        requested=sorted((r.asset, r.amount) for r in requested),
        nonce=side["nonce"],
    )


# ---------------------------------------------------------------------------
# Take
# ---------------------------------------------------------------------------


def _settlement_coins(spends: list[CoinSpend]) -> dict[str, list[Coin]]:
    """Settlement outputs created by a side's spends, grouped by asset.

    Coins are identified by parsing CREATE_COIN conditions whose target
    is the side's settlement puzzle hash (OFFER_MOD_HASH).
    """
    out: dict[str, list[Coin]] = {}
    for spend in spends:
        conds = conditions_of_spend(spend)
        for cond in conds:
            opcode, args = _condition_args(cond)
            if (
                opcode == _CREATE_COIN
                and len(args) >= 2
                and args[0] == OFFER_MOD_HASH
            ):
                out.setdefault("native", []).append(
                    Coin(spend.coin.coin_id(), OFFER_MOD_HASH, _atom_int(args[1]))
                )
    return out


def _payments_of_group(group) -> list[Payment]:
    _, payments = group
    out = []
    for p in _sexpr_as_list(payments):
        args = _sexpr_as_list(p)
        ph = args[0]
        memos = [m for m in _sexpr_as_list(args[2])] if len(args) > 2 else []
        out.append(Payment(ph, _atom_int(args[1]), memos))
    return out


def _completion_spends(
    settlement: dict[str, list[Coin]],
    groups: dict[str, list],
) -> list[CoinSpend]:
    """Build native settlement completion spends (port of
    ``Offer.to_valid_spend``).

    ``settlement``: asset -> settlement coins.  ``groups``: asset ->
    notarized group sexprs for the completing solution.  The first coin
    of each asset's group carries the groups; the rest are empty.
    """
    completion: list[CoinSpend] = []
    for asset in sorted(settlement):
        if asset != "native":
            raise OfferError(f"unsupported settlement asset {asset!r} — refusing")
        coins = sorted(settlement[asset], key=lambda c: c.coin_id())
        if not coins:
            continue
        expected = sum(p.amount for g in groups[asset] for p in _payments_of_group(g))
        if sum(c.amount for c in coins) != expected:
            raise OfferError(
                "settlement does not match the payments — refusing"
            )
        for pos, coin in enumerate(coins):
            solution = (
                cs.ser(cs._list(groups[asset])) if pos == 0 else cs.ser([])
            )
            completion.append(CoinSpend(coin, OFFER_MOD, solution))
    return completion


@dataclass(frozen=True)
class TakeResult:
    bundle_bytes: bytes  # broadcast-ready: completion + maker + taker spends
    bundle_txid: str
    offered: list[tuple[str, int]]  # what the taker received
    given: list[tuple[str, int]]  # what the taker gave


def take_offer(
    master_sk: bytes,
    network_id: str,
    offer: ParsedOffer,
    xch_inputs: list[XchInput],
    receive: list[RequestedPayment],
    change_ph: bytes | None,
    fee: int = 0,
) -> TakeResult:
    """Take a native XCH offer: verify, build our side, complete settlement.

    ``receive``: where WE take the maker's offered XCH — one entry, the
    amount must exactly equal the offered total.  ``change_ph``/``fee``:
    as in :func:`make_offer`.  Returns the full broadcast-ready bundle.
    Nothing is broadcast here.
    """
    # --- 1. verify the maker's side ---
    maker_settlement = _settlement_coins(offer.spends)
    maker_offered = {a: sum(c.amount for c in cs_) for a, cs_ in maker_settlement.items()}
    if not maker_offered:
        raise OfferError("offer has no settlement outputs — refusing")
    summary = summarize_offer(offer)
    offered_assets = {a for a, _ in summary["offered"]}
    for asset in maker_offered:
        if asset not in offered_assets:
            raise OfferError("offer spends use an unsupported driver — refusing")
    # Announcements: what the maker must have asserted.
    requested = {
        asset: [Payment(p.puzzle_hash, p.amount, p.memos) for p in payments]
        for asset, payments in offer.requested.items()
    }
    expected_ann = {
        hashlib.sha256(
            OFFER_MOD_HASH
            + cs.sha256tree(cs.deser(notarized_group(offer.nonce, payments)))
        ).digest()
        for asset, payments in requested.items()
    }
    asserted = assert_announcements_of_spends(offer.spends)
    if not expected_ann <= asserted:
        raise OfferError(
            "maker spends do not assert the requested-payment announcements — refusing"
        )

    # --- 2. our side: we give the maker's requested, receive their offered.
    receive_map: dict[str, RequestedPayment] = {}
    for r in receive:
        if r.asset != "native":
            raise OfferError(f"unsupported receive asset {r.asset!r} — refusing")
        if r.asset in receive_map:
            raise OfferError(f"duplicate receive asset {r.asset!r}")
        receive_map[r.asset] = r
    if set(receive_map) != set(maker_offered):
        raise OfferError(
            "receive legs must exactly match the maker's offered assets — refusing"
        )
    for asset, r in receive_map.items():
        if r.amount != maker_offered[asset]:
            raise OfferError(
                f"receive amount ({r.amount}) != offered ({maker_offered[asset]}) — refusing"
            )
    # What we give = the maker's requested (asset, total amount).
    give = sorted(
        (asset, sum(p.amount for p in payments))
        for asset, payments in requested.items()
    )
    side = _build_side(
        master_sk, network_id, give, list(receive_map.values()),
        xch_inputs, change_ph, fee,
    )
    # Cross-check: our settlement must fund exactly the maker's requested.
    our_settlement = side["settlement"]
    for asset, total in give:
        got = sum(c.amount for c in our_settlement.get(asset, []))
        if got != total:
            raise OfferError("taker settlement mismatch — refusing")

    # --- 3. completion spends for BOTH sides.
    maker_completion = _completion_spends(maker_settlement, side["groups"])
    taker_completion = _completion_spends(our_settlement, offer.requested_groups)

    spends = maker_completion + list(offer.spends) + taker_completion + side["spends"]
    agg = cs.aggregate_signatures([offer.signature] + side["signatures"])
    bundle_bytes = serialize_bundle(spends, agg)
    return TakeResult(
        bundle_bytes=bundle_bytes,
        bundle_txid=hashlib.sha256(bundle_bytes).hexdigest(),
        offered=sorted((a, maker_offered[a]) for a in maker_offered),
        given=give,
    )


# ---------------------------------------------------------------------------
# Cancel
# ---------------------------------------------------------------------------


def cancel_offer(
    master_sk: bytes,
    network_id: str,
    coin: Coin,
    index: int,
    change_ph: bytes,
    fee: int = 0,
) -> bytes:
    """Securely cancel our own XCH offer by spending one maker coin on-chain.

    Spends the maker coin back to ``change_ph`` (minus ``fee``).
    Spending any single maker input on-chain invalidates the whole
    offer.  Returns the serialized broadcast-ready SpendBundle (single
    spend).  Nothing is broadcast here.
    """
    if len(change_ph) != 32 or fee < 0:
        raise OfferError("bad cancel params")
    inp = XchInput(coin.parent_coin_info, coin.puzzle_hash, coin.amount, index)
    _check_xch_input(master_sk, inp)
    if coin.amount - fee <= 0:
        raise OfferError("cancel amount does not cover fee")
    conds = [_inner_create_coin(change_ph, coin.amount - fee)]
    if fee > 0:
        conds.append(_reserve_fee_cond(fee))
    conditions = cs._list(conds)
    reveal, _, ssk = _standard_inner(master_sk, index)
    solution = _standard_solution(conditions)
    sig = cs.sign_coin_spend(
        ssk,
        (coin.parent_coin_info, coin.puzzle_hash, coin.amount),
        conditions, network_id,
    )
    return serialize_bundle([CoinSpend(coin, reveal, solution)], sig)
