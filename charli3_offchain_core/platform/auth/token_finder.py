"""Platform authorization NFT finding utilities."""

import logging

from pycardano import (
    Address,
    Asset,
    AssetName,
    MultiAsset,
    NativeScript,
    ScriptHash,
    TransactionId,
    TransactionInput,
    TransactionOutput,
    UTxO,
    Value,
)

from charli3_offchain_core.blockchain.chain_query import ChainQuery
from charli3_offchain_core.platform.auth.token_script_builder import (
    PlatformAuthScript,
    ScriptConfig,
)

logger = logging.getLogger(__name__)


class PlatformAuthFinder:
    """Utility for finding platform authorization NFTs"""

    def __init__(self, chain_query: ChainQuery) -> None:
        self.chain_query = chain_query

    async def find_auth_utxo(
        self, policy_id: str, platform_address: str
    ) -> UTxO | None:
        """Find platform authorization NFT UTxO.

        Bypasses pycardano's get_utxos() path which chokes on native-script
        reference UTxOs (0.17-fork bug). Queries Blockfrost directly and
        constructs a minimal UTxO pointing at the NFT-bearing output.
        """
        try:
            raw = self._raw_utxos_from_blockfrost(platform_address)
        except Exception as e:
            logger.error("Error finding auth NFT: %s", str(e))
            return None

        for entry in raw:
            amounts = entry.get("amount", [])
            # Skip UTxOs that don't carry the platform policy token.
            asset_info = None
            lovelace = 0
            multi_asset_dict: dict[str, dict[str, int]] = {}
            for a in amounts:
                unit = a["unit"]
                qty = int(a["quantity"])
                if unit == "lovelace":
                    lovelace = qty
                    continue
                entry_policy = unit[:56]
                asset_name_hex = unit[56:]
                multi_asset_dict.setdefault(entry_policy, {})[asset_name_hex] = qty
                if entry_policy == policy_id:
                    asset_info = (policy_id, asset_name_hex, qty)

            if asset_info is None:
                continue

            # Build a minimal UTxO. Only policy+asset+qty and tx_ref are needed.
            ma = MultiAsset()
            for pid, names in multi_asset_dict.items():
                asset = Asset()
                for n_hex, q in names.items():
                    asset[AssetName(bytes.fromhex(n_hex))] = q
                ma[ScriptHash(bytes.fromhex(pid))] = asset

            tx_id = TransactionId(bytes.fromhex(entry["tx_hash"]))
            tx_in = TransactionInput(tx_id, entry["output_index"])
            output = TransactionOutput(
                address=Address.from_primitive(platform_address),
                amount=Value(coin=lovelace, multi_asset=ma),
            )
            return UTxO(tx_in, output)

        return None

    def _raw_utxos_from_blockfrost(self, platform_address: str) -> list[dict]:
        """Fetch UTxOs for an address via Blockfrost REST, bypassing pycardano's
        parser. Returns raw dicts as given by the /addresses/{addr}/utxos endpoint.
        """
        import os
        import urllib.request

        project_id = os.environ.get("BLOCKFROST_PROJECT_ID") or os.environ.get(
            "BLOCKFROST_API_KEY"
        )
        if not project_id:
            raise RuntimeError("BLOCKFROST_PROJECT_ID / BLOCKFROST_API_KEY not set")

        # Derive base URL from the project id prefix (preprod/mainnet/preview).
        if project_id.startswith("preprod"):
            base = "https://cardano-preprod.blockfrost.io/api/v0"
        elif project_id.startswith("preview"):
            base = "https://cardano-preview.blockfrost.io/api/v0"
        else:
            base = "https://cardano-mainnet.blockfrost.io/api/v0"

        import json

        req = urllib.request.Request(
            f"{base}/addresses/{platform_address}/utxos",
            headers={"project_id": project_id},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)

    def _has_policy_token(self, utxo: UTxO, policy_hash: ScriptHash) -> bool:
        """Check if UTxO contains token from policy."""
        return (
            utxo.output.amount.multi_asset is not None
            and policy_hash in utxo.output.amount.multi_asset
        )

    async def get_platform_script(self, address: str) -> NativeScript:
        """Get MultiSig script for platform authorization.

        Bypasses pycardano's native-script CBOR parser (0.17 fork bug with
        wrapped ScriptPubkey tags) by fetching the JSON representation from
        Blockfrost's /scripts/{hash}/json endpoint and reconstructing.
        """
        script_hash = self._get_script_hash(address)
        hash_hex = script_hash.payload.hex()
        try:
            script_json = self._raw_script_json_from_blockfrost(hash_hex)
        except Exception:
            # Fall back to the original path (will raise the pycardano error)
            # so operators see the same diagnostic if Blockfrost is unavailable.
            return await self.chain_query.get_native_script(script_hash)
        return self._build_native_script_from_json(script_json)

    def _raw_script_json_from_blockfrost(self, script_hash: str) -> dict:
        import os
        import urllib.request
        import json

        project_id = os.environ.get("BLOCKFROST_PROJECT_ID") or os.environ.get(
            "BLOCKFROST_API_KEY"
        )
        if not project_id:
            raise RuntimeError("BLOCKFROST_PROJECT_ID / BLOCKFROST_API_KEY not set")
        if project_id.startswith("preprod"):
            base = "https://cardano-preprod.blockfrost.io/api/v0"
        elif project_id.startswith("preview"):
            base = "https://cardano-preview.blockfrost.io/api/v0"
        else:
            base = "https://cardano-mainnet.blockfrost.io/api/v0"
        req = urllib.request.Request(
            f"{base}/scripts/{script_hash}/json",
            headers={"project_id": project_id},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp).get("json", {})

    @staticmethod
    def _build_native_script_from_json(data: dict) -> NativeScript:
        """Recursively turn the Blockfrost native-script JSON into pycardano
        NativeScript objects. Handles: sig, all, any, atLeast, before, after.
        """
        from pycardano import (
            InvalidBefore,
            InvalidHereAfter,
            ScriptAll,
            ScriptAny,
            ScriptNofK,
            ScriptPubkey,
            VerificationKeyHash,
        )

        t = data.get("type")
        if t == "sig":
            return ScriptPubkey(VerificationKeyHash(bytes.fromhex(data["keyHash"])))
        if t == "all":
            return ScriptAll(
                [
                    PlatformAuthFinder._build_native_script_from_json(s)
                    for s in data.get("scripts", [])
                ]
            )
        if t == "any":
            return ScriptAny(
                [
                    PlatformAuthFinder._build_native_script_from_json(s)
                    for s in data.get("scripts", [])
                ]
            )
        if t == "atLeast":
            return ScriptNofK(
                int(data["required"]),
                [
                    PlatformAuthFinder._build_native_script_from_json(s)
                    for s in data.get("scripts", [])
                ],
            )
        if t == "before":
            return InvalidHereAfter(int(data["slot"]))
        if t == "after":
            return InvalidBefore(int(data["slot"]))
        raise ValueError(f"Unknown native script type: {t}")

    def _get_script_hash(self, address: str) -> ScriptHash:
        """Extract script hash from script address."""
        if isinstance(address, Address):
            addr = address
        else:
            addr = Address.from_primitive(str(address))

        return addr.payment_part

    def get_script_config(self, script: NativeScript) -> ScriptConfig:
        """Get signers from script"""
        if not isinstance(script, NativeScript):
            return None
        return PlatformAuthScript.from_native_script(script)
