"""Heuristics for oracle validation and spot-price dependence."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import (
    constructor_blocks,
    contract_blocks,
    function_blocks,
    modifier_blocks,
    relative_path,
    solidity_files,
)


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        code = contract.code_body
        # The L2 uptime feed has a different schema from a price feed;
        # the derived lender delegates price validation to its base.
        delegates_price_validation = (
            "sequencer.latestRoundData" in code and "super._validatedPrice" in code
        )
        functions = list(function_blocks(contract))
        # Oracle reads in modifiers and constructors are scannable units
        # too, with the same per-body checks as functions; validation stays
        # scoped to each body.
        units = (
            functions
            + list(modifier_blocks(contract))
            + list(constructor_blocks(contract))
        )
        for function in units:
            code = function.code_body
            round_data_calls = list(re.finditer(r"\blatestRoundData\s*\(", code))
            if contract.name == "FakeOracle" or not round_data_calls:
                continue
            if delegates_price_validation and all(
                re.search(r"\bsequencer\s*\.\s*$", code[:match.start()])
                for match in round_data_calls
            ):
                continue
            checks = {
                "positive answer": bool(re.search(r"(?:price|answer)\s*>\s*0", code)),
                "freshness bound": bool(re.search(r"block\.timestamp\s*-\s*\w+\s*<\s*(?:MAX_STALENESS|\d+)", code)),
                "future timestamp bound": bool(re.search(r"\w+\s*<=\s*block\.timestamp", code)),
                "completed round": bool(re.search(r"\w+\s*>=\s*\w+", code) and "answeredInRound" in code),
                "feed-decimal normalization": "decimals()" in code,
            }
            missing = [name for name, present in checks.items() if not present]
            if missing:
                findings.append(
                    Finding(
                        detector="oracle",
                        severity="high" if "positive answer" in missing or "freshness bound" in missing else "medium",
                        confidence="high",
                        title="Oracle answer is missing validation checks",
                        message="Missing checks: " + ", ".join(missing) + ".",
                        file=relative_path(root, source_path),
                        line=contract.line(function.start),
                        contract=contract.name,
                    )
                )
        spot_function = any(
            function.name in {"getPrice", "price"}
            and re.search(
                r"\breturn\s+[\s(]*reserve\w*[\s()]*\*[\s()]*1e18[\s()]*/[\s()]*reserve\w*[\s)]*;",
                function.code_body,
            )
            for function in functions
        )
        if spot_function:
            findings.append(
                Finding(
                    detector="oracle",
                    severity="high",
                    confidence="high",
                    title="Oracle exposes a manipulable reserve spot price",
                    message="The price is computed directly from current reserves without a time-weighted observation path.",
                    file=relative_path(root, source_path),
                    line=contract.line(contract.start),
                    contract=contract.name,
                )
            )
    return findings


def detect(root: Path) -> list[Finding]:
    return [
        finding
        for path, source in solidity_files(root)
        for finding in detect_source(root, path, source)
    ]
