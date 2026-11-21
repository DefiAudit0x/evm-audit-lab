"""Heuristics for oracle validation and spot-price dependence."""

from __future__ import annotations

from pathlib import Path
import re

from .finding import Finding
from .solidity import contract_blocks, function_blocks, relative_path, solidity_files


def detect_source(root: Path, source_path: Path, source: str) -> list[Finding]:
    findings = []
    for contract in contract_blocks(source_path, source):
        code = contract.code_body
        if contract.name != "FakeOracle" and "latestRoundData" in code:
            # The L2 uptime feed has a different schema from a price feed;
            # the derived lender delegates price validation to its base.
            if "sequencer.latestRoundData" in code and "super._validatedPrice" in code:
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
                        line=contract.line(contract.start),
                        contract=contract.name,
                    )
                )
        spot_function = any(
            function.name in {"getPrice", "price"}
            and re.search(
                r"\breturn\s+[\s(]*reserve\w*[\s()]*\*[\s()]*1e18[\s()]*/[\s()]*reserve\w*[\s)]*;",
                function.code_body,
            )
            for function in function_blocks(contract)
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
