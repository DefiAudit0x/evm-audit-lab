"""Regression cases for PR #6 detector review (Fixes 161–165)."""
from pathlib import Path
import unittest

from audit.detectors import precision, proxy_upgrade, storage_collision
from audit.detectors.solidity import contract_blocks

ROOT = Path(__file__).resolve().parents[1]
PATH = Path('src/ReviewFixture.sol')


def mint_findings(body):
    source = '''contract Pool {
        uint256 totalShares;
        uint256 totalAssets;
        mapping(address => uint256) balances;
        function deposit(uint256 assets) external returns (uint256) {
            BODY
        }
    }'''.replace('BODY', body)
    return precision.detect_source(ROOT, PATH, source)


class Fix161Tests(unittest.TestCase):
    def test_indexed_tuple_keeps_proof(self):
        for target in ('shares[ownerOf(id)]', 'shares[msg.sender]'):
            body = f'''minted = assets * totalShares / totalAssets;
                require(minted > 0);
                ({target}, fee) = ({target} + minted, 0);'''
            with self.subTest(target=target):
                self.assertFalse(precision._written_between(
                    body, 0, len(body), 'shares', include_indexed=False))
                self.assertEqual(mint_findings(body), [])
                # The indexed tuple is a consumer, including without calls
                # in its indices (the old _TOP_LEVEL_WRITE matched that case).
                self.assertEqual(precision._last_consumer_end(body + ' minted = 0;', 0), len(body))
                self.assertEqual(mint_findings(body + ' minted = 0;'), [])

    def test_nested_scalar_tuple_clears_proof(self):
        body = '''minted = assets * totalShares / totalAssets;
            require(minted > 0);
            (shares[ownerOf(id)], (fee, minted)) = values();
            balances[msg.sender] += minted;'''
        self.assertTrue(precision._written_between(body, body.index('require'), len(body),
                                                  'minted', include_indexed=False))
        self.assertEqual(len(mint_findings(body)), 1)


class Fix162Tests(unittest.TestCase):
    def test_later_constant_does_not_cover_credit(self):
        division = 'minted = assets * totalShares / totalAssets;'
        credit = 'shares[msg.sender] += minted;'
        self.assertEqual(len(mint_findings(f'{division} {credit} minted = 1; return minted;')), 1)
        self.assertEqual(mint_findings(f'{division} minted = 1; {credit} return minted;'), [])

    def test_arm_later_constant_does_not_cover_credit(self):
        for before, expected in ((False, 1), (True, 0)):
            arm = 'minted = assets * totalShares / totalAssets; '
            arm += ('minted = 1; balances[msg.sender] += minted;' if before else
                    'balances[msg.sender] += minted; minted = 1;')
            body = f'if (seed) {{ {arm} }} else {{ minted = 1; }} return minted;'
            with self.subTest(before=before):
                self.assertEqual(len(mint_findings(body)), expected)


class Fix163Tests(unittest.TestCase):
    def test_constant_proof_belongs_to_credited_variable(self):
        for name, expected in (('shares', 1), ('minted', 0)):
            body = f'''minted = assets * totalShares / totalAssets;
                {name} = 1; balances[msg.sender] += minted; return minted;'''
            with self.subTest(name=name):
                self.assertEqual(len(mint_findings(body)), expected)
                guarded = body.replace(f'{name} = 1;', f'assert(({name} > 0));')
                self.assertEqual(len(mint_findings(guarded)), expected)

    def test_arm_proof_belongs_to_credited_variable(self):
        for name, expected in (('shares', 1), ('minted', 0)):
            body = f'''if (seed) {{
                minted = assets * totalShares / totalAssets;
                {name} = 1;
            }} else {{ minted = 1; }}
            balances[msg.sender] += minted; return minted;'''
            with self.subTest(name=name):
                self.assertEqual(len(mint_findings(body)), expected)


class Fix164Tests(unittest.TestCase):
    def test_condition_read_is_not_assignment(self):
        for statement in ('if (compatible) marker = 1;',
                          'else if (compatible) marker = 1;',
                          'while (compatible) marker = 1;',
                          'for (; compatible;) marker = 1;'):
            with self.subTest(statement=statement):
                self.assertFalse(proxy_upgrade._assigned_between(statement, 0, len(statement), 'compatible'))
        source = '''contract Vault {
            function upgradeToAndCall(address candidate, bytes calldata data) external {
                (bool compatible, bytes memory uuid) = candidate.staticcall(abi.encodeCall(this.proxiableUUID, ()));
                if (compatible) marker = 1;
                require(compatible);
                require(abi.decode(uuid, (bytes32)) == IMPLEMENTATION_SLOT);
            }
        }'''
        findings = proxy_upgrade.detect_source(ROOT, PATH, source)
        self.assertEqual(len(findings), 1)
        self.assertNotIn('UUPS proxiableUUID compatibility', findings[0].message)

    def test_nested_tuple_remains_assignment(self):
        statement = 'if (enabled) ((compatible, uuid), marker) = values();'
        for name in ('compatible', 'uuid'):
            self.assertTrue(proxy_upgrade._assigned_between(statement, 0, len(statement), name))


class Fix165Tests(unittest.TestCase):
    def test_array_span_counts_whole_elements(self):
        for kind, count, span in (('address', 5000, 5000), ('uint128', 5000, 2500),
                                  ('uint192', 10, 10)):
            with self.subTest(kind=kind):
                self.assertEqual(storage_collision._slot_span(('array', kind, str(count))), span)

    def test_large_address_array_tail_layout(self):
        source = 'contract Layout { address[5000] reserved; uint256 tail; }'
        contract = next(contract_blocks(PATH, source))
        layout = storage_collision._resolved_storage_layout(contract, {contract.name: contract})
        self.assertEqual(layout[1], ('uint256', 5000, 0, (1,)))
