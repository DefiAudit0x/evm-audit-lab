"""Regression cases for PR #6 detector review (Fixes 161–172)."""
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


class Fix166Tests(unittest.TestCase):
    def test_final_tuple_target_invalidates_join_proof(self):
        for name in ('minted', 'shares'):
            body = f'''if (seed) {{ {name} = 1; }} else {{ {name} = 2; }}
                (fee, {name}) = (0, 0);
                balances[msg.sender] += {name};
                return assets * totalShares / totalAssets;'''
            with self.subTest(name=name):
                self.assertTrue(precision._written_between(
                    body, body.index('(fee'), len(body), name, include_indexed=False))
                self.assertEqual(len(mint_findings(body)), 1)

    def test_indexed_tuple_target_still_ignored(self):
        statement = '(shares[ownerOf(id)], fee) = values();'
        self.assertFalse(precision._written_between(
            statement, 0, len(statement), 'shares', include_indexed=False))

    def test_nested_scalar_tuple_target_still_detected(self):
        statement = '(fee, (minted, other)) = values();'
        self.assertTrue(precision._written_between(
            statement, 0, len(statement), 'minted', include_indexed=False))


class Fix167Tests(unittest.TestCase):
    def check_credit(self, suffix, expected, *, arm=False):
        sequence = f'''minted = assets * totalShares / totalAssets;
            balances[msg.sender] += minted; {suffix}'''
        body = (f'if (seed) {{ {sequence} }} else {{ minted = 1; }} return minted;'
                if arm else sequence + ' return minted;')
        self.assertEqual(len(mint_findings(body)), expected)

    def test_later_guard_covers_credit(self):
        self.check_credit('require(minted > 0);', 0)

    def test_arm_later_guard_covers_credit(self):
        self.check_credit('require(minted > 0);', 0, arm=True)

    def test_positive_overwrite_does_not_cover_credit(self):
        self.check_credit('minted = 1;', 1)

    def test_arm_positive_overwrite_does_not_cover_credit(self):
        self.check_credit('minted = 1;', 1, arm=True)

    def test_other_guard_does_not_cover_credit(self):
        self.check_credit('require(shares > 0);', 1)

    def test_arm_other_guard_does_not_cover_credit(self):
        self.check_credit('require(shares > 0);', 1, arm=True)

    def test_overwrite_then_guard_does_not_cover_credit(self):
        self.check_credit('minted = 0; require(minted > 0);', 1)

    def test_arm_overwrite_then_guard_does_not_cover_credit(self):
        self.check_credit('minted = 0; require(minted > 0);', 1, arm=True)


class Fix168Tests(unittest.TestCase):
    def test_each_arm_proves_its_own_credited_scalar(self):
        body = '''require(assets > 0);
            if (empty) {
                minted = assets;
                balances[msg.sender] += minted;
            } else {
                shares = assets * totalShares / totalAssets;
                require(shares > 0);
                balances[msg.sender] += shares;
            }'''
        self.assertEqual(mint_findings(body), [])

    def test_arm_must_prove_its_own_credit(self):
        body = '''require(assets > 0);
            if (empty) {
                minted = assets;
                balances[msg.sender] += minted;
            } else {
                shares = assets * totalShares / totalAssets;
                balances[msg.sender] += shares;
            }'''
        self.assertEqual(len(mint_findings(body)), 1)


    def test_post_join_consumer_requires_each_arm_credit(self):
        body = '''require(assets > 0);
            if (empty) {
                minted = assets;
                balances[msg.sender] += minted;
            } else {
                shares = assets * totalShares / totalAssets;
                require(shares > 0);
                balances[msg.sender] += shares;
            }
            return minted;'''
        self.assertEqual(len(mint_findings(body)), 1)


class Fix169Tests(unittest.TestCase):
    def test_post_join_return_without_branch_credit_requires_proof(self):
        for name in ('minted', 'shares'):
            with self.subTest(name=name):
                body = f'''uint256 {name} = assets * totalShares / totalAssets;
                    if (totalShares == 0) {{ {name} = 1; }}
                    else {{ totalAssets += assets; }}
                    return {name};'''
                self.assertEqual(len(mint_findings(body)), 1)

    def test_arm_can_guard_post_join_scalar_without_crediting_it(self):
        body = '''minted = assets * totalShares / totalAssets;
            if (totalShares == 0) { minted = 1; }
            else { require(minted > 0); totalAssets += assets; }
            return minted;'''
        self.assertEqual(mint_findings(body), [])


class Fix170Tests(unittest.TestCase):
    def check_prefix_credit(self, then_body, else_body, expected):
        body = f'''minted = assets * totalShares / totalAssets;
            balances[msg.sender] += minted;
            if (assets > 1) {{ {then_body} }}
            else {{ {else_body} }}'''
        self.assertEqual(len(mint_findings(body)), expected)

    def test_unrelated_chain_does_not_cover_prefix_credit(self):
        self.check_prefix_credit('totalAssets += assets;', 'totalAssets += 1;', 1)

    def test_both_arms_guard_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'require(minted > 0);', 0)

    def test_one_arm_guard_does_not_cover_prefix_credit(self):
        for guarded_then in (False, True):
            with self.subTest(guarded_then=guarded_then):
                guard, unrelated = 'require(minted > 0);', 'totalAssets += 1;'
                self.check_prefix_credit(
                    guard if guarded_then else unrelated,
                    unrelated if guarded_then else guard, 1)

    def test_arm_constant_overwrite_does_not_cover_prefix_credit(self):
        for tail in ('minted = 1;', 'minted = 1; require(minted > 0);'):
            with self.subTest(tail=tail):
                self.check_prefix_credit(tail, tail, 1)

    def test_prefix_overwrite_cannot_be_validated_by_arm_guards(self):
        body = '''minted = assets * totalShares / totalAssets;
            balances[msg.sender] += minted;
            minted = 1;
            if (assets > 1) { require(minted > 0); }
            else { require(minted > 0); }'''
        self.assertEqual(len(mint_findings(body)), 1)


class Fix171Tests(unittest.TestCase):
    def test_post_join_guard_discharges_its_scalar_obligation(self):
        body = '''uint256 shares = assets * totalShares / totalAssets;
            uint256 minted;
            if (totalShares == 0) { minted = 1; }
            else { minted = 2; }
            require(shares > 0);
            balances[msg.sender] += minted;
            return minted;'''
        self.assertEqual(mint_findings(body), [])

    def test_unguarded_post_join_return_still_requires_arm_proof(self):
        body = '''uint256 minted = assets * totalShares / totalAssets;
            if (totalShares == 0) { minted = 1; }
            else { totalAssets += assets; }
            return minted;'''
        self.assertEqual(len(mint_findings(body)), 1)

    def test_post_join_guard_does_not_discharge_another_scalar(self):
        body = '''uint256 minted = assets * totalShares / totalAssets;
            uint256 shares = assets;
            if (totalShares == 0) { minted = 1; }
            else { totalAssets += assets; }
            require(shares > 0);
            return minted;'''
        self.assertEqual(len(mint_findings(body)), 1)


class Fix172Tests(unittest.TestCase):
    def check_prefix_credit(self, then_body, else_body, expected):
        body = f'''uint256 minted = assets * totalShares / totalAssets;
            balances[msg.sender] += minted;
            if (assets > 1) {{ {then_body} }}
            else {{ {else_body} }}'''
        self.assertEqual(len(mint_findings(body)), expected)

    def test_final_revert_terminates_prefix_credit(self):
        for revert in ('revert();', 'revert("zero mint");', 'revert(failureCode());'):
            for reverting_then in (False, True):
                with self.subTest(revert=revert, reverting_then=reverting_then):
                    guard = 'require(minted > 0);'
                    self.check_prefix_credit(
                        revert if reverting_then else guard,
                        guard if reverting_then else revert, 0)

    def test_final_custom_error_revert_terminates_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'revert ZeroMint();', 0)

    def test_final_custom_error_revert_with_argument_terminates_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'revert ZeroMint(assets);', 0)

    def test_final_revert_prefixed_call_does_not_terminate_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'revertTokens();', 1)

    def test_final_qualified_custom_error_revert_terminates_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'revert Pool.ZeroMint();', 0)

    def test_unrelated_arms_still_leave_prefix_credit_unvalidated(self):
        self.check_prefix_credit('totalAssets += assets;', 'totalAssets += 1;', 1)

    def test_conditional_revert_does_not_terminate_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'if (assets == 0) { revert(); }', 1)

    def test_one_guard_and_continuing_arm_leave_prefix_credit_unvalidated(self):
        self.check_prefix_credit('require(minted > 0);', 'totalAssets += assets;', 1)

    def test_revert_followed_by_executable_statement_does_not_terminate(self):
        self.check_prefix_credit('require(minted > 0);', 'revert(); totalAssets += assets;', 1)

    def test_require_false_does_not_terminate_prefix_credit(self):
        self.check_prefix_credit('require(minted > 0);', 'require(false);', 1)
