// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {SafeSplitter} from "../src/SafeSplitter.sol";

contract SafeSplitterTraversalTest is Test {
    function testTraversalDefersNewPayeeUntilNextPass() public {
        SafeSplitter splitter = new SafeSplitter();
        address latePayee = makeAddr("latePayee");

        splitter.register{value: 1 wei}();
        for (uint256 i; i < splitter.MAX_BATCH(); ++i) {
            address original = makeAddr(string.concat("original", vm.toString(i)));
            vm.deal(original, 1 wei);
            vm.prank(original);
            splitter.register{value: 1 wei}();
        }
        assertFalse(splitter.distribute(splitter.MAX_BATCH()));

        vm.deal(latePayee, 1 wei);
        for (uint256 i; i < splitter.MAX_BATCH() + 1; ++i) {
            address registrant = i == splitter.MAX_BATCH() ? latePayee : makeAddr(string.concat("late", vm.toString(i)));
            vm.deal(registrant, 1 wei);
            vm.prank(registrant);
            splitter.register{value: 1 wei}();
        }

        assertTrue(splitter.distribute(1));
        assertEq(splitter.cursor(), 0);
        assertEq(splitter.pending(latePayee), 1 wei);
        assertEq(splitter.owed(latePayee), 0);

        assertFalse(splitter.distribute(splitter.MAX_BATCH()));
        for (uint256 i; i < splitter.MAX_BATCH(); ++i) {
            splitter.distribute(splitter.MAX_BATCH());
        }
        assertTrue(splitter.distribute(splitter.MAX_BATCH()));
        assertEq(splitter.pending(latePayee), 0);
        assertEq(splitter.owed(latePayee), 1 wei);
    }
}
