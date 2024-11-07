// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.23;

import "./RemoveOwnerBase.t.sol";

contract RemoveOwnerAtIndexTest is RemoveOwnerBaseTest {
    function test_reverts_ifIsLastOwner() public {
        // note this could be fuzzed but it takes a very long time to complete
        uint256 owners = 3;
        MockMultiOwnable mock = new MockMultiOwnable();
        address firstOnwer = makeAddr("first");
        bytes[] memory initialOwners = new bytes[](1);
        initialOwners[0] = abi.encode(firstOnwer);
        mock.init(initialOwners);
        assertEq(mock.nextOwnerIndex(), 1);
        assertEq(mock.removedOwnersCount(), 0);
        assertEq(mock.ownerCount(), 1);
        vm.startPrank(firstOnwer);
        for (uint256 i; i < owners; i++) {

            // mock.addOwnerAddress(makeAddr(string(abi.encodePacked(i))));
            // assertEq(mock.nextOwnerIndex(), i + 2);
            // assertEq(mock.ownerCount(), i + 2);

            address newOwner = makeAddr(string(abi.encodePacked(i)));
            mock.addOwnerAddress(newOwner);
            assertEq(mock.nextOwnerIndex(), i + 2);
            assertEq(mock.ownerCount(), i + 2);
            emit log_uint(i); // Log the new owner's address
            emit log_address(newOwner); // Log the new owner's address


        }
        for (uint256 i = 1; i < owners + 1; i++) {
            // mock.removeOwnerAtIndex(i, abi.encode(makeAddr(string(abi.encodePacked(i - 1)))));
            // assertEq(mock.removedOwnersCount(), i);
            // assertEq(mock.ownerCount(), owners - i + 1);

            
            address ownerToRemove = makeAddr(string(abi.encodePacked(i - 1)));
            mock.removeOwnerAtIndex(i, abi.encode(ownerToRemove));
            assertEq(mock.removedOwnersCount(), i);
            assertEq(mock.ownerCount(), owners - i + 1);
            emit log_address(ownerToRemove); // Log the removed owner's address

            
        }
        vm.expectRevert(MultiOwnable.LastOwner.selector);
        mock.removeOwnerAtIndex(0, abi.encode(firstOnwer));
    }
}
