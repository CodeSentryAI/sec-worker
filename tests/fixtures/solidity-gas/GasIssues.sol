// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract GasIssues {
    uint256 public total;
    mapping(address => uint256) public balances;

    function andInIf(bool a, bool b) external pure returns (bool) {
        if (a && b) {
            return true;
        }
        return false;
    }

    function addToTotal(uint256[] calldata xs) external {
        uint256 len = xs.length;
        for (uint256 i; i < len; ++i) {
            total += xs[i];
        }
    }
}
