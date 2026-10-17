// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import "./Base.sol";

contract Token is Base {
    constructor(uint256 initialSupply) {
        totalSupply = initialSupply;
        balanceOf[msg.sender] = initialSupply;
        emit Transfer(address(0), msg.sender, initialSupply);
    }
}
