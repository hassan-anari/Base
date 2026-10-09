// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
// Disposable acceptance chain fixture, never deployed to a public network.
contract AcceptanceToken {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    constructor(address holder) { balanceOf[holder] = 1000000000; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
