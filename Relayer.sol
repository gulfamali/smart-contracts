// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

interface IERC20 {
    function allowance(address owner, address spender) external view returns (uint);
    function transfer(address recipient, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract Relayer {

    address owner;
    mapping(address => uint256) nonces;

    constructor() {
        owner = msg.sender;
    }

    function transferFrom(
        address token,
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes memory signature
    ) external {
        bytes32 signedMessage = prefixed(transferFromHash(token, from, to, amount, nonce));
        require(verify(signedMessage, signature, nonce) == from, "Invalid signature");
        nonces[msg.sender]++;

        require(IERC20(token).transferFrom(from, to, amount));
    }

    function transferFromHash(
        address token,
        address from,
        address to,
        uint amount,
        uint nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(token, from, to, amount, nonce));
    }

    function bulkNativeTransfer(
        address[] calldata recipients, 
        uint256[] calldata amounts
    ) external payable {
        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++)
            total += amounts[i];
        
        require(msg.value == total, "Insufficient amount received");

        for (uint256 i = 0; i < recipients.length; i++)
            payable(recipients[i]).transfer(amounts[i]);
    }

    function bulkTransfer(
        address token, 
        address from, 
        address[] calldata recipients, 
        uint256[] calldata amounts, 
        uint256 nonce,
        bytes memory signature
    ) external {
        bytes32 signedMessage = prefixed(bulkTransferHash(token, from, recipients, amounts, nonce));
        require(verify(signedMessage, signature, nonce) == from, "Invalid signature");
        nonces[msg.sender]++;

        IERC20 erc20Token = IERC20(token);
        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++)
            total += amounts[i];

        require(erc20Token.allowance(from, address(this)) >= total, "Insufficient allowance");

        for (uint256 i = 0; i < recipients.length; i++)
            require(erc20Token.transferFrom(from, recipients[i], amounts[i]));
    }

    function bulkTransferHash(
        address token, 
        address from, 
        address[] calldata recipients, 
        uint256[] calldata amounts, 
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(token, from, recipients, amounts, nonce));
    }

    function verify(bytes32 message, bytes memory sig, uint256 nonce) internal view returns (address) {
        require(msg.sender == owner, "Forbidden");
        require(nonces[msg.sender] < nonce, "Invalid nonce");

        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(message, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        require(sig.length == 65, "invalid signature length");

        assembly {
            // first 32 bytes, after the length prefix
            r := mload(add(sig, 32))
            // second 32 bytes
            s := mload(add(sig, 64))
            // final byte (first byte of the next 32 bytes)
            v := byte(0, mload(add(sig, 96)))
        }

        return (v, r, s);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }
}