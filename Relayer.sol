// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

interface IERC20 {
    function transfer(address recipient, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract Relayer {

    address owner;
    mapping(address => mapping( uint256 => bool)) nonces;

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
        require(msg.sender == owner, "Forbidden");
        require(!nonces[msg.sender][nonce], "Invalid nonce");

        bytes32 message = prefixed(keccak256(abi.encodePacked(from, to, amount, nonce, this)));
        require(verify(message, signature) == from, "Invalid signature");

        nonces[msg.sender][nonce] = true;

        require(IERC20(token).transferFrom(from, to, amount));
    }

    function verify(bytes32 message, bytes memory sig) internal pure returns (address) {
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