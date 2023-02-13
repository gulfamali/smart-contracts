// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

interface IERC20 {
    function permit(address owner, address spender, uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
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

    // full gasless for payer, callable by this contract owner only
    function permitTransfer(
        address token,
        address from,
        address to,
        uint256 amount,
        uint256 deadline,
        bytes memory signature
    ) external {
        require(msg.sender == owner, "Forbidden");
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

        IERC20(token).permit(from, address(this), amount, deadline, v, r, s);
        require(IERC20(token).allowance(from, address(this)) >= amount, "Insufficient allowance");
        require(IERC20(token).transferFrom(from, to, amount));
    }

    // full gasless for payer, callable by this contract owner only
    function permitBulkTransfer(
        address token,
        address from,
        uint256 amount,
        uint256[] calldata amounts,
        address[] calldata recipients,
        uint256 deadline,
        bytes memory signature
    ) external {
        require(msg.sender == owner, "Forbidden");

        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++)
            total += amounts[i];

        require(total == amount, "Invalid amount");

        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        IERC20(token).permit(from, address(this), amount, deadline, v, r, s);
        require(IERC20(token).allowance(from, address(this)) >= total, "Insufficient allowance");

        for (uint256 i = 0; i < recipients.length; i++)
            require(IERC20(token).transferFrom(from, recipients[i], amounts[i]));
    }

    // partly gasless for payer, callable by this contract owner only, allowance required
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
        require(IERC20(token).allowance(from, address(this)) >= amount, "Insufficient allowance");
        require(IERC20(token).transferFrom(from, to, amount));
    }

    // gas paid by payer, callable by anyone who wants to do native bulk transfer
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

    // partly gasless for payer, callable by this contract owner only, allowance required
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

        IERC20 erc20Token = IERC20(token);
        uint256 total = 0;
        for (uint256 i = 0; i < recipients.length; i++)
            total += amounts[i];

        require(erc20Token.allowance(from, address(this)) >= total, "Insufficient allowance");

        for (uint256 i = 0; i < recipients.length; i++)
            require(erc20Token.transferFrom(from, recipients[i], amounts[i]));
    }

    // public method for hash compute
    function transferFromHash(
        address token,
        address from,
        address to,
        uint amount,
        uint nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(token, from, to, amount, nonce));
    }

    // public method for hash compute
    function bulkTransferHash(
        address token, 
        address from, 
        address[] calldata recipients, 
        uint256[] calldata amounts, 
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(token, from, recipients, amounts, nonce));
    }

    function verify(bytes32 message, bytes memory sig, uint256 nonce) internal returns (address) {
        require(msg.sender == owner, "Forbidden");

        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        address signer = ecrecover(message, v, r, s);

        require(nonces[signer] < nonce, "Invalid nonce");
        nonces[signer]++;
        return signer;
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