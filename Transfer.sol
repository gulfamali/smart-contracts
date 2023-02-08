// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/metatx/ERC2771Context.sol";

interface IERC20 {
    function transfer(address recipient, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract Transfer is ERC2771Context {
  // A modifier that only allows the trusted relayer to call
  // the required target function: `incrementContext`
  modifier onlyTrustedForwarder() {
      require(
          isTrustedForwarder(msg.sender),
          "Only callable by Trusted Forwarder"
      );
      _;
  }

  // ERC2771Context: setting the immutable trusted relayer variable
  constructor(address trustedForwarder) ERC2771Context(trustedForwarder) {}

  function transferFrom(address token, address recipient, uint256 value) external onlyTrustedForwarder {
    require(IERC20(token).transferFrom(_msgSender(), recipient, value));
  }
}
