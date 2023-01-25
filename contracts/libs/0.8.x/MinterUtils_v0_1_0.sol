// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

pragma solidity ^0.8.0;

/**
 * @title Art Blocks Minter Utils Library
 * @notice A collection of utility functions that may be used across the Art
 * Blocks minter ecosystem.
 * Semantic versioning is used in the solidity file name, and is therefore
 * controlled by contracts importing the appropriate filename version.
 * @author Art Blocks Inc.
 */
library MinterUtils {
    /**
     * @notice Validates that a GenArt721CoreV3 core contract's
     * `getPrimaryRevenueSplits` function returns the expected number of
     * return values based on the `isEngine` expected state of the core
     * contract.
     * @param isEngine Whether the core contract is expected to be an Art
     * Blocks Engine contract or not.
     * @param genArt721CoreAddress The address of the deployed core contract.
     */
    function ValidateV3CoreGetPrimaryRevenueSplitsResponse(
        bool isEngine,
        address genArt721CoreAddress
    ) internal {
        // confirm split payment returns expected qty of return values to
        // add protection against a misconfigured isEngine state
        bytes memory payload = abi.encodeWithSignature(
            "getPrimaryRevenueSplits(uint256,uint256)",
            0,
            0
        );
        (bool success, bytes memory returnData) = genArt721CoreAddress.call(
            payload
        );
        require(success);
        if (isEngine) {
            // require 8 32-byte words returned if engine
            require(
                returnData.length == 8 * 32,
                "Unexpected revenue split bytes"
            );
        } else {
            // require 6 32-byte words returned if flagship (not engine)
            require(
                returnData.length == 6 * 32,
                "Unexpected revenue split bytes"
            );
        }
    }
}
