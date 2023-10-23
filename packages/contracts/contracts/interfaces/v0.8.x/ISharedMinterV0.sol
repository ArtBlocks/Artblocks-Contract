// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

pragma solidity ^0.8.0;

interface ISharedMinterV0 {
    // This section defines events for generic project minter configuration updates
    /**
     * @dev Strings not supported. Recommend conversion of (short) strings to
     * bytes32 to remain gas-efficient.
     */
    /**
     * @notice Generic project minter configuration event. Removes key `key`
     * for project `projectId`.
     */
    event ConfigKeyRemoved(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key
    );
    /// BOOL
    /**
     * @notice Generic project minter configuration event. Sets value of key
     * `key` to `value` for project `projectId`.
     */
    event ConfigValueSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        bool value
    );
    /// UINT256
    /**
     * @notice Generic project minter configuration event. Sets value of key
     * `key` to `value` for project `projectId`.
     */
    event ConfigValueSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        uint256 value
    );
    /**
     * @notice Generic project minter configuration event. Adds value `value`
     * to the set of uint256 at key `key` for project `projectId`.
     */
    event ConfigValueAddedToSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        uint256 value
    );
    /**
     * @notice Generic project minter configuration event. Removes value
     * `value` to the set of uint256 at key `key` for project `projectId`.
     */
    event ConfigValueRemovedFromSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        uint256 value
    );
    /// ADDRESS
    /**
     * @notice Generic project minter configuration event. Sets value of key
     * `key` to `value` for project `projectId`.
     */
    event ConfigValueSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        address value
    );
    /**
     * @notice Generic project minter configuration event. Adds value `value`
     * to the set of addresses at key `key` for project `projectId`.
     */
    event ConfigValueAddedToSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        address value
    );
    /**
     * @notice Generic project minter configuration event. Removes value
     * `value` to the set of addresses at key `key` for project `projectId`.
     */
    event ConfigValueRemovedFromSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        address value
    );
    /// BYTES32
    /**
     * @notice Generic project minter configuration event. Sets value of key
     * `key` to `value` for project `projectId`.
     */
    event ConfigValueSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        bytes32 value
    );
    /**
     * @notice Generic project minter configuration event. Adds value `value`
     * to the set of bytes32 at key `key` for project `projectId`.
     */
    event ConfigValueAddedToSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        bytes32 value
    );
    /**
     * @notice Generic project minter configuration event. Removes value
     * `value` to the set of bytes32 at key `key` for project `projectId`.
     */
    event ConfigValueRemovedFromSet(
        uint256 indexed projectId,
        address indexed coreContract,
        bytes32 key,
        bytes32 value
    );

    ///////////////////////////

    // Sets the local max invocations for a given project, checking that the provided max invocations is
    // less than or equal to the global max invocations for the project set on the core contract.
    // This does not impact the max invocations value defined on the core contract.
    function manuallyLimitProjectMaxInvocations(
        uint256 projectId,
        address coreContract,
        uint24 maxInvocations
    ) external;

    // Called to make the minter contract aware of the max invocations for a
    // given project.
    function syncProjectMaxInvocationsToCore(
        uint256 projectId,
        address coreContract
    ) external;

    // getter function of public variable
    function minterType() external view returns (string memory);

    function minterFilterAddress() external returns (address);

    // Gets if token price is configured, token price in wei, currency symbol,
    // and currency address, assuming this is project's minter.
    // Supersedes any defined core price.
    function getPriceInfo(
        uint256 projectId,
        address coreContract
    )
        external
        view
        returns (
            bool isConfigured,
            uint256 tokenPriceInWei,
            string memory currencySymbol,
            address currencyAddress
        );
}
