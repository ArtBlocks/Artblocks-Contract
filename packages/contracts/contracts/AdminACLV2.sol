// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

import "./interfaces/v0.8.x/IAdminACLV0.sol";
import "./interfaces/v0.8.x/IAdminACLV1.sol";
import "./GenArt721CoreV3.sol";
import "@openzeppelin-4.7/contracts/access/Ownable.sol";
import "@openzeppelin-4.7/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin-4.7/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title Admin ACL contract, V2.
 * @author Art Blocks Inc.
 * @notice Privileged Roles and Ownership:
 * This contract has a single superAdmin that passes all ACL checks. It also
 * contains a set of additional superAdmin wallets who also pass all ACL
 * checks. Only the superAdmin may add or remove additional superAdmins.
 * All checks for any other address will return false.
 * The superAdmin can be changed by the current superAdmin.
 * Care must be taken to ensure that the admin ACL contract is secure behind a
 * multi-sig or other secure access control mechanism.
 * This contract continues to broadcast support (and require future-adminACL
 * broadcasted support) for IAdminACLV0 via ERC165 interface detection.
 */
contract AdminACLV2 is IAdminACLV1, ERC165 {
    // add Enumerable Set methods
    using EnumerableSet for EnumerableSet.AddressSet;

    string public AdminACLType = "AdminACLV2";

    /// superAdmin is the only address that passes any and all ACL checks
    address public superAdmin;

    // Set of addresses that have been granted additional superAdmin role
    EnumerableSet.AddressSet private _additionalSuperAdmins;

    constructor() {
        superAdmin = msg.sender;
    }

    /**
     * @notice Allows superAdmin change the superAdmin address.
     * @param _newSuperAdmin The new superAdmin address.
     * @param _genArt721CoreAddressesToUpdate Array of genArt721Core
     * addresses to update to the new superAdmin, for indexing purposes only.
     * @dev this function is gated to only superAdmin address.
     */
    function changeSuperAdmin(
        address _newSuperAdmin,
        address[] calldata _genArt721CoreAddressesToUpdate
    ) external {
        require(msg.sender == superAdmin, "Only superAdmin");
        address previousSuperAdmin = superAdmin;
        superAdmin = _newSuperAdmin;
        emit SuperAdminTransferred(
            previousSuperAdmin,
            _newSuperAdmin,
            _genArt721CoreAddressesToUpdate
        );
    }

    /**
     * Calls transferOwnership on other contract from this contract.
     * This is useful for updating to a new AdminACL contract.
     * @dev this function is gated to only superAdmin address.
     * @dev This implementation requires that the new AdminACL contract
     * broadcasts support of IAdminACLV0 via ERC165 interface detection.
     */
    function transferOwnershipOn(
        address _contract,
        address _newAdminACL
    ) external {
        require(msg.sender == superAdmin, "Only superAdmin");
        // ensure new AdminACL contract supports IAdminACLV0
        require(
            ERC165(_newAdminACL).supportsInterface(
                type(IAdminACLV0).interfaceId
            ),
            "AdminACLV2: new admin ACL does not support IAdminACLV0"
        );
        Ownable(_contract).transferOwnership(_newAdminACL);
    }

    /**
     * @notice Calls renounceOwnership on other contract from this contract.
     * @dev this function is gated to only superAdmin address.
     */
    function renounceOwnershipOn(address _contract) external {
        require(msg.sender == superAdmin, "Only superAdmin");
        Ownable(_contract).renounceOwnership();
    }

    /**
     * @notice Checks if sender `_sender` is allowed to call function with selector
     * `_selector` on contract `_contract`. Returns true if sender is superAdmin,
     * or if sender is in set of additional superAdmins.
     */
    function allowed(
        address _sender,
        address /*_contract*/,
        bytes4 /*_selector*/
    ) external view returns (bool) {
        // always allow superAdmin
        if (_sender == superAdmin) {
            return true;
        }
        // return if sender is in additional superAdmins set
        return _additionalSuperAdmins.contains(_sender);
    }

    /**
     *
     * @notice Adds address to additional superAdmin set. Only callable by
     * superAdmin (not an additional superAdmin). Address must not already
     * be in set.
     * @param additionalSuperAdmin Wallet to be added to additional superAdmin.
     */
    function addAditionalSuperAdmin(
        address additionalSuperAdmin,
        address[] calldata genArt721CoreAddressesToUpdate
    ) external {
        require(msg.sender == superAdmin, "Only superAdmin");
        require(
            _additionalSuperAdmins.add(additionalSuperAdmin),
            "AdminACLV2: Already registered"
        );
        emit AdditionalSuperAdminAdded(
            additionalSuperAdmin,
            genArt721CoreAddressesToUpdate
        );
    }

    /**
     *
     * @notice Removes address from additionalSuperAdmin set. Only callable by
     * superAdmin. Address must be in set.
     * @param additionalSuperAdmin NFT core address to be registered.
     */
    function removeAdditionalSuperAdmin(
        address additionalSuperAdmin,
        address[] calldata genArt721CoreAddressesToUpdate
    ) external {
        require(msg.sender == superAdmin, "Only superAdmin");
        require(
            _additionalSuperAdmins.remove(additionalSuperAdmin),
            "AdminACLV2: Not registered"
        );
        emit AdditionalSuperAdminRemoved(
            additionalSuperAdmin,
            genArt721CoreAddressesToUpdate
        );
    }

    /**
     * @notice Gets quantity of addresses registered as additional superAdmins
     * @return uint256 quantity of addresses approved
     */
    function getNumAdditionalSuperAdmins() external view returns (uint256) {
        return _additionalSuperAdmins.length();
    }

    /**
     * @notice Get additional superAdmin address at index
     * `_index` of enumerable set.
     * @param _index enumerable set index to query.
     * @return additionalSuperAdmin at index `_index`
     * @dev index must be < quantity of registered additional superAdmins
     */
    function getAdditionalSuperAdminAt(
        uint256 _index
    ) external view returns (address additionalSuperAdmin) {
        return _additionalSuperAdmins.at(_index);
    }

    /**
     * @notice Get array of all additional superAdmin addresses.
     * @dev unbounded gas, but unlikely to be encountered in practice.
     * @return address[] array of all additional superAdmin addresses
     */
    function getAdditionalSuperAdmins()
        external
        view
        returns (address[] memory)
    {
        return _additionalSuperAdmins.values();
    }

    /**
     * @inheritdoc ERC165
     */
    function supportsInterface(
        bytes4 interfaceId
    ) public view virtual override(ERC165) returns (bool) {
        return
            interfaceId == type(IAdminACLV0).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}
