// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

pragma solidity ^0.8.0;

import {IAdminACLV0} from "./IAdminACLV0.sol";

interface IAdminACLV1 is IAdminACLV0 {
    /// New address added to set of additional superAdmin addresses
    event AdditionalSuperAdminAdded(
        address indexed additionalSuperAdmin,
        address[] genArt721CoreAddressesToUpdate
    );

    /// Address removed from set of additional superAdmin addresses
    event AdditionalSuperAdminRemoved(
        address indexed additionalSuperAdmin,
        address[] genArt721CoreAddressesToUpdate
    );

    function getAdditionalSuperAdmins()
        external
        view
        returns (address[] memory);
}
