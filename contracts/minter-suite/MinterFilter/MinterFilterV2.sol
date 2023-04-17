// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

pragma solidity 0.8.17;

import "../../interfaces/0.8.x/IMinterFilterV1.sol";
import "../../interfaces/0.8.x/IFilteredMinterV0.sol";
import "../../interfaces/0.8.x/IGenArt721CoreContractV3_Base.sol";
import "../../interfaces/0.8.x/IEngineRegistryV1.sol";

import "../../libs/0.8.x/Bytes32Strings.sol";

import "@openzeppelin-4.7/contracts/access/Ownable.sol";
import "@openzeppelin-4.7/contracts/utils/structs/EnumerableMap.sol";
import "@openzeppelin-4.7/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title MinterFilterV2
 * @dev At the time of deployment, this contract is intended to be used with
 * core contracts that implement IGenArt721CoreContractV3_Base.
 * @author Art Blocks Inc.
 * @notice This Minter Filter V2 contract allows minters to be set on a
 * per-project basis, for any registered core contract. This minter filter does
 * not extend the previous version of the minter filters, as the previous
 * version is not compatible with multiple core contracts.
 *
 * This contract is designed to be managed by an Admin ACL contract, as well as
 * delegated privileges to core contract artists and Admin ACL contracts.
 * These roles hold extensive power and can arbitrarily control and modify
 * how a project's tokens may be minted.
 * Care must be taken to ensure that the admin ACL contract and artist
 * addresses are secure behind a multi-sig or other access control mechanism.
 * ----------------------------------------------------------------------------
 * The following functions are restricted as allowed by this contract's Admin
 * ACL:
 * - updateEngineRegistry
 * - approveMinterGlobally
 * - revokeMinterGlobally
 * - removeMintersForProjectsOnContracts
 * ----------------------------------------------------------------------------
 * The following functions are restricted as allowed by each core contract's
 * Admin ACL contract:
 * - approveMinterForContract
 * - revokeMinterForContract
 * - removeMintersForProjectsOnContract
 * ----------------------------------------------------------------------------
 * The following functions are restricted as allowed by each core contract's
 * Admin ACL contract, or to the artist address of the project:
 * - setMinterForProject
 * - removeMinterForProject
 * ----------------------------------------------------------------------------
 * Additional admin and artist privileged roles may be described on minters,
 * registries, and other contracts that may interact with this contract.
 */
contract MinterFilterV2 is Ownable, IMinterFilterV1 {
    // add Enumerable Map methods
    using EnumerableMap for EnumerableMap.UintToAddressMap;
    using EnumerableSet for EnumerableSet.AddressSet;
    // add Bytes32Strings methods
    using Bytes32Strings for bytes32;

    /// version & type of this core contract
    bytes32 constant MINTER_FILTER_VERSION = "v2.0.0";

    function minterFilterVersion() external pure returns (string memory) {
        return MINTER_FILTER_VERSION.toString();
    }

    bytes32 constant MINTER_FILTER_TYPE = "MinterFilterV2";

    function minterFilterType() external pure returns (string memory) {
        return MINTER_FILTER_TYPE.toString();
    }

    /// Admin ACL contract for this minter filter
    IAdminACLV0 public adminACLContract;

    /**
     * @notice Engine registry, that tracks all registered core contracts
     * @dev the engine registry is assumed to also register flagship and
     * collaboration contracts.
     */
    IEngineRegistryV1 public engineRegistry;

    /// minter address => qty projects across all core contracts currently
    /// using the minter
    mapping(address => uint256) public numProjectsUsingMinter;

    /**
     * Enumerable Set of globally approved minters.
     * This is a Set of addresses that are approved to mint on any
     * project, for any core contract.
     * @dev note that contract admins can extend a separate Set of minters for
     * their core contract via the `approveMinterForContract` function.
     */
    EnumerableSet.AddressSet private globallyApprovedMinters;

    /**
     * Mapping of core contract addresses to Enumerable Sets of approved
     * minters for that core contract.
     * @dev note that contract admins can extend this Set for their core
     * contract by via the `approveMinterForContract` function, and can remove
     * minters from this Set via the `revokeMinterForContract` function.
     */
    mapping(address => EnumerableSet.AddressSet)
        private contractApprovedMinters;

    /**
     * Mapping of core contract addresses to Enumerable Maps of project IDs to
     * minter addresses.
     */
    mapping(address => EnumerableMap.UintToAddressMap) private minterForProject;

    function _onlyNonZeroAddress(address _address) internal pure {
        require(_address != address(0), "Only non-zero address");
    }

    /**
     * @notice Function to restrict access to only AdminACL allowed calls
     * on a given core contract.
     * @dev defers to the ACL contract used by the core contract
     * @param _selector function selector to be checked
     */
    function _onlyAdminACL(bytes4 _selector) internal {
        require(
            adminACLAllowed(msg.sender, address(this), _selector),
            "Only Admin ACL allowed"
        );
    }

    /**
     * @notice Function to restrict access to only AdminACL allowed calls
     * on a given core contract.
     * @dev defers to the ACL contract used by the core contract
     * @param _coreContract core contract address
     * @param _selector function selector to be checked
     */
    function _onlyCoreAdminACL(
        address _coreContract,
        bytes4 _selector
    ) internal {
        require(
            IGenArt721CoreContractV3_Base(_coreContract).adminACLAllowed(
                msg.sender,
                address(this),
                _selector
            ),
            "Only Core AdminACL allowed"
        );
    }

    // function to restrict access to only core AdminACL or the project artist
    function _onlyCoreAdminACLOrArtist(
        uint256 _projectId,
        address _coreContract,
        bytes4 _selector
    ) internal {
        IGenArt721CoreContractV3_Base genArtCoreContract_Base = IGenArt721CoreContractV3_Base(
                _coreContract
            );
        require(
            (msg.sender ==
                genArtCoreContract_Base.projectIdToArtistAddress(_projectId)) ||
                (
                    genArtCoreContract_Base.adminACLAllowed(
                        msg.sender,
                        address(this),
                        _selector
                    )
                ),
            "Only Artist or Core Admin ACL"
        );
    }

    // function to restrict access to only core contracts registered with the
    // currently configured engine registry. This is used to prevent
    // non-registered core contracts from being used with this minter filter.
    function _onlyRegisteredCoreContract(address _coreContract) internal view {
        // @dev use engine registry to check if core contract is registered
        require(
            engineRegistry.isRegisteredContract(_coreContract),
            "Only registered core contract"
        );
    }

    // function to restrict access to only valid project IDs
    function _onlyValidProjectId(
        uint256 _projectId,
        address _coreContract
    ) internal view {
        IGenArt721CoreContractV3_Base genArtCoreContract = IGenArt721CoreContractV3_Base(
                _coreContract
            );
        require(
            (_projectId >= genArtCoreContract.startingProjectId()) &&
                (_projectId < genArtCoreContract.nextProjectId()),
            "Only valid project ID"
        );
    }

    // checks if minter is globally approved or approved for a core contract
    function _onlyApprovedMinter(
        address _coreContract,
        address _minter
    ) internal view {
        require(
            globallyApprovedMinters.contains(_minter) ||
                contractApprovedMinters[_coreContract].contains(_minter),
            "Only approved minters"
        );
    }

    /**
     * @notice Initializes contract to be a Minter for `_genArt721Address`.
     * @param _adminACLContract Address of admin access control contract, to be
     * set as contract owner.
     * @param _engineRegistry Address of engine registry contract.
     */
    constructor(address _adminACLContract, address _engineRegistry) {
        // set AdminACL management contract as owner
        _transferOwnership(_adminACLContract);
        // set engine registry contract
        _updateEngineRegistry(_engineRegistry);
        emit Deployed();
    }

    /// @dev override to prevent renouncing ownership
    /// @dev not permission gated since this immediately reverts
    function renounceOwnership() public pure override {
        revert("Cannot renounce ownership");
    }

    /**
     * @notice Updates the engine registry contract to be used by this contract.
     * Only callable as allowed by AdminACL of this contract.
     * @param _engineRegistry Address of the new engine registry contract.
     */
    function updateEngineRegistry(address _engineRegistry) external {
        _onlyAdminACL(this.updateEngineRegistry.selector);
        _updateEngineRegistry(_engineRegistry);
    }

    /**
     * @notice Globally approves minter `_minter` to be available for
     * minting on any project, for any core contract.
     * Only callable as allowed by AdminACL of this contract.
     * @dev Reverts if minter is already globally approved, or does not
     * implement minterType().
     * @param _minter Minter to be approved.
     */
    function approveMinterGlobally(address _minter) external {
        _onlyAdminACL(this.approveMinterGlobally.selector);
        // @dev add() returns true only if the value was not already in the Set
        require(
            globallyApprovedMinters.add(_minter),
            "Minter already approved"
        );
        emit MinterApprovedGlobally(
            _minter,
            IFilteredMinterV0(_minter).minterType()
        );
    }

    /**
     * @notice Removes previously globally approved minter `_minter`
     * from the list of globally approved minters.
     * Only callable as allowed by AdminACL of this contract.
     * Reverts if minter is not globally approved, or if minter is still
     * in use by any project.
     * @dev intentionally do not check if minter is still in use by any
     * project, meaning that any projects currently using the minter will
     * continue to be able to use it. If existing projects should be forced
     * to discontinue using a minter, the minter may be removed by the minter
     * filter admin in bulk via the `TODO` function.
     * @param _minter Minter to remove.
     */
    function revokeMinterGlobally(address _minter) external {
        _onlyAdminACL(this.revokeMinterGlobally.selector);
        // @dev remove() returns true only if the value was already in the Set
        require(
            globallyApprovedMinters.remove(_minter),
            "Only previously approved minter"
        );
        emit MinterRevokedGlobally(_minter);
    }

    /**
     * @notice Approves minter `_minter` to be available for minting on
     * any project on core contarct `_coreContract`.
     * Only callable as allowed by AdminACL of core contract `_coreContract`.
     * Reverts if core contract is not registered, if minter is already
     * approved for the contract, or if minter does not implement minterType().
     * @param _minter Minter to be approved.
     * @param _coreContract Core contract to approve minter for.
     */
    function approveMinterForContract(
        address _coreContract,
        address _minter
    ) external {
        _onlyRegisteredCoreContract(_coreContract);
        _onlyCoreAdminACL(
            _coreContract,
            this.approveMinterForContract.selector
        );
        // @dev add() returns true only if the value was not already in the Set
        require(
            contractApprovedMinters[_coreContract].add(_minter),
            "Minter already approved"
        );
        emit MinterApprovedForContract(
            _coreContract,
            _minter,
            IFilteredMinterV0(_minter).minterType()
        );
    }

    /**
     * @notice Removes previously approved minter `_minter` from the
     * list of approved minters on core contract `_coreContract`.
     * Only callable as allowed by AdminACL of core contract `_coreContract`.
     * Reverts if core contract is not registered, or if minter is not approved
     * on contract.
     * @dev intentionally does not check if minter is still in use by any
     * project, meaning that any projects currently using the minter will
     * continue to be able to use it. If existing projects should be forced
     * to discontinue using a minter, the minter may be removed by the contract
     * admin in bulk via the `TODO` function.
     * @param _minter Minter to remove.
     */
    function revokeMinterForContract(
        address _coreContract,
        address _minter
    ) external {
        _onlyRegisteredCoreContract(_coreContract);
        _onlyCoreAdminACL(_coreContract, this.revokeMinterForContract.selector);
        // @dev intentionally do not check if minter is still in use by any
        // project, since it is possible that a different contract's project is
        // using the minter
        // @dev remove() returns true only if the value was already in the Set
        require(
            contractApprovedMinters[_coreContract].remove(_minter),
            "Only previously approved minter"
        );
        emit MinterRevokedForContract(_coreContract, _minter);
    }

    /**
     * @notice Sets minter for project `_projectId` on contract `_coreContract`
     * to minter `_minter`.
     * Only callable by the project's artist or as allowed by AdminACL of
     * core contract `_coreContract`.
     * Reverts if:
     *  - core contract is not registered
     *  - minter is not approved globally on this minter filter or for the
     *    project's core contract
     *  - project is not valid on the core contract
     *  - function is called by an address other than the project's artist
     *    or a sender allowed by the core contract's admin ACL
     *  - minter does not implement minterType()
     * @param _projectId Project ID to set minter for.
     * @param _coreContract Core contract of project.
     * @param _minter Minter to be the project's minter.
     */
    function setMinterForProject(
        uint256 _projectId,
        address _coreContract,
        address _minter
    ) external {
        /// CHECKS
        _onlyRegisteredCoreContract(_coreContract);
        _onlyCoreAdminACLOrArtist(
            _projectId,
            _coreContract,
            this.setMinterForProject.selector
        );
        _onlyApprovedMinter(_coreContract, _minter);
        _onlyValidProjectId(_projectId, _coreContract);
        /// EFFECTS
        // decrement number of projects using a previous minter
        (bool hasPreviousMinter, address previousMinter) = minterForProject[
            _coreContract
        ].tryGet(_projectId);
        if (hasPreviousMinter) {
            numProjectsUsingMinter[previousMinter]--;
        }
        // assign new minter
        numProjectsUsingMinter[_minter]++;
        minterForProject[_coreContract].set(_projectId, _minter);
        emit ProjectMinterRegistered(
            _projectId,
            _coreContract,
            _minter,
            IFilteredMinterV0(_minter).minterType()
        );
    }

    /**
     * @notice Updates project `_projectId` on contract `_coreContract` to have
     * no configured minter.
     * Only callable by the project's artist or as allowed by AdminACL of
     * core contract `_coreContract`.
     * Reverts if:
     *  - core contract is not registered
     *  - project does not already have a minter assigned
     *  - function is called by an address other than the project's artist
     *    or a sender allowed by the core contract's admin ACL
     * @param _projectId Project ID to remove minter for.
     * @param _coreContract Core contract of project.
     * @dev requires project to have an assigned minter
     */
    function removeMinterForProject(
        uint256 _projectId,
        address _coreContract
    ) external {
        _onlyRegisteredCoreContract(_coreContract);
        _onlyCoreAdminACLOrArtist(
            _projectId,
            _coreContract,
            this.removeMinterForProject.selector
        );
        // @dev this will revert if project does not have a minter
        _removeMinterForProject(_projectId, _coreContract);
    }

    /**
     * @notice Updates an array of project IDs to have no configured minter.
     * Only callable as allowed by AdminACL of core contract `_coreContract`.
     * Reverts if the core contract is not registered, or if any project does
     * not already have a minter assigned.
     * @param _projectIds Array of project IDs to remove minters for.
     * @dev caution with respect to single tx gas limits
     */
    function removeMintersForProjectsOnContract(
        uint256[] calldata _projectIds,
        address _coreContract
    ) external {
        _onlyRegisteredCoreContract(_coreContract);
        _onlyCoreAdminACL(
            _coreContract,
            this.removeMintersForProjectsOnContract.selector
        );
        uint256 numProjects = _projectIds.length;
        for (uint256 i; i < numProjects; ) {
            _removeMinterForProject(_projectIds[i], _coreContract);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @notice Mint a token from project `_projectId` on contract
     * `_coreContract` to `_to`, originally purchased by `sender`.
     * @param _to The new token's owner.
     * @param _projectId Project ID to mint a new token on.
     * @param _sender Address purchasing a new token.
     * @param _coreContract Core contract of project.
     * @return tokenId Token ID of minted token
     * @dev reverts w/nonexistent key error when project has no assigned minter
     * @dev does not check if core contract is registered, for gas efficiency
     * and because project must have already been assigned a minter, which
     * requires the core contract to have been previously registered. If core
     * contract was unregistered but the project still has an assigned minter,
     * minting will remain possible.
     * @dev function name is optimized for gas.
     */
    function mint_joo(
        address _to,
        uint256 _projectId,
        address _coreContract,
        address _sender
    ) external returns (uint256 tokenId) {
        // CHECKS
        // minter is the project's minter
        require(
            msg.sender == minterForProject[_coreContract].get(_projectId),
            "Only assigned minter"
        );
        // INTERACTIONS
        tokenId = IGenArt721CoreContractV3_Base(_coreContract).mint_Ecf(
            _to,
            _projectId,
            _sender
        );
        return tokenId;
    }

    /**
     * @notice Gets the assigned minter for project `_projectId` on core
     * contract `_coreContract`.
     * Reverts if project does not have an assigned minter.
     * @param _projectId Project ID to query.
     * @param _coreContract Core contract of project.
     * @return address Minter address assigned to project
     * @dev requires project to have an assigned minter
     * @dev this function intentionally does not check that the core contract
     * is registered, since it must have been registered at the time the
     * project was assigned a minter
     */
    function getMinterForProject(
        uint256 _projectId,
        address _coreContract
    ) external view returns (address) {
        (bool hasMinter, address currentMinter) = minterForProject[
            _coreContract
        ].tryGet(_projectId);
        require(hasMinter, "No minter assigned");
        return currentMinter;
    }

    /**
     * @notice Queries if project `_projectId` on core contract `_coreContract`
     * has an assigned minter.
     * @param _projectId Project ID to query.
     * @param _coreContract Core contract of project.
     * @return bool true if project has an assigned minter, else false
     * @dev requires project to have an assigned minter
     * @dev this function intentionally does not check that the core contract
     * is registered, since it must have been registered at the time the
     * project was assigned a minter
     */
    function projectHasMinter(
        uint256 _projectId,
        address _coreContract
    ) external view returns (bool) {
        (bool hasMinter, ) = minterForProject[_coreContract].tryGet(_projectId);
        return hasMinter;
    }

    /**
     * @notice Gets quantity of projects on a given core contract that have
     * assigned minters.
     * @param _coreContract Core contract to query.
     * @return uint256 quantity of projects that have assigned minters
     * @dev this function intentionally does not check that the core contract
     * is registered, since it must have been registered at the time the
     * project was assigned a minter
     */
    function getNumProjectsOnContractWithMinters(
        address _coreContract
    ) external view returns (uint256) {
        return minterForProject[_coreContract].length();
    }

    /**
     * @notice Get project ID and minter address at index `_index` of
     * enumerable map.
     * @param _coreContract Core contract to query.
     * @param _index enumerable map index to query.
     * @return projectId project ID at index `_index`
     * @return minterAddress minter address for project at index `_index`
     * @return minterType minter type of minter at minterAddress
     * @dev index must be < quantity of projects that have assigned minters,
     * otherwise reverts
     * @dev reverts if minter does not implement minterType() function
     * @dev this function intentionally does not check that the core contract
     * is registered, since it must have been registered at the time the
     * project was assigned a minter
     */
    function getProjectAndMinterInfoOnContractAt(
        address _coreContract,
        uint256 _index
    )
        external
        view
        returns (
            uint256 projectId,
            address minterAddress,
            string memory minterType
        )
    {
        // @dev at() reverts if index is out of bounds
        (projectId, minterAddress) = minterForProject[_coreContract].at(_index);
        minterType = IFilteredMinterV0(minterAddress).minterType();
        return (projectId, minterAddress, minterType);
    }

    /**
     * @notice View that returns if a core contract is registered with the
     * engine registry, allowing this minter filter to service it.
     * @param _coreContract core contract address to be checked
     * @return bool true if core contract is registered, else false
     */
    function isRegisteredCoreContract(
        address _coreContract
    ) external view override returns (bool) {
        return engineRegistry.isRegisteredContract(_coreContract);
    }

    /**
     * @notice Gets all projects on core contract `_coreContract` that are
     * using minter `_minter`.
     * Warning: Unbounded gas limit. This function is gas-intensive and should
     * only be used for off-chain queries. Alternatively, the subgraph indexing
     * layer may be used to query these values.
     * @param _coreContract core contract to query
     * @param _minter minter to query
     */
    function getProjectsOnContractUsingMinter(
        address _coreContract,
        address _minter
    ) external view returns (uint256[] memory projectIds) {
        // initialize arrays with maximum potential length
        // @dev use num projects using minter across all contracts since it the
        // maximum length of this array
        uint256 maxNumProjects = numProjectsUsingMinter[_minter];
        projectIds = new uint256[](maxNumProjects);
        // iterate over all projects on contract, adding to array if using
        // `_minter`
        EnumerableMap.UintToAddressMap storage minterMap = minterForProject[
            _coreContract
        ];
        uint256 numProjects = minterMap.length();
        uint256 numProjectsOnContractUsingMinter;
        for (uint256 i; i < numProjects; ) {
            (uint256 projectId, address minter) = minterMap.at(i);
            if (minter == _minter) {
                projectIds[numProjectsOnContractUsingMinter++] = projectId;
            }
            unchecked {
                ++i;
            }
        }
        // trim array if necessary
        if (maxNumProjects > numProjectsOnContractUsingMinter) {
            assembly {
                let decrease := sub(
                    maxNumProjects,
                    numProjectsOnContractUsingMinter
                )
                mstore(projectIds, sub(mload(projectIds), decrease))
            }
        }
        return projectIds;
    }

    /**
     * @notice Convenience function that returns whether `_sender` is allowed
     * to call function with selector `_selector` on contract `_contract`, as
     * determined by this contract's current Admin ACL contract. Expected use
     * cases include minter contracts checking if caller is allowed to call
     * admin-gated functions on minter contracts.
     * @param _sender Address of the sender calling function with selector
     * `_selector` on contract `_contract`.
     * @param _contract Address of the contract being called by `_sender`.
     * @param _selector Function selector of the function being called by
     * `_sender`.
     * @return bool Whether `_sender` is allowed to call function with selector
     * `_selector` on contract `_contract`.
     * @dev assumes the Admin ACL contract is the owner of this contract, which
     * is expected to always be true.
     * @dev adminACLContract is expected to either be null address (if owner
     * has renounced ownership), or conform to IAdminACLV0 interface. Check for
     * null address first to avoid revert when admin has renounced ownership.
     */
    function adminACLAllowed(
        address _sender,
        address _contract,
        bytes4 _selector
    ) public returns (bool) {
        return
            owner() != address(0) &&
            adminACLContract.allowed(_sender, _contract, _selector);
    }

    /**
     * @notice Returns contract owner. Set to deployer's address by default on
     * contract deployment.
     * @return address Address of contract owner.
     * @dev ref: https://docs.openzeppelin.com/contracts/4.x/api/access#Ownable
     * @dev owner role was called `admin` prior to V3 core contract
     */
    function owner()
        public
        view
        override(Ownable, IMinterFilterV1)
        returns (address)
    {
        return Ownable.owner();
    }

    /**
     * @notice Updates project `_projectId` to have no configured minter
     * Reverts if project does not already have an assigned minter.
     * @param _projectId Project ID to remove minter.
     * @dev requires project to have an assigned minter
     * @dev this function intentionally does not check that the core contract
     * is registered, since it must have been registered at the time the
     * project was assigned a minter
     */
    function _removeMinterForProject(
        uint256 _projectId,
        address _coreContract
    ) internal {
        // remove minter for project and emit
        // @dev `minterForProject.get()` reverts tx if no minter set for project
        numProjectsUsingMinter[
            minterForProject[_coreContract].get(_projectId, "No minter set")
        ]--;
        minterForProject[_coreContract].remove(_projectId);
        emit ProjectMinterRemoved(_projectId, _coreContract);
    }

    /**
     * @notice Transfers ownership of the contract to a new account (`_owner`).
     * Internal function without access restriction.
     * @param _owner New owner.
     * @dev owner role was called `admin` prior to V3 core contract.
     * @dev Overrides and wraps OpenZeppelin's _transferOwnership function to
     * also update adminACLContract for improved introspection.
     */
    function _transferOwnership(address _owner) internal override {
        Ownable._transferOwnership(_owner);
        adminACLContract = IAdminACLV0(_owner);
    }

    /**
     * @notice Updates this contract's engine registry contract to
     * `_engineRegistry`.
     * @param _engineRegistry New engine registry contract address.
     */
    function _updateEngineRegistry(address _engineRegistry) internal {
        _onlyNonZeroAddress(_engineRegistry);
        engineRegistry = IEngineRegistryV1(_engineRegistry);
        emit EngineRegistryUpdated(_engineRegistry);
    }
}
