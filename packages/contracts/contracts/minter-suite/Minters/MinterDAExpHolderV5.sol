// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

import "../../interfaces/v0.8.x/IGenArt721CoreContractV3_Base.sol";
import "../../interfaces/v0.8.x/IDelegationRegistry.sol";
import "../../interfaces/v0.8.x/ISharedMinterV0.sol";
import "../../interfaces/v0.8.x/ISharedMinterDAV0.sol";
import "../../interfaces/v0.8.x/ISharedMinterDAExpV0.sol";
import "../../interfaces/v0.8.x/ISharedMinterHolderV0.sol";
import "../../interfaces/v0.8.x/IMinterFilterV1.sol";

import "../../libs/v0.8.x/minter-libs/SplitFundsLib.sol";
import "../../libs/v0.8.x/minter-libs/MaxInvocationsLib.sol";
import "../../libs/v0.8.x/minter-libs/TokenHolderLib.sol";
import "../../libs/v0.8.x/minter-libs/DAExpLib.sol";
import "../../libs/v0.8.x/AuthLib.sol";

import "@openzeppelin-4.5/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin-4.5/contracts/utils/structs/EnumerableSet.sol";

pragma solidity 0.8.19;

/**
 * @title Shared, filtered Minter contract that allows tokens to be minted with
 * ETH when purchaser owns an allowlisted ERC-721 NFT. This contract does NOT
 * track if a purchaser has/has not minted already -- it simply restricts
 * purchasing to anybody that holds one or more of a specified list of ERC-721
 * NFTs. Pricing is achieved using an automated, exponential Dutch-auction mechanism.
 * This is designed to be used with GenArt721CoreContractV3 flagship or
 * engine contracts.
 * @author Art Blocks Inc.
 * @notice Privileged Roles and Ownership:
 * This contract is designed to be managed, with limited powers.
 * Privileged roles and abilities are controlled by the project's artist, which
 * can be modified by the core contract's Admin ACL contract. Both of these
 * roles hold extensive power and can modify minter details.
 * Care must be taken to ensure that the admin ACL contract and artist
 * addresses are secure behind a multi-sig or other access control mechanism.
 * ----------------------------------------------------------------------------
 * The following functions are restricted to the minter filter's Admin ACL
 * contract:
 * - setMinimumPriceDecayHalfLifeSeconds
 * ----------------------------------------------------------------------------
 * The following functions are restricted to the core contract's Admin ACL
 * contract:
 * - resetAuctionDetails (note: this will prevent minting until a new auction
 *   is created)
 * ----------------------------------------------------------------------------
 * The following functions are restricted to a project's artist:
 * - setAuctionDetails (note: this may only be called when there is no active
 *   auction)
 * - syncProjectMaxInvocationsToCore
 * - manuallyLimitProjectMaxInvocations
 * - allowHoldersOfProjects
 * - removeHoldersOfProjects
 * - allowAndRemoveHoldersOfProjects
 * ----------------------------------------------------------------------------
 * Additional admin and artist privileged roles may be described on other
 * contracts that this minter integrates with.
 *
 * This contract allows gated minting with support for vaults to delegate minting
 * privileges via an external delegation registry. This means a vault holding an
 * allowed token can delegate minting privileges to a wallet that is not holding an
 * allowed token, enabling the vault to remain air-gapped while still allowing minting.
 * The delegation registry contract is responsible for managing these delegations,
 * and is available at the address returned by the public immutable
 * `delegationRegistryAddress`. At the time of writing, the delegation
 * registry enables easy delegation configuring at https://delegate.cash/.
 * Art Blocks does not guarentee the security of the delegation registry, and
 * users should take care to ensure that the delegation registry is secure.
 * Delegations must be configured by the vault owner prior to purchase. Supported
 * delegation types include token-level, contract-level (via genArt721CoreAddress), or
 * wallet-level delegation. Contract-level delegations must be configured for the core
 * token contract as returned by the public immutable variable `genArt721CoreAddress`.
 *
 *  @dev Note that while this minter makes use of `block.timestamp` and it is
 * technically possible that this value is manipulated by block producers, such
 * manipulation will not have material impact on the price values of this minter
 * given the business practices for how pricing is congfigured for this minter
 * and that variations on the order of less than a minute should not
 * meaningfully impact price given the minimum allowable price decay rate that
 * this minter intends to support.
 */
contract MinterDAExpHolderV5 is
    ReentrancyGuard,
    ISharedMinterV0,
    ISharedMinterDAV0,
    ISharedMinterDAExpV0,
    ISharedMinterHolderV0
{
    // add Enumerable Set methods
    using EnumerableSet for EnumerableSet.AddressSet;

    /// Minter filter address this minter interacts with
    address public immutable minterFilterAddress;

    /// Minter filter this minter may interact with.
    IMinterFilterV1 private immutable minterFilter;

    // Delegation registry address
    address public immutable delegationRegistryAddress;

    // Delegation registry address
    IDelegationRegistry private immutable delegationRegistryContract;

    /// minterType for this minter
    string public constant minterType = "MinterDAExpHolderV5";

    /// minter version for this minter
    string public constant minterVersion = "v5.0.0";

    uint256 constant ONE_MILLION = 1_000_000;
    //// Minimum price decay half life: price must decay with a half life of at
    /// least this amount (must cut in half at least every N seconds).
    uint256 public minimumPriceDecayHalfLifeSeconds = 45; // 45 seconds

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR SplitFundsLib begin here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // contractAddress => IsEngineCache
    mapping(address => SplitFundsLib.IsEngineCache) private _isEngineCaches;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR SplitFundsLib end here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // TODO

    mapping(address => mapping(uint256 => DAExpLib.DAProjectConfig))
        private _auctionProjectConfigMapping;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR MaxInvocationsLib begin here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // contractAddress => projectId => max invocations specific project config
    mapping(address => mapping(uint256 => MaxInvocationsLib.MaxInvocationsProjectConfig))
        private _maxInvocationsProjectConfigMapping;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR MaxInvocationsLib end here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR TokenHolderLib begin here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * coreContract => projectId => ownedNFTAddress => ownedNFTProjectIds => bool
     * projects whose holders are allowed to purchase a token on `projectId`
     */
    mapping(address => mapping(uint256 => TokenHolderLib.HolderProjectConfig))
        private _allowedProjectHoldersMapping;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR TokenHolderLib end here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    /**
     * @notice Initializes contract to be a Filtered Minter for
     * `_minterFilter` minter filter.
     * @param _minterFilter Minter filter for which this will be a
     * filtered minter.
     */
    constructor(
        address _minterFilter,
        address _delegationRegistryAddress
    ) ReentrancyGuard() {
        delegationRegistryAddress = _delegationRegistryAddress;
        emit DelegationRegistryUpdated(_delegationRegistryAddress);
        delegationRegistryContract = IDelegationRegistry(
            _delegationRegistryAddress
        );

        minterFilterAddress = _minterFilter;
        minterFilter = IMinterFilterV1(_minterFilter);
        emit AuctionMinHalfLifeSecondsUpdated(minimumPriceDecayHalfLifeSeconds);
    }

    /**
     * @notice Manually sets the local maximum invocations of project `_projectId`
     * with the provided `_maxInvocations`, checking that `_maxInvocations` is less
     * than or equal to the value of project `_project_id`'s maximum invocations that is
     * set on the core contract.
     * @dev Note that a `_maxInvocations` of 0 can only be set if the current `invocations`
     * value is also 0 and this would also set `maxHasBeenInvoked` to true, correctly short-circuiting
     * this minter's purchase function, avoiding extra gas costs from the core contract's maxInvocations check.
     * @param _projectId Project ID to set the maximum invocations for.
     * @param _coreContract Core contract address for the given project.
     * @param _maxInvocations Maximum invocations to set for the project.
     */
    function manuallyLimitProjectMaxInvocations(
        uint256 _projectId,
        address _coreContract,
        uint24 _maxInvocations
    ) external {
        AuthLib.onlyArtist({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: msg.sender
        });
        MaxInvocationsLib.manuallyLimitProjectMaxInvocations({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _maxInvocations: _maxInvocations,
            maxInvocationsProjectConfig: _maxInvocationsProjectConfigMapping[
                _coreContract
            ][_projectId]
        });

        emit ProjectMaxInvocationsLimitUpdated(
            _projectId,
            _coreContract,
            _maxInvocations
        );
    }

    /**
     * @notice Allows holders of NFTs at addresses `_ownedNFTAddresses`,
     * project IDs `_ownedNFTProjectIds` to mint on project `_projectId`.
     * `_ownedNFTAddresses` assumed to be aligned with `_ownedNFTProjectIds`.
     * e.g. Allows holders of project `_ownedNFTProjectIds[0]` on token
     * contract `_ownedNFTAddresses[0]` to mint `_projectId`.
     * WARNING: Only Art Blocks Core contracts are compatible with holder allowlisting,
     * due to assumptions about tokenId and projectId relationships.
     * @param _projectId Project ID to enable minting on.
     * @param _coreContract Core contract address for the given project.
     * @param _ownedNFTAddresses NFT core addresses of projects to be
     * allowlisted. Indexes must align with `_ownedNFTProjectIds`.
     * @param _ownedNFTProjectIds Project IDs on `_ownedNFTAddresses` whose
     * holders shall be allowlisted to mint project `_projectId`. Indexes must
     * align with `_ownedNFTAddresses`.
     */
    function allowHoldersOfProjects(
        uint256 _projectId,
        address _coreContract,
        address[] memory _ownedNFTAddresses,
        uint256[] memory _ownedNFTProjectIds
    ) external {
        AuthLib.onlyArtist({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: msg.sender
        });
        TokenHolderLib.allowHoldersOfProjects({
            holderProjectConfig: _allowedProjectHoldersMapping[_coreContract][
                _projectId
            ],
            _ownedNFTAddresses: _ownedNFTAddresses,
            _ownedNFTProjectIds: _ownedNFTProjectIds
        });

        // emit approve event
        emit AllowedHoldersOfProjects(
            _projectId,
            _coreContract,
            _ownedNFTAddresses,
            _ownedNFTProjectIds
        );
    }

    /**
     * @notice Removes holders of NFTs at addresses `_ownedNFTAddresses`,
     * project IDs `_ownedNFTProjectIds` to mint on project `_projectId`. If
     * other projects owned by a holder are still allowed to mint, holder will
     * maintain ability to purchase.
     * `_ownedNFTAddresses` assumed to be aligned with `_ownedNFTProjectIds`.
     * e.g. Removes holders of project `_ownedNFTProjectIds[0]` on token
     * contract `_ownedNFTAddresses[0]` from mint allowlist of `_projectId`.
     * @param _projectId Project ID to enable minting on.
     * @param _coreContract Core contract address for the given project.
     * @param _ownedNFTAddresses NFT core addresses of projects to be removed
     * from allowlist. Indexes must align with `_ownedNFTProjectIds`.
     * @param _ownedNFTProjectIds Project IDs on `_ownedNFTAddresses` whose
     * holders will be removed from allowlist to mint project `_projectId`.
     * Indexes must align with `_ownedNFTAddresses`.
     */
    function removeHoldersOfProjects(
        uint256 _projectId,
        address _coreContract,
        address[] memory _ownedNFTAddresses,
        uint256[] memory _ownedNFTProjectIds
    ) external {
        AuthLib.onlyArtist({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: msg.sender
        });
        // require same length arrays
        TokenHolderLib.removeHoldersOfProjects({
            holderProjectConfig: _allowedProjectHoldersMapping[_coreContract][
                _projectId
            ],
            _ownedNFTAddresses: _ownedNFTAddresses,
            _ownedNFTProjectIds: _ownedNFTProjectIds
        });

        // emit removed event
        emit RemovedHoldersOfProjects(
            _projectId,
            _coreContract,
            _ownedNFTAddresses,
            _ownedNFTProjectIds
        );
    }

    /**
     * @notice Allows holders of NFTs at addresses `_ownedNFTAddressesAdd`,
     * project IDs `_ownedNFTProjectIdsAdd` to mint on project `_projectId`.
     * Also removes holders of NFTs at addresses `_ownedNFTAddressesRemove`,
     * project IDs `_ownedNFTProjectIdsRemove` from minting on project
     * `_projectId`.
     * `_ownedNFTAddressesAdd` assumed to be aligned with
     * `_ownedNFTProjectIdsAdd`.
     * e.g. Allows holders of project `_ownedNFTProjectIdsAdd[0]` on token
     * contract `_ownedNFTAddressesAdd[0]` to mint `_projectId`.
     * `_ownedNFTAddressesRemove` also assumed to be aligned with
     * `_ownedNFTProjectIdsRemove`.
     * WARNING: Only Art Blocks Core contracts are compatible with holder allowlisting,
     * due to assumptions about tokenId and projectId relationships.
     * @param _projectId Project ID to enable minting on.
     * @param _coreContract Core contract address for the given project.
     * @param _ownedNFTAddressesAdd NFT core addresses of projects to be
     * allowlisted. Indexes must align with `_ownedNFTProjectIdsAdd`.
     * @param _ownedNFTProjectIdsAdd Project IDs on `_ownedNFTAddressesAdd`
     * whose holders shall be allowlisted to mint project `_projectId`. Indexes
     * must align with `_ownedNFTAddressesAdd`.
     * @param _ownedNFTAddressesRemove NFT core addresses of projects to be
     * removed from allowlist. Indexes must align with
     * `_ownedNFTProjectIdsRemove`.
     * @param _ownedNFTProjectIdsRemove Project IDs on
     * `_ownedNFTAddressesRemove` whose holders will be removed from allowlist
     * to mint project `_projectId`. Indexes must align with
     * `_ownedNFTAddressesRemove`.
     * @dev if a project is included in both add and remove arrays, it will be
     * removed.
     */
    function allowAndRemoveHoldersOfProjects(
        uint256 _projectId,
        address _coreContract,
        address[] memory _ownedNFTAddressesAdd,
        uint256[] memory _ownedNFTProjectIdsAdd,
        address[] memory _ownedNFTAddressesRemove,
        uint256[] memory _ownedNFTProjectIdsRemove
    ) external {
        AuthLib.onlyArtist({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: msg.sender
        });
        TokenHolderLib.allowAndRemoveHoldersOfProjects({
            holderProjectConfig: _allowedProjectHoldersMapping[_coreContract][
                _projectId
            ],
            _ownedNFTAddressesAdd: _ownedNFTAddressesAdd,
            _ownedNFTProjectIdsAdd: _ownedNFTProjectIdsAdd,
            _ownedNFTAddressesRemove: _ownedNFTAddressesRemove,
            _ownedNFTProjectIdsRemove: _ownedNFTProjectIdsRemove
        });

        // emit events
        emit AllowedHoldersOfProjects(
            _projectId,
            _coreContract,
            _ownedNFTAddressesAdd,
            _ownedNFTProjectIdsAdd
        );
        emit RemovedHoldersOfProjects(
            _projectId,
            _coreContract,
            _ownedNFTAddressesRemove,
            _ownedNFTProjectIdsRemove
        );
    }

    /**
     * @notice Sets auction details for project `_projectId`.
     * Requires one of the following:
     * - The auction is unconfigured
     * - The auction has not yet started
     * - The minter-local max invocations have been reached
     * @dev Note that allowing the artist to set auction details after reaching
     * max invocations effectively grants the artist the ability to set a new
     * auction at any point, since minter-local max invocations can be set by
     * the artist.
     * @param _projectId Project ID to set auction details for.
     * @param _coreContract Core contract address for the given project.
     * @param _auctionTimestampStart Timestamp at which to start the auction.
     * @param _priceDecayHalfLifeSeconds The half life with which to decay the
     *  price (in seconds).
     * @param _startPrice Price at which to start the auction, in Wei.
     * @param _basePrice Resting price of the auction, in Wei.
     * @dev Note that it is intentionally supported here that the configured
     * price may be explicitly set to `0`.
     */
    function setAuctionDetails(
        uint256 _projectId,
        address _coreContract,
        uint64 _auctionTimestampStart,
        uint64 _priceDecayHalfLifeSeconds,
        uint128 _startPrice,
        uint128 _basePrice
    ) external {
        AuthLib.onlyArtist({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: msg.sender
        });
        // CHECKS
        DAExpLib.DAProjectConfig
            storage _auctionProjectConfig = _auctionProjectConfigMapping[
                _coreContract
            ][_projectId];
        MaxInvocationsLib.MaxInvocationsProjectConfig
            storage _maxInvocationsProjectConfig = _maxInvocationsProjectConfigMapping[
                _coreContract
            ][_projectId];

        require(
            (_priceDecayHalfLifeSeconds >= minimumPriceDecayHalfLifeSeconds),
            "Price decay half life must be greater than min allowable value"
        );

        // EFFECTS
        bool maxHasBeenInvoked = MaxInvocationsLib.getMaxHasBeenInvoked(
            _maxInvocationsProjectConfig
        );
        DAExpLib.setAuctionDetailsExp({
            _DAProjectConfig: _auctionProjectConfig,
            _auctionTimestampStart: _auctionTimestampStart,
            _priceDecayHalfLifeSeconds: _priceDecayHalfLifeSeconds,
            _startPrice: _startPrice,
            _basePrice: _basePrice,
            _maxHasBeenInvoked: maxHasBeenInvoked
        });

        emit SetAuctionDetailsExp({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _auctionTimestampStart: _auctionTimestampStart,
            _priceDecayHalfLifeSeconds: _priceDecayHalfLifeSeconds,
            _startPrice: _startPrice,
            _basePrice: _basePrice
        });

        // sync local max invocations if not initially populated
        // @dev if local max invocations and maxHasBeenInvoked are both
        // initial values, we know they have not been populated.
        if (
            MaxInvocationsLib.maxInvocationsIsUnconfigured(
                _maxInvocationsProjectConfig
            )
        ) {
            syncProjectMaxInvocationsToCore(_projectId, _coreContract);
        }
    }

    /**
     * @notice Sets the minimum and maximum values that are settable for
     * `_priceDecayHalfLifeSeconds` across all projects.
     * @param _minimumPriceDecayHalfLifeSeconds Minimum price decay half life
     * (in seconds).
     */
    function setMinimumPriceDecayHalfLifeSeconds(
        uint256 _minimumPriceDecayHalfLifeSeconds
    ) external {
        AuthLib.onlyMinterFilterAdminACL({
            _minterFilterAddress: minterFilterAddress,
            _sender: msg.sender,
            _contract: address(this),
            _selector: this.setMinimumPriceDecayHalfLifeSeconds.selector
        });
        require(
            _minimumPriceDecayHalfLifeSeconds > 0,
            "Half life of zero not allowed"
        );
        minimumPriceDecayHalfLifeSeconds = _minimumPriceDecayHalfLifeSeconds;

        emit AuctionMinHalfLifeSecondsUpdated(
            _minimumPriceDecayHalfLifeSeconds
        );
    }

    /**
     * @notice Resets auction details for project `_projectId`, zero-ing out all
     * relevant auction fields. Not intended to be used in normal auction
     * operation, but rather only in case of the need to halt an auction.
     * @param _projectId Project ID to set auction details for.
     */
    function resetAuctionDetails(
        uint256 _projectId,
        address _coreContract
    ) external {
        AuthLib.onlyCoreAdminACL({
            _coreContract: _coreContract,
            _sender: msg.sender,
            _contract: address(this),
            _selector: this.resetAuctionDetails.selector
        });
        delete _auctionProjectConfigMapping[_coreContract][_projectId];

        emit ResetAuctionDetails(_projectId, _coreContract);
    }

    /**
     * @notice Inactive function - requires NFT ownership to purchase.
     */
    function purchase(uint256, address) external payable returns (uint256) {
        revert("Purchase requires NFT ownership");
    }

    /**
     * @notice Inactive function - requires NFT ownership to purchase.
     */
    function purchaseTo(
        address,
        uint256,
        address
    ) external payable returns (uint256) {
        revert("Purchase requires NFT ownership");
    }

    /**
     * @notice Purchases a token from project `_projectId`.
     * @param _projectId Project ID to mint a token on.
     * @param _coreContract Core contract address for the given project.
     * @return tokenId Token ID of minted token
     */
    function purchase(
        uint256 _projectId,
        address _coreContract,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId
    ) external payable returns (uint256 tokenId) {
        tokenId = purchaseTo({
            _to: msg.sender,
            _projectId: _projectId,
            _coreContract: _coreContract,
            _ownedNFTAddress: _ownedNFTAddress,
            _ownedNFTTokenId: _ownedNFTTokenId,
            _vault: address(0)
        });

        return tokenId;
    }

    /**
     * @notice Purchases a token from project `_projectId` and sets
     * the token's owner to `_to`.
     * @param _to Address to be the new token's owner.
     * @param _projectId Project ID to mint a token on.
     * @param _coreContract Core contract address for the given project.
     * @param _ownedNFTAddress ERC-721 NFT holding the project token owned by
     * msg.sender being used to claim right to purchase.
     * @param _ownedNFTTokenId ERC-721 NFT token ID owned by msg.sender being used
     * to claim right to purchase.
     * @return tokenId Token ID of minted token
     */
    function purchaseTo(
        address _to,
        uint256 _projectId,
        address _coreContract,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId
    ) external payable returns (uint256 tokenId) {
        return
            purchaseTo({
                _to: _to,
                _projectId: _projectId,
                _coreContract: _coreContract,
                _ownedNFTAddress: _ownedNFTAddress,
                _ownedNFTTokenId: _ownedNFTTokenId,
                _vault: address(0)
            });
    }

    // public getter functions
    /**
     * @notice Gets the maximum invocations project configuration.
     * @param _coreContract The address of the core contract.
     * @param _projectId The ID of the project whose data needs to be fetched.
     * @return MaxInvocationsLib.MaxInvocationsProjectConfig instance with the
     * configuration data.
     */
    function maxInvocationsProjectConfig(
        uint256 _projectId,
        address _coreContract
    )
        external
        view
        returns (MaxInvocationsLib.MaxInvocationsProjectConfig memory)
    {
        return _maxInvocationsProjectConfigMapping[_coreContract][_projectId];
    }

    /**
     * @notice Retrieves the auction parameters for a specific project.
     * @param _projectId The unique identifier for the project.
     * @param _coreContract The address of the core contract for the project.
     * @return timestampStart The start timestamp for the auction.
     * @return priceDecayHalfLifeSeconds The half-life for the price decay during the auction, in seconds.
     * @return startPrice The starting price of the auction.
     * @return basePrice The base price of the auction.
     */
    function projectAuctionParameters(
        uint256 _projectId,
        address _coreContract
    )
        external
        view
        returns (
            uint64 timestampStart,
            uint64 priceDecayHalfLifeSeconds,
            uint128 startPrice,
            uint128 basePrice
        )
    {
        DAExpLib.DAProjectConfig
            storage _auctionProjectConfig = _auctionProjectConfigMapping[
                _coreContract
            ][_projectId];
        timestampStart = _auctionProjectConfig.timestampStart;
        priceDecayHalfLifeSeconds = _auctionProjectConfig
            .priceDecayHalfLifeSeconds;
        startPrice = _auctionProjectConfig.startPrice;
        basePrice = _auctionProjectConfig.basePrice;
    }

    /**
     * @notice Checks if the specified `_coreContract` is a valid engine contract.
     * @dev This function retrieves the cached value of `_coreContract` from
     * the `isEngineCache` mapping. If the cached value is already set, it
     * returns the cached value. Otherwise, it calls the `getV3CoreIsEngine`
     * function from the `SplitFundsLib` library to check if `_coreContract`
     * is a valid engine contract.
     * @dev This function will revert if the provided `_coreContract` is not
     * a valid Engine or V3 Flagship contract.
     * @param _coreContract The address of the contract to check.
     * @return bool indicating if `_coreContract` is a valid engine contract.
     */
    function isEngineView(address _coreContract) external view returns (bool) {
        SplitFundsLib.IsEngineCache storage isEngineCache = _isEngineCaches[
            _coreContract
        ];
        if (isEngineCache.isCached) {
            return isEngineCache.isEngine;
        } else {
            // @dev this calls the non-modifying variant of getV3CoreIsEngine
            return SplitFundsLib.getV3CoreIsEngineView(_coreContract);
        }
    }

    /**
     * @notice projectId => has project reached its maximum number of
     * invocations? Note that this returns a local cache of the core contract's
     * state, and may be out of sync with the core contract. This is
     * intentional, as it only enables gas optimization of mints after a
     * project's maximum invocations has been reached. A false negative will
     * only result in a gas cost increase, since the core contract will still
     * enforce a maxInvocation check during minting. A false positive is not
     * possible because the V3 core contract only allows maximum invocations
     * to be reduced, not increased. Based on this rationale, we intentionally
     * do not do input validation in this method as to whether or not the input
     * @param `_projectId` is an existing project ID.
     * @param `_coreContract` is an existing core contract address.
     */
    function projectMaxHasBeenInvoked(
        uint256 _projectId,
        address _coreContract
    ) external view returns (bool) {
        return
            MaxInvocationsLib.getMaxHasBeenInvoked(
                _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
            );
    }

    /**
     * @notice projectId => project's maximum number of invocations.
     * Optionally synced with core contract value, for gas optimization.
     * Note that this returns a local cache of the core contract's
     * state, and may be out of sync with the core contract. This is
     * intentional, as it only enables gas optimization of mints after a
     * project's maximum invocations has been reached.
     * @dev A number greater than the core contract's project max invocations
     * will only result in a gas cost increase, since the core contract will
     * still enforce a maxInvocation check during minting. A number less than
     * the core contract's project max invocations is only possible when the
     * project's max invocations have not been synced on this minter, since the
     * V3 core contract only allows maximum invocations to be reduced, not
     * increased. When this happens, the minter will enable minting, allowing
     * the core contract to enforce the max invocations check. Based on this
     * rationale, we intentionally do not do input validation in this method as
     * to whether or not the input `_projectId` is an existing project ID.
     * @param `_projectId` is an existing project ID.
     * @param `_coreContract` is an existing core contract address.
     */
    function projectMaxInvocations(
        uint256 _projectId,
        address _coreContract
    ) external view returns (uint256) {
        return
            MaxInvocationsLib.getMaxInvocations(
                _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
            );
    }

    /**
     * @notice Gets if price of token is configured, price of minting a
     * token on project `_projectId`, and currency symbol and address to be
     * used as payment. Supersedes any core contract price information.
     * @param _projectId Project ID to get price information for
     * @param _coreContract Contract address of the core contract
     * @return isConfigured true only if token price has been configured on
     * this minter
     * @return tokenPriceInWei current price of token on this minter - invalid
     * if price has not yet been configured
     * @return currencySymbol currency symbol for purchases of project on this
     * minter. This minter always returns "ETH"
     * @return currencyAddress currency address for purchases of project on
     * this minter. This minter always returns null address, reserved for ether
     */
    function getPriceInfo(
        uint256 _projectId,
        address _coreContract
    )
        external
        view
        returns (
            bool isConfigured,
            uint256 tokenPriceInWei,
            string memory currencySymbol,
            address currencyAddress
        )
    {
        DAExpLib.DAProjectConfig
            storage auctionProjectConfig = _auctionProjectConfigMapping[
                _coreContract
            ][_projectId];
        isConfigured = (auctionProjectConfig.startPrice > 0);
        if (!isConfigured) {
            // In the case of unconfigured auction, return price of zero when
            // getPriceExp would otherwise revert
            tokenPriceInWei = 0;
        } else if (block.timestamp <= auctionProjectConfig.timestampStart) {
            // Provide a reasonable value for `tokenPriceInWei` when
            // getPriceExp would otherwise revert, using the starting price
            // before auction starts.
            tokenPriceInWei = auctionProjectConfig.startPrice;
        } else {
            tokenPriceInWei = DAExpLib.getPriceExp(auctionProjectConfig);
        }
        currencySymbol = "ETH";
        currencyAddress = address(0);
    }

    /**
     * @notice Checks if a specific NFT owner is allowed in a given project.
     * @dev This function retrieves the allowance status of an NFT owner
     * within a specific project from the allowedProjectHoldersMapping.
     * @param _projectId The ID of the project to check.
     * @param _coreContract Core contract address for the given project.
     * @param _ownedNFTAddress The address of the owned NFT contract.
     * @param _ownedNFTProjectId The ID of the owned NFT project.
     * @return bool True if the NFT owner is allowed in the given project, False otherwise.
     */
    function allowedProjectHolders(
        uint256 _projectId,
        address _coreContract,
        address _ownedNFTAddress,
        uint256 _ownedNFTProjectId
    ) external view returns (bool) {
        return
            _allowedProjectHoldersMapping[_coreContract][_projectId]
                .allowedProjectHolders[_ownedNFTAddress][_ownedNFTProjectId];
    }

    /**
     * @notice Returns if token is an allowlisted NFT for project `_projectId`.
     * @param _projectId Project ID to be checked.
     * @param _coreContract Core contract address for the given project.
     * @param _ownedNFTAddress ERC-721 NFT token address to be checked.
     * @param _ownedNFTTokenId ERC-721 NFT token ID to be checked.
     * @return bool Token is allowlisted
     * @dev does not check if token has been used to purchase
     * @dev assumes project ID can be derived from tokenId / 1_000_000
     */
    function isAllowlistedNFT(
        uint256 _projectId,
        address _coreContract,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId
    ) external view returns (bool) {
        return
            TokenHolderLib.isAllowlistedNFT({
                holderProjectConfig: _allowedProjectHoldersMapping[
                    _coreContract
                ][_projectId],
                _ownedNFTAddress: _ownedNFTAddress,
                _ownedNFTTokenId: _ownedNFTTokenId
            });
    }

    /**
     * @notice Syncs local maximum invocations of project `_projectId` based on
     * the value currently defined in the core contract.
     * @param _coreContract Core contract address for the given project.
     * @param _projectId Project ID to set the maximum invocations for.
     * @dev this enables gas reduction after maxInvocations have been reached -
     * core contracts shall still enforce a maxInvocation check during mint.
     */
    function syncProjectMaxInvocationsToCore(
        uint256 _projectId,
        address _coreContract
    ) public {
        AuthLib.onlyArtist({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: msg.sender
        });

        uint256 maxInvocations = MaxInvocationsLib
            .syncProjectMaxInvocationsToCore({
                _projectId: _projectId,
                _coreContract: _coreContract,
                maxInvocationsProjectConfig: _maxInvocationsProjectConfigMapping[
                    _coreContract
                ][_projectId]
            });
        emit ProjectMaxInvocationsLimitUpdated(
            _projectId,
            _coreContract,
            maxInvocations
        );
    }

    /**
     * @notice Purchases a token from project `_projectId` and sets
     * the token's owner to `_to`.
     * @param _to Address to be the new token's owner.
     * @param _projectId Project ID to mint a token on.
     * @param _coreContract Core contract address for the given project.
     * @return tokenId Token ID of minted token
     */
    function purchaseTo(
        address _to,
        uint256 _projectId,
        address _coreContract,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId,
        address _vault
    ) public payable nonReentrant returns (uint256 tokenId) {
        // CHECKS
        MaxInvocationsLib.MaxInvocationsProjectConfig
            storage _maxInvocationsProjectConfig = _maxInvocationsProjectConfigMapping[
                _coreContract
            ][_projectId];

        DAExpLib.DAProjectConfig
            storage _auctionProjectConfig = _auctionProjectConfigMapping[
                _coreContract
            ][_projectId];
        // Note that `maxHasBeenInvoked` is only checked here to reduce gas
        // consumption after a project has been fully minted.
        // `_maxInvocationsProjectConfig.maxHasBeenInvoked` is locally cached to reduce
        // gas consumption, but if not in sync with the core contract's value,
        // the core contract also enforces its own max invocation check during
        // minting.
        require(
            !_maxInvocationsProjectConfig.maxHasBeenInvoked,
            "Max invocations reached"
        );

        uint256 pricePerTokenInWei = DAExpLib.getPriceExp(
            _auctionProjectConfig
        );
        require(msg.value >= pricePerTokenInWei, "Min value to mint req.");

        // require token used to claim to be in set of allowlisted NFTs
        require(
            TokenHolderLib.isAllowlistedNFT({
                holderProjectConfig: _allowedProjectHoldersMapping[
                    _coreContract
                ][_projectId],
                _ownedNFTAddress: _ownedNFTAddress,
                _ownedNFTTokenId: _ownedNFTTokenId
            }),
            "Only allowlisted NFTs"
        );

        // handle that the vault may be either the `msg.sender` in the case
        // that there is not a true vault, or may be `_vault` if one is
        // provided explicitly (and it is valid).
        address vault = msg.sender;
        if (_vault != address(0)) {
            // If a vault is provided, it must be valid, otherwise throw rather
            // than optimistically-minting with original `msg.sender`.
            // Note, we do not check `checkDelegateForAll` or `checkDelegateForContract` as well,
            // as they are known to be implicitly checked by calling `checkDelegateForToken`.
            bool isValidVault = delegationRegistryContract
                .checkDelegateForToken({
                    delegate: msg.sender,
                    vault: _vault,
                    contract_: _coreContract,
                    tokenId: _ownedNFTTokenId
                });

            require(isValidVault, "Invalid delegate-vault pairing");
            vault = _vault;
        }

        // EFFECTS
        tokenId = minterFilter.mint_joo({
            _to: _to,
            _projectId: _projectId,
            _coreContract: _coreContract,
            _sender: vault
        });

        // NOTE: delegate-vault handling **ends here**.

        MaxInvocationsLib.validatePurchaseEffectsInvocations(
            tokenId,
            _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
        );

        // INTERACTIONS
        // require vault to own NFT used to redeem
        /**
         * @dev Considered an interaction because calling ownerOf on an NFT
         * contract. Plan is to only integrate with AB/PBAB NFTs on the minter, but
         * in case other NFTs are registered, better to check here. Also,
         * function is non-reentrant, so this is extra cautious.
         */
        TokenHolderLib.validateNFTOwnership({
            _ownedNFTAddress: _ownedNFTAddress,
            _ownedNFTTokenId: _ownedNFTTokenId,
            _targetOwner: vault
        });

        // INTERACTIONS
        bool isEngine = SplitFundsLib.isEngine(
            _coreContract,
            _isEngineCaches[_coreContract]
        );
        SplitFundsLib.splitFundsETH({
            _projectId: _projectId,
            _pricePerTokenInWei: pricePerTokenInWei,
            _coreContract: _coreContract,
            _isEngine: isEngine
        });

        return tokenId;
    }
}
