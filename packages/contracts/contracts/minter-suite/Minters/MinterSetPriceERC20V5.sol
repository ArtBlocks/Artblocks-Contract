// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

import "../../interfaces/v0.8.x/IGenArt721CoreContractV3_Base.sol";
import "../../interfaces/v0.8.x/IDelegationRegistry.sol";
import "../../interfaces/v0.8.x/ISharedMinterV0.sol";
import "../../interfaces/v0.8.x/IMinterFilterV1.sol";

import "../../libs/v0.8.x/minter-libs/SplitFundsLib.sol";
import "../../libs/v0.8.x/minter-libs/MaxInvocationsLib.sol";

import "@openzeppelin-4.5/contracts/security/ReentrancyGuard.sol";

pragma solidity 0.8.19;

/**
 * @title Shared, filtered Minter contract that allows tokens to be minted with
 * artist-configured ERC20 tokens.
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
 * The following functions are restricted to a project's artist:
 * - updatePricePerTokenInWei
 * - updateProjectCurrencyInfo
 * - setProjectMaxInvocations
 * - syncProjectMaxInvocationsToCore
 * - manuallyLimitProjectMaxInvocations
 * ----------------------------------------------------------------------------
 * Additional admin and artist privileged roles may be described on other
 * contracts that this minter integrates with.
 */
contract MinterSetPriceERC20V5 is ReentrancyGuard, ISharedMinterV0 {
    /// Minter filter address this minter interacts with
    address public immutable minterFilterAddress;

    /// Minter filter this minter may interact with.
    IMinterFilterV1 private immutable minterFilter;

    /// minterType for this minter
    string public constant minterType = "MinterSetPriceERC20V5";

    /// minter version for this minter
    string public constant minterVersion = "v5.0.0";

    uint256 constant ONE_MILLION = 1_000_000;

    /// contractAddress => projectId => base project config
    mapping(address => mapping(uint256 => ProjectConfig))
        private _projectConfigMapping;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR SplitFundsLib begin here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // contractAddress => IsEngineCache
    mapping(address => SplitFundsLib.IsEngineCache) private _isEngineCaches;

    // contractAddress => projectId => SplitFundsProjectConfig
    mapping(address => mapping(uint256 => SplitFundsLib.SplitFundsProjectConfig))
        private _splitFundsProjectConfigs;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR SplitFundsLib end here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR MaxInvocationsLib begin here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // contractAddress => projectId => max invocations specific project config
    mapping(address => mapping(uint256 => MaxInvocationsLib.MaxInvocationsProjectConfig))
        private _maxInvocationsProjectConfigMapping;

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    // STATE VARIABLES FOR MaxInvocationsLib end here
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // MODIFIERS
    /**
     * @dev Throws if called by any account other than the artist of the specified project.
     * Requirements: `msg.sender` must be the artist associated with `_projectId`.
     * @param _projectId The ID of the project being checked.
     * @param _coreContract The address of the GenArt721CoreContractV3_Base contract.
     */
    function _onlyArtist(
        uint256 _projectId,
        address _coreContract
    ) internal view {
        require(
            msg.sender ==
                IGenArt721CoreContractV3_Base(_coreContract)
                    .projectIdToArtistAddress(_projectId),
            "Only Artist"
        );
    }

    /**
     * @notice Initializes contract to be a Filtered Minter for
     * `_minterFilter` minter filter.
     * @param _minterFilter Minter filter for which this will be a
     * filtered minter.
     */
    constructor(address _minterFilter) ReentrancyGuard() {
        minterFilterAddress = _minterFilter;
        minterFilter = IMinterFilterV1(_minterFilter);
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
        _onlyArtist(_projectId, _coreContract);
        MaxInvocationsLib.manuallyLimitProjectMaxInvocations(
            _projectId,
            _coreContract,
            _maxInvocations,
            _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
        );
        emit ProjectMaxInvocationsLimitUpdated(
            _projectId,
            _coreContract,
            _maxInvocations
        );
    }

    /**
     * @notice Updates this minter's price per token of project `_projectId`
     * to be '_pricePerTokenInWei`, in Wei.
     * @dev Note that it is intentionally supported here that the configured
     * price may be explicitly set to `0`.
     * @param _projectId Project ID to set the price per token for.
     * @param _coreContract Core contract address for the given project.
     * @param _pricePerTokenInWei Price per token to set for the project, in Wei.
     */
    function updatePricePerTokenInWei(
        uint256 _projectId,
        address _coreContract,
        uint248 _pricePerTokenInWei
    ) external {
        _onlyArtist(_projectId, _coreContract);
        ProjectConfig storage _projectConfig = _projectConfigMapping[
            _coreContract
        ][_projectId];
        _projectConfig.pricePerTokenInWei = _pricePerTokenInWei;
        _projectConfig.priceIsConfigured = true;
        emit PricePerTokenInWeiUpdated(
            _projectId,
            _coreContract,
            _pricePerTokenInWei
        );

        // sync local max invocations if not initially populated
        // @dev if local max invocations and maxHasBeenInvoked are both
        // initial values, we know they have not been populated.
        MaxInvocationsLib.MaxInvocationsProjectConfig
            storage _maxInvocationsProjectConfig = _maxInvocationsProjectConfigMapping[
                _coreContract
            ][_projectId];
        if (
            _maxInvocationsProjectConfig.maxInvocations == 0 &&
            _maxInvocationsProjectConfig.maxHasBeenInvoked == false
        ) {
            syncProjectMaxInvocationsToCore(_projectId, _coreContract);
        }
    }

    /**
     * @notice Updates payment currency of project `_projectId` on core
     * contract `_coreContract` to be `_currencySymbol` at address
     * `_currencyAddress`.
     * Only supports ERC20 tokens - for ETH minting, use a different minter.
     * @param _projectId Project ID to update.
     * @param _coreContract Core contract address for the given project.
     * @param _currencySymbol Currency symbol.
     * @param _currencyAddress Currency address.
     */
    function updateProjectCurrencyInfo(
        uint256 _projectId,
        address _coreContract,
        string memory _currencySymbol,
        address _currencyAddress
    ) external nonReentrant {
        _onlyArtist(_projectId, _coreContract);
        SplitFundsLib.SplitFundsProjectConfig
            storage _splitFundsProjectConfig = _splitFundsProjectConfigs[
                _coreContract
            ][_projectId];
        SplitFundsLib.updateProjectCurrencyInfoERC20({
            _splitFundsProjectConfig: _splitFundsProjectConfig,
            _currencySymbol: _currencySymbol,
            _currencyAddress: _currencyAddress
        });
        emit ProjectCurrencyInfoUpdated({
            _projectId: _projectId,
            _coreContract: _coreContract,
            _currencyAddress: _currencyAddress,
            _currencySymbol: _currencySymbol
        });
    }

    /**
     * @notice Purchases a token from project `_projectId`.
     * @param _projectId Project ID to mint a token on.
     * @param _coreContract Core contract address for the given project.
     * @return tokenId Token ID of minted token
     */
    function purchase(
        uint256 _projectId,
        address _coreContract
    ) external payable returns (uint256 tokenId) {
        tokenId = purchaseTo(msg.sender, _projectId, _coreContract);
        return tokenId;
    }

    // public getter functions
    /**
     * @notice Gets the maximum invocations project configuration.
     * @param _projectId The ID of the project whose data needs to be fetched.
     * @param _coreContract The address of the core contract.
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
     * @notice Gets the base project configuration.
     * @param _projectId The ID of the project whose data needs to be fetched.
     * @param _coreContract The address of the core contract.
     * @return ProjectConfig instance with the project configuration data.
     */
    function projectConfig(
        uint256 _projectId,
        address _coreContract
    ) external view returns (ProjectConfig memory) {
        return _projectConfigMapping[_coreContract][_projectId];
    }

    /**
     * @notice Checks if the specified `_coreContract` is a valid engine contract.
     * @dev This function retrieves the cached value of `_isEngine` from
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
            _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
                .maxHasBeenInvoked;
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
            uint256(
                _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
                    .maxInvocations
            );
    }

    /**
     * @notice Gets your balance of the ERC20 token currently set
     * as the payment currency for project `_projectId` in the core
     * contract `_coreContract`.
     * @param _projectId Project ID to be queried.
     * @param _coreContract The address of the core contract.
     * @return balance Balance of ERC20
     */
    function getYourBalanceOfProjectERC20(
        uint256 _projectId,
        address _coreContract
    ) external view returns (uint256 balance) {
        SplitFundsLib.SplitFundsProjectConfig
            storage _splitFundsProjectConfig = _splitFundsProjectConfigs[
                _coreContract
            ][_projectId];
        balance = SplitFundsLib.getERC20Balance(
            _splitFundsProjectConfig.currencyAddress,
            msg.sender
        );
        return balance;
    }

    /**
     * @notice Gets your allowance for this minter of the ERC20
     * token currently set as the payment currency for project
     * `_projectId`.
     * @param _projectId Project ID to be queried.
     * @param _coreContract The address of the core contract.
     * @return remaining Remaining allowance of ERC20
     */
    function checkYourAllowanceOfProjectERC20(
        uint256 _projectId,
        address _coreContract
    ) external view returns (uint256 remaining) {
        SplitFundsLib.SplitFundsProjectConfig
            storage _splitFundsProjectConfig = _splitFundsProjectConfigs[
                _coreContract
            ][_projectId];
        remaining = SplitFundsLib.getERC20Allowance({
            _currencyAddress: _splitFundsProjectConfig.currencyAddress,
            _walletAddress: msg.sender,
            _spenderAddress: address(this)
        });
        return remaining;
    }

    /**
     * @notice Gets if price of token is configured, price of minting a
     * token on project `_projectId`, and currency symbol and address to be
     * used as payment.
     * `isConfigured` is only true if a price has been configured, and an ERC20
     * token has been configured.
     * @param _projectId Project ID to get price information for
     * @param _coreContract Contract address of the core contract
     * @return isConfigured true only if token price has been configured on
     * this minter and an ERC20 token has been configured
     * @return tokenPriceInWei current price of token on this minter - invalid
     * if price has not yet been configured
     * @return currencySymbol currency symbol for purchases of project on this
     * minter. "UNCONFIG" if not yet configured. Note that currency symbol is
     * defined by the artist, and is not necessarily the same as the ERC20
     * token symbol on-chain.
     * @return currencyAddress currency address for purchases of project on
     * this minter. Null address if not yet configured.
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
        ProjectConfig storage _projectConfig = _projectConfigMapping[
            _coreContract
        ][_projectId];
        tokenPriceInWei = _projectConfig.pricePerTokenInWei;
        // get currency info from SplitFundsLib
        SplitFundsLib.SplitFundsProjectConfig
            storage _splitFundsProjectConfig = _splitFundsProjectConfigs[
                _coreContract
            ][_projectId];
        (currencyAddress, currencySymbol) = SplitFundsLib.getCurrencyInfoERC20(
            _splitFundsProjectConfig
        );
        // report if price and ERC20 token are configured
        // @dev currencyAddress is non-zero if an ERC20 token is configured
        isConfigured =
            _projectConfig.priceIsConfigured &&
            currencyAddress != address(0);
    }

    /**
     * @notice Syncs local maximum invocations of project `_projectId` based on
     * the value currently defined in the core contract.
     * @param _projectId Project ID to set the maximum invocations for.
     * @param _coreContract Core contract address for the given project.
     * @dev this enables gas reduction after maxInvocations have been reached -
     * core contracts shall still enforce a maxInvocation check during mint.
     */
    function syncProjectMaxInvocationsToCore(
        uint256 _projectId,
        address _coreContract
    ) public {
        _onlyArtist(_projectId, _coreContract);

        uint256 maxInvocations = MaxInvocationsLib
            .syncProjectMaxInvocationsToCore(
                _projectId,
                _coreContract,
                _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
            );
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
        address _coreContract
    ) public payable nonReentrant returns (uint256 tokenId) {
        // CHECKS
        ProjectConfig storage _projectConfig = _projectConfigMapping[
            _coreContract
        ][_projectId];
        MaxInvocationsLib.MaxInvocationsProjectConfig
            storage _maxInvocationsProjectConfig = _maxInvocationsProjectConfigMapping[
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

        // require artist to have configured price of token on this minter
        require(_projectConfig.priceIsConfigured, "Price not configured");
        // @dev revert occurs during payment split if ERC20 token is not
        // configured (i.e. address(0)), so check is not performed here

        // EFFECTS
        tokenId = minterFilter.mint_joo(
            _to,
            _projectId,
            _coreContract,
            msg.sender
        );

        MaxInvocationsLib.validatePurchaseEffectsInvocations(
            tokenId,
            _maxInvocationsProjectConfigMapping[_coreContract][_projectId]
        );

        // INTERACTIONS
        // split ERC20 funds
        bool isEngine = SplitFundsLib.isEngine(
            _coreContract,
            _isEngineCaches[_coreContract]
        );
        // process payment in ERC20
        SplitFundsLib.SplitFundsProjectConfig
            storage _splitFundsProjectConfig = _splitFundsProjectConfigs[
                _coreContract
            ][_projectId];
        SplitFundsLib.splitFundsERC20({
            _splitFundsProjectConfig: _splitFundsProjectConfig,
            _projectId: _projectId,
            _pricePerTokenInWei: _projectConfig.pricePerTokenInWei,
            _coreContract: _coreContract,
            _isEngine: isEngine
        });

        return tokenId;
    }
}
