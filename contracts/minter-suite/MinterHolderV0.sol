// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

import "../interfaces/0.8.x/IGenArt721CoreContractV1.sol";
import "../interfaces/0.8.x/IMinterFilterV0.sol";
import "../interfaces/0.8.x/IFilteredMinterHolderV0.sol";

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableMap.sol";

pragma solidity 0.8.9;

/**
 * @title Filtered Minter contract that allows tokens to be minted with ETH
 * when purchaser owns an allowlisted ERC-721 NFT.
 * @author Art Blocks Inc.
 */
contract MinterHolderV0 is ReentrancyGuard, IFilteredMinterHolderV0 {
    /**
     * @notice Allowlisted holders of NFTs at address `_NFTAddress` to be
     * considered for minting.
     */
    event RegisteredNFTAddress(address indexed _NFTAddress);

    /**
     * @notice Removed holders of NFTs at address `_NFTAddress` to be
     * considered for minting.
     */
    event UnregisteredNFTAddress(address indexed _NFTAddress);

    /**
     * @notice Allow holders of NFTs at address `_ownedNFTAddress`, project ID
     * `_ownedNFTProjectId` to mint on project `_projectId`.
     */
    event AllowHoldersOfProject(
        uint256 indexed _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTProjectId
    );

    /**
     * @notice Allow holders of NFTs at address `_ownedNFTAddress`, project ID
     * `_ownedNFTProjectId` to mint on project `_projectId`.
     */
    event RemovedHoldersOfProject(
        uint256 indexed _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTProjectId
    );

    // add Enumerable Set methods
    using EnumerableSet for EnumerableSet.AddressSet;

    /// Core contract address this minter interacts with
    address public immutable genArt721CoreAddress;

    /// This contract handles cores with interface IV1
    IGenArt721CoreContractV1 private immutable genArtCoreContract;

    /// Minter filter address this minter interacts with
    address public immutable minterFilterAddress;

    /// Minter filter this minter may interact with.
    IMinterFilterV0 private immutable minterFilter;

    /// minterType for this minter
    string public constant minterType = "MinterHolderV0";

    uint256 constant ONE_MILLION = 1_000_000;

    /// Set of core contracts allowed to be queried for token holders
    EnumerableSet.AddressSet private _registeredNFTAddresses;
    /// projectId => has project reached its maximum number of invocations?
    mapping(uint256 => bool) public projectMaxHasBeenInvoked;
    /// projectId => project's maximum number of invocations
    mapping(uint256 => uint256) public projectMaxInvocations;
    /// projectId => price per token in wei - supersedes any defined core price
    mapping(uint256 => uint256) private projectIdToPricePerTokenInWei;
    /// projectId => price per token has been configured on this minter
    mapping(uint256 => bool) private projectIdToPriceIsConfigured;

    /**
     * projectId => ownedNFTAddress => ownedNFTProjectIds => bool
     * projects whose holders are allowed to purchase a token on `projectId`
     */
    mapping(uint256 => mapping(address => mapping(uint256 => bool)))
        public allowedProjectHolders;

    modifier onlyCoreWhitelisted() {
        require(
            genArtCoreContract.isWhitelisted(msg.sender),
            "Only Core whitelisted"
        );
        _;
    }

    modifier onlyArtist(uint256 _projectId) {
        require(
            msg.sender ==
                genArtCoreContract.projectIdToArtistAddress(_projectId),
            "Only Artist"
        );
        _;
    }

    /**
     * @notice Initializes contract to be a Filtered Minter for
     * `_minterFilter`, integrated with Art Blocks core contract
     * at address `_genArt721Address`.
     * @param _genArt721Address Art Blocks core contract for which this
     * contract will be a minter.
     * @param _minterFilter Minter filter for which
     * this will a filtered minter.
     */
    constructor(address _genArt721Address, address _minterFilter)
        ReentrancyGuard()
    {
        genArt721CoreAddress = _genArt721Address;
        genArtCoreContract = IGenArt721CoreContractV1(_genArt721Address);
        minterFilterAddress = _minterFilter;
        minterFilter = IMinterFilterV0(_minterFilter);
        require(
            minterFilter.genArt721CoreAddress() == _genArt721Address,
            "Illegal contract pairing"
        );
    }

    /**
     *
     * @notice Registers holders of NFTs at address `_NFTAddress` to be
     * considered for minting. New core address is assumed to follow syntax of:
     * `projectId = tokenId / 1_000_000`
     * @param _NFTAddress NFT core address to be registered.
     */
    function registerNFTAddress(address _NFTAddress)
        external
        onlyCoreWhitelisted
    {
        _registeredNFTAddresses.add(_NFTAddress);
        emit RegisteredNFTAddress(_NFTAddress);
    }

    /**
     *
     * @notice Unregisters holders of NFTs at address `_NFTAddress` to be
     * considered for adding to future allowlists.
     * @param _NFTAddress NFT core address to be unregistered.
     */
    function unregisterNFTAddress(address _NFTAddress)
        external
        onlyCoreWhitelisted
    {
        _registeredNFTAddresses.remove(_NFTAddress);
        emit UnregisteredNFTAddress(_NFTAddress);
    }

    /**
     * @notice Allows holders of NFTs at address `_ownedNFTAddress`, project ID
     * `_ownedNFTProjectId` to mint on project `_projectId`.
     * @param _projectId Project ID to enable minting on.
     * @param _ownedNFTAddress NFT core address of project to be allowlisted.
     * @param _ownedNFTProjectId Project ID on `_ownedNFTAddress` whose
     * holders shall be allowlisted to mint project `_projectId`.
     */
    function allowHoldersOfProject(
        uint256 _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTProjectId
    ) external onlyArtist(_projectId) {
        // require _ownedNFTAddress be registered
        require(
            _registeredNFTAddresses.contains(_ownedNFTAddress),
            "Only Registered NFT Addresses"
        );
        allowedProjectHolders[_projectId][_ownedNFTAddress][
            _ownedNFTProjectId
        ] = true;
        emit AllowHoldersOfProject(
            _projectId,
            _ownedNFTAddress,
            _ownedNFTProjectId
        );
    }

    /**
     * @notice Removes holders of NFTs at address `_ownedNFTAddress`, project
     * ID `_ownedNFTProjectId` to mint on project `_projectId`. If other
     * projects owned by a holder are still allowed to mint, holder will
     * maintain ability to purchase.
     * @param _projectId Project ID to enable minting on.
     * @param _ownedNFTAddress NFT core address of project to be removed from
     * allowlist.
     * @param _ownedNFTProjectId Project ID on `_ownedNFTAddress` whose holders
     * will be removed from allowlist to mint project `_projectId`.
     */
    function removeHoldersOfProject(
        uint256 _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTProjectId
    ) external onlyArtist(_projectId) {
        allowedProjectHolders[_projectId][_ownedNFTAddress][
            _ownedNFTProjectId
        ] = false;
        emit RemovedHoldersOfProject(
            _projectId,
            _ownedNFTAddress,
            _ownedNFTProjectId
        );
    }

    /**
     * @notice Returns if token is an allowlisted NFT for project `_projectId`.
     * @param _projectId Project ID to be checked.
     * @param _ownedNFTAddress ERC-721 NFT token address to be checked.
     * @param _ownedNFTTokenId ERC-721 NFT token ID to be checked.
     * @return bool Token is allowlisted
     * @dev does not check if token has been used to purchase
     * @dev assumes project ID can be derived from tokenId / 1_000_000
     */
    function isAllowlistedNFT(
        uint256 _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId
    ) public view returns (bool) {
        uint256 ownedNFTProjectId = _ownedNFTTokenId / ONE_MILLION;
        return
            allowedProjectHolders[_projectId][_ownedNFTAddress][
                ownedNFTProjectId
            ];
    }

    /**
     * @notice Sets the maximum invocations of project `_projectId` based
     * on the value currently defined in the core contract.
     * @param _projectId Project ID to set the maximum invocations for.
     * @dev also checks and may refresh projectMaxHasBeenInvoked for project
     * @dev this enables gas reduction after maxInvocations have been reached -
     * core contracts shall still enforce a maxInvocation check during mint.
     */
    function setProjectMaxInvocations(uint256 _projectId)
        external
        onlyCoreWhitelisted
    {
        uint256 invocations;
        uint256 maxInvocations;
        (, , invocations, maxInvocations, , , , , ) = genArtCoreContract
            .projectTokenInfo(_projectId);
        // update storage with results
        projectMaxInvocations[_projectId] = maxInvocations;
        if (invocations < maxInvocations) {
            projectMaxHasBeenInvoked[_projectId] = false;
        }
    }

    /**
     * @notice Warning: Disabling purchaseTo is not supported on this minter.
     * This method exists purely for interface-conformance purposes.
     */
    function togglePurchaseToDisabled(uint256 _projectId)
        external
        view
        onlyArtist(_projectId)
    {
        revert("Action not supported");
    }

    /**
     * @notice Updates this minter's price per token of project `_projectId`
     * to be '_pricePerTokenInWei`, in Wei.
     * This price supersedes any legacy core contract price per token value.
     */
    function updatePricePerTokenInWei(
        uint256 _projectId,
        uint256 _pricePerTokenInWei
    ) external onlyArtist(_projectId) {
        projectIdToPricePerTokenInWei[_projectId] = _pricePerTokenInWei;
        projectIdToPriceIsConfigured[_projectId] = true;
        emit PricePerTokenInWeiUpdated(_projectId, _pricePerTokenInWei);
    }

    /**
     * @notice Inactive function - requires NFT ownership to purchase.
     */
    function purchase(uint256) external payable returns (uint256) {
        revert("Must claim NFT ownership");
    }

    /**
     * @notice Inactive function - requires NFT ownership to purchase.
     */
    function purchaseTo(address, uint256) public payable returns (uint256) {
        revert("Must claim NFT ownership");
    }

    /**
     * @notice Purchases a token from project `_projectId`.
     * @param _projectId Project ID to mint a token on.
     * @param _ownedNFTAddress ERC-721 NFT address owned by msg.sender being used to
     * prove right to purchase.
     * @param _ownedNFTTokenId ERC-721 NFT token ID owned by msg.sender being used
     * to prove right to purchase.
     * @return tokenId Token ID of minted token
     */
    function purchase(
        uint256 _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId
    ) external payable returns (uint256 tokenId) {
        tokenId = purchaseTo(
            msg.sender,
            _projectId,
            _ownedNFTAddress,
            _ownedNFTTokenId
        );
        return tokenId;
    }

    /**
     * @notice Purchases a token from project `_projectId` and sets
     * the token's owner to `_to`.
     * @param _to Address to be the new token's owner.
     * @param _projectId Project ID to mint a token on.
     * @param _ownedNFTAddress ERC-721 NFT address owned by msg.sender being used to
     * claim right to purchase.
     * @param _ownedNFTTokenId ERC-721 NFT token ID owned by msg.sender being used
     * to claim right to purchase.
     * @return tokenId Token ID of minted token
     */
    function purchaseTo(
        address _to,
        uint256 _projectId,
        address _ownedNFTAddress,
        uint256 _ownedNFTTokenId
    ) public payable nonReentrant returns (uint256 tokenId) {
        // CHECKS
        require(
            !projectMaxHasBeenInvoked[_projectId],
            "Maximum number of invocations reached"
        );

        require(
            msg.value >= projectIdToPricePerTokenInWei[_projectId],
            "Must send minimum value to mint!"
        );

        // require artist to have configured price of token on this minter
        require(
            projectIdToPriceIsConfigured[_projectId],
            "Price not configured"
        );

        // require token used to claim to be in set of allowlisted NFTs
        require(
            isAllowlistedNFT(_projectId, _ownedNFTAddress, _ownedNFTTokenId),
            "Only allowlisted NFTs"
        );

        // EFFECTS
        tokenId = minterFilter.mint(_to, _projectId, msg.sender);
        // what if projectMaxInvocations[_projectId] is 0 (default value)?
        // that is intended, so that by default the minter allows infinite transactions,
        // allowing the artblocks contract to stop minting
        // uint256 tokenInvocation = tokenId % ONE_MILLION;
        if (
            projectMaxInvocations[_projectId] > 0 &&
            tokenId % ONE_MILLION == projectMaxInvocations[_projectId] - 1
        ) {
            projectMaxHasBeenInvoked[_projectId] = true;
        }

        // INTERACTIONS
        // require sender to own NFT used to redeem
        /**
         * @dev Considered an interaction because calling ownerOf on an NFT
         * contract. Plan is to only register AB/PBAB NFTs on the minter, but
         * in case other NFTs are registered, better to check here. Also,
         * function is non-reentrant, so being extra cautious.
         */
        require(
            IERC721(_ownedNFTAddress).ownerOf(_ownedNFTTokenId) == msg.sender,
            "Only owner of NFT"
        );

        // split funds
        _splitFundsETH(_projectId);

        return tokenId;
    }

    /**
     * @dev splits ETH funds between sender (if refund), foundation,
     * artist, and artist's additional payee for a token purchased on
     * project `_projectId`.
     * @dev utilizes transfer() to send ETH, so access lists may need to be
     * populated when purchasing tokens.
     */
    function _splitFundsETH(uint256 _projectId) internal {
        if (msg.value > 0) {
            uint256 pricePerTokenInWei = projectIdToPricePerTokenInWei[
                _projectId
            ];
            uint256 refund = msg.value - pricePerTokenInWei;
            if (refund > 0) {
                (bool success_, ) = msg.sender.call{value: refund}("");
                require(success_, "Refund failed");
            }
            uint256 foundationAmount = (pricePerTokenInWei *
                genArtCoreContract.artblocksPercentage()) / 100;
            if (foundationAmount > 0) {
                (bool success_, ) = genArtCoreContract.artblocksAddress().call{
                    value: foundationAmount
                }("");
                require(success_, "Foundation payment failed");
            }
            uint256 projectFunds = pricePerTokenInWei - foundationAmount;
            uint256 additionalPayeeAmount;
            if (
                genArtCoreContract.projectIdToAdditionalPayeePercentage(
                    _projectId
                ) > 0
            ) {
                additionalPayeeAmount =
                    (projectFunds *
                        genArtCoreContract.projectIdToAdditionalPayeePercentage(
                            _projectId
                        )) /
                    100;
                if (additionalPayeeAmount > 0) {
                    (bool success_, ) = genArtCoreContract
                        .projectIdToAdditionalPayee(_projectId)
                        .call{value: additionalPayeeAmount}("");
                    require(success_, "Additional payment failed");
                }
            }
            uint256 creatorFunds = projectFunds - additionalPayeeAmount;
            if (creatorFunds > 0) {
                (bool success_, ) = genArtCoreContract
                    .projectIdToArtistAddress(_projectId)
                    .call{value: creatorFunds}("");
                require(success_, "Artist payment failed");
            }
        }
    }

    /**
     * @notice Gets quantity of NFT addresses registered on this minter.
     * @return uint256 quantity of NFT addresses registered
     */
    function getNumRegisteredNFTAddresses() external view returns (uint256) {
        return _registeredNFTAddresses.length();
    }

    /**
     * @notice Get registered NFT core contract address at index `_index` of
     * enumerable set.
     * @param _index enumerable set index to query.
     * @return NFTAddress NFT core contract address at index `_index`
     * @dev index must be < quantity of registered NFT addresses
     */
    function getRegisteredNFTAddressAt(uint256 _index)
        external
        view
        returns (address NFTAddress)
    {
        return _registeredNFTAddresses.at(_index);
    }

    /**
     * @notice Gets if price of token is configured, price of minting a
     * token on project `_projectId`, and currency symbol and address to be
     * used as payment. Supersedes any core contract price information.
     * @param _projectId Project ID to get price information for.
     * @return isConfigured true only if token price has been configured on
     * this minter
     * @return tokenPriceInWei current price of token on this minter - invalid
     * if price has not yet been configured
     * @return currencySymbol currency symbol for purchases of project on this
     * minter. This minter always returns "ETH"
     * @return currencyAddress currency address for purchases of project on
     * this minter. This minter always returns null address, reserved for ether
     */
    function getPriceInfo(uint256 _projectId)
        external
        view
        returns (
            bool isConfigured,
            uint256 tokenPriceInWei,
            string memory currencySymbol,
            address currencyAddress
        )
    {
        isConfigured = projectIdToPriceIsConfigured[_projectId];
        tokenPriceInWei = projectIdToPricePerTokenInWei[_projectId];
        currencySymbol = "ETH";
        currencyAddress = address(0);
    }
}
