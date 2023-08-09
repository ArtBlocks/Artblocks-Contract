// SPDX-License-Identifier: LGPL-3.0-only
// Creatd By: Art Blocks Inc.

pragma solidity 0.8.19;

import "../../interfaces/v0.8.x/IGenArt721CoreContractV3_Base.sol";
import "../../interfaces/v0.8.x/ISharedRandomizerV0.sol";
import "../../interfaces/v0.8.x/IPseudorandomAtomic.sol";

/**
 * @title A shared randomizer contract that enables support of many Art Blocks
 * and Art Blocks Engine core contracts with a single randomizer.
 * @notice This randomizer is designed to be used with many core contracts that
 * implement the `IGenArt721CoreContractV3_Base` interface. It exclusively uses
 * atomic callbacks, and will assign a token's hash before returning from the
 * `assignTokenHash` function, as long as the call does not revert.
 *
 * The randomizer generates a token's hash seed in one of two ways:
 * 1. If the project of the token is specified as using a hash seed setter
 * contract, the randomizer will assign the token the hash seed as previously
 * pre-set by the project's hash seed setter contract. If no hash seed has
 * been set, the randomizer will revert (will not assign null token hash).
 * 2. If the project of the token is not specified as using a hash seed setter
 * contract, the randomizer will generate a new hash seed using the
 * `IPseudorandomAtomic` contract, which is immutable and set during
 * deployment.
 *
 * @dev When using this randomizer for ployptych minting, several requirements
 * may be required by the hash seed setter contract, including the possibility
 * that a token's hash seed must be available in a public getter function on
 * the core contract. Please inspect the hash seed setter contract to ensure
 * that all requirements are met.
 *
 * @notice Privileged Roles and Ownership:
 * Privileged roles and abilities are controlled by each core contract's
 * artists.
 * These roles hold extensive power and can influence the behavior of this
 * randomizer.
 * Care must be taken to ensure that the artist addresses are secure.
 * ----------------------------------------------------------------------------
 * The following functions are restricted to only the Artist address:
 * - setHashSeedSetterContract
 * - toggleProjectUseAssignedHashSeed
 * ----------------------------------------------------------------------------
 * The following function is restricted to only the hash seed setter contract
 * of a given core contract:
 * - preSetHashSeed
 * ----------------------------------------------------------------------------
 * Additional admin and artist privileged roles may be described on minters,
 * registries, and other contracts that may interact with this randomizer.
 */
contract SharedRandomizerV0 is ISharedRandomizerV0 {
    IPseudorandomAtomic public immutable pseudorandomAtomicContract;

    // constant used to obtain the project ID from the token ID
    uint256 internal constant ONE_MILLION = 1_000_000;

    // mapping of core contract => token ID => pre-assigned hash seed
    // @dev this mapping is only used when the project is configured as using
    // a hash seed setter contract. It is not populated when the project is
    // using pseudorandomAtomicContract.
    mapping(address => mapping(uint256 => bytes12))
        private _preAssignedHashSeeds;

    // mapping of core contract => project ID => usesHashSeedSetter Contract
    mapping(address => mapping(uint256 => bool))
        private _projectUsesHashSeedSetter;

    // mapping of core contract => projectId => hash seed setter contract
    mapping(address => mapping(uint256 => address))
        private _hashSeedSetterContracts;

    // modifier to restrict access to only Artist allowed calls
    function _onlyArtist(
        address _coreContract,
        uint256 _projectId
    ) internal view {
        require(
            msg.sender ==
                IGenArt721CoreContractV3_Base(_coreContract)
                    .projectIdToArtistAddress(_projectId),
            "Only Artist"
        );
    }

    /**
     * Modifier to restrict access to only calls by the hash seed setter
     * contract of a given project.
     * @param _coreContract core contract address associated with the project
     * @param _projectId project ID being set
     */
    function _onlyHashSeedSetterContract(
        address _coreContract,
        uint256 _projectId
    ) internal view {
        require(
            msg.sender == _hashSeedSetterContracts[_coreContract][_projectId],
            "Only Hash Seed Setter Contract"
        );
    }

    /**
     *
     * @param _pseudorandomAtomicContract Address of the pseudorandom atomic
     * contract to use for atomically generating random values. This contract
     * does not have an owner, and therefore the pseudorandom atomic contract
     * address cannot be changed after deployment.
     */
    constructor(address _pseudorandomAtomicContract) {
        pseudorandomAtomicContract = IPseudorandomAtomic(
            _pseudorandomAtomicContract
        );
        emit PseudorandomAtomicContractUpdated({
            pseudorandomAtomicContract: _pseudorandomAtomicContract
        });
    }

    /**
     * @inheritdoc ISharedRandomizerV0
     */
    function setHashSeedSetterContract(
        address _coreContract,
        uint256 _projectId,
        address _hashSeedSetterContract
    ) external {
        _onlyArtist(_coreContract, _projectId);
        _hashSeedSetterContracts[_coreContract][
            _projectId
        ] = _hashSeedSetterContract;
        emit HashSeedSetterForProjectUpdated({
            coreContract: _coreContract,
            projectId: _projectId,
            hashSeedSetterContract: _hashSeedSetterContract
        });
    }

    /**
     * @inheritdoc ISharedRandomizerV0
     */
    function toggleProjectUseAssignedHashSeed(
        address _coreContract,
        uint256 _projectId
    ) external {
        _onlyArtist(_coreContract, _projectId);
        _projectUsesHashSeedSetter[_coreContract][
            _projectId
        ] = !_projectUsesHashSeedSetter[_coreContract][_projectId];
        emit ProjectUsingHashSeedSetterUpdated({
            coreContract: _coreContract,
            projectId: _projectId,
            usingHashSeedSetter: _projectUsesHashSeedSetter[_coreContract][
                _projectId
            ]
        });
    }

    /**
     * @inheritdoc ISharedRandomizerV0
     */
    function preSetHashSeed(
        address _coreContract,
        uint256 _tokenId,
        bytes12 _hashSeed
    ) external {
        uint256 projectId = _tokenIdToProjectId(_tokenId);
        _onlyHashSeedSetterContract(_coreContract, projectId);
        _preAssignedHashSeeds[_coreContract][_tokenId] = _hashSeed;
        // @dev event indicating token hash seed assigned is not required for
        // subgraph indexing because token hash seeds are still assigned
        // atomically in `assignTokenHash` function. If token hash seeds were
        // assigned async, event emission may be required to support subgraph
        // indexing.
    }

    /**
     * @inheritdoc IRandomizer_V3CoreBase
     */
    function assignTokenHash(uint256 _tokenId) external {
        // @dev This function is not specifically gated to any specific caller,
        // but will only call back to the calling contract, `msg.sender`, to
        // set the specified token's hash seed.
        // A third party contract calling this function will not be able to set
        // the token hash seed on a different core contract.
        // @dev variables are named to improve readability
        address coreContract = msg.sender;
        uint256 projectId = _tokenIdToProjectId(_tokenId);
        bytes32 hashSeed;
        if (_projectUsesHashSeedSetter[coreContract][projectId]) {
            hashSeed = _preAssignedHashSeeds[coreContract][_tokenId];
        } else {
            hashSeed = _getPseudorandomAtomic(coreContract, _tokenId);
        }
        // verify that the hash seed is non-zero
        require(hashSeed != 0, "Only non-zero hash seed");
        // assign the token hash seed on the core contract
        IGenArt721CoreContractV3_Base(coreContract).setTokenHash_8PT(
            _tokenId,
            hashSeed
        );
    }

    /**
     * @inheritdoc ISharedRandomizerV0
     */
    function projectUsesHashSeedSetter(
        address _coreContract,
        uint256 _projectId
    ) external view returns (bool _usingHashSeedSetter) {
        return _projectUsesHashSeedSetter[_coreContract][_projectId];
    }

    /**
     * @inheritdoc ISharedRandomizerV0
     */
    function hashSeedSetterContracts(
        address _coreContract,
        uint256 _projectId
    ) external view returns (address _hashSeedSetterContract) {
        return _hashSeedSetterContracts[_coreContract][_projectId];
    }

    /**
     * @inheritdoc ISharedRandomizerV0
     */
    function preAssignedHashSeed(
        address _coreContract,
        uint256 _tokenId
    ) external view returns (bytes12 _hashSeed) {
        return _preAssignedHashSeeds[_coreContract][_tokenId];
    }

    /**
     * @notice Internal function to atomically obtain a pseudorandom number
     * from the configured pseudorandom contract.
     * @param _coreContract - The core contract that is requesting an atomic
     * pseudorandom number.
     * @param _tokenId - The token ID on `_coreContract` that is associated
     * with the pseudorandom number request.
     */
    function _getPseudorandomAtomic(
        address _coreContract,
        uint256 _tokenId
    ) internal view returns (bytes32) {
        return
            pseudorandomAtomicContract.getPseudorandomAtomic(
                keccak256(abi.encodePacked(_coreContract, _tokenId))
            );
    }

    /**
     * @notice Gets the project ID for a given `_tokenId`.
     * @param _tokenId Token ID to be queried.
     * @return projectId Project ID for given `_tokenId`.
     */
    function _tokenIdToProjectId(
        uint256 _tokenId
    ) internal pure returns (uint256 projectId) {
        return _tokenId / ONE_MILLION;
    }
}
