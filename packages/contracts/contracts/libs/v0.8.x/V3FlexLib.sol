// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

pragma solidity ^0.8.0;

import {IGenArt721CoreContractV3_Engine_Flex} from "../../interfaces/v0.8.x/IGenArt721CoreContractV3_Engine_Flex.sol";
import {BytecodeStorageWriter, BytecodeStorageReader} from "./BytecodeStorageV1.sol";

/**
 * @title Art Blocks V3 Engine Flex - External Helper Library
 * @notice This library is designed to offload bytecode from the V3 Engine
 * Flex contract. It implements logic that may be accessed via DELEGATECALL for
 * operations related to the V3 Engine Flex contract.
 * @author Art Blocks Inc.
 */

library V3FlexLib {
    using BytecodeStorageWriter for string;
    // For the purposes of this implementation, due to the limited scope and
    // existing legacy infrastructure, the library emits the events
    // defined in IGenArt721CoreContractV3_Engine_Flex.sol. The events are
    // manually duplicated here
    /**
     * @notice When an external asset dependency is updated or added, this event is emitted.
     * @param _projectId The project ID of the project that was updated.
     * @param _index The index of the external asset dependency that was updated.
     * @param _cid The content ID of the external asset dependency. This is an empty string
     * if the dependency type is ONCHAIN.
     * @param _dependencyType The type of the external asset dependency.
     * @param _externalAssetDependencyCount The number of external asset dependencies.
     */
    event ExternalAssetDependencyUpdated(
        uint256 indexed _projectId,
        uint256 indexed _index,
        string _cid,
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependencyType _dependencyType,
        uint24 _externalAssetDependencyCount
    );

    /**
     * @notice The project id `_projectId` has had an external asset dependency removed at index `_index`.
     */
    event ExternalAssetDependencyRemoved(
        uint256 indexed _projectId,
        uint256 indexed _index
    );

    /**
     * @notice The preferred gateway for dependency type `_dependencyType` has been updated to `_gatewayAddress`.
     */
    event GatewayUpdated(
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependencyType indexed _dependencyType,
        string _gatewayAddress
    );

    /**
     * @notice The project id `_projectId` has had all external asset dependencies locked.
     * @dev This is a one-way operation. Once locked, the external asset dependencies cannot be updated.
     */
    event ProjectExternalAssetDependenciesLocked(uint256 indexed _projectId);

    // position of V3 Flex Lib storage, using a diamond storage pattern
    // for this library
    bytes32 constant V3_FLEX_LIB_STORAGE_POSITION =
        keccak256("v3flexlib.storage");

    // project-level variables
    /**
     * Struct used to store a project's currently configured price, and
     * whether or not the price has been configured.
     */
    struct FlexProjectData {
        bool externalAssetDependenciesLocked;
        uint24 externalAssetDependencyCount;
        mapping(uint256 => IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependency) externalAssetDependencies;
    }

    // Diamond storage pattern is used in this library
    struct V3FlexLibStorage {
        string preferredIPFSGateway;
        string preferredArweaveGateway;
        mapping(uint256 projectId => FlexProjectData) flexProjectsData;
    }

    /**
     * @notice Updates preferredIPFSGateway to `_gateway`.
     */
    function updateIPFSGateway(string calldata _gateway) external {
        s().preferredIPFSGateway = _gateway;
        emit GatewayUpdated(
            IGenArt721CoreContractV3_Engine_Flex
                .ExternalAssetDependencyType
                .IPFS,
            _gateway
        );
    }

    /**
     * @notice Updates preferredArweaveGateway to `_gateway`.
     */
    function updateArweaveGateway(string calldata _gateway) external {
        s().preferredArweaveGateway = _gateway;
        emit GatewayUpdated(
            IGenArt721CoreContractV3_Engine_Flex
                .ExternalAssetDependencyType
                .ARWEAVE,
            _gateway
        );
    }

    /**
     * @notice Locks external asset dependencies for project `_projectId`.
     */
    function lockProjectExternalAssetDependencies(uint256 _projectId) external {
        FlexProjectData storage flexProjectData = getFlexProjectData(
            _projectId
        );
        _onlyUnlockedProjectExternalAssetDependencies(flexProjectData);
        flexProjectData.externalAssetDependenciesLocked = true;
        emit ProjectExternalAssetDependenciesLocked(_projectId);
    }

    /**
     * @notice Updates external asset dependency for project `_projectId`.
     * @dev Making this an external function adds roughly 1% to the gas cost of adding an asset, but
     * significantly reduces the bytecode of contracts using this library.
     * @param _projectId Project to be updated.
     * @param _index Asset index.
     * @param _cidOrData Asset cid (Content identifier) or data string to be translated into bytecode.
     * @param _dependencyType Asset dependency type.
     *  0 - IPFS
     *  1 - ARWEAVE
     *  2 - ONCHAIN
     */
    function updateProjectExternalAssetDependency(
        uint256 _projectId,
        uint256 _index,
        string memory _cidOrData,
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependencyType _dependencyType
    ) external {
        FlexProjectData storage flexProjectData = getFlexProjectData(
            _projectId
        );
        _onlyUnlockedProjectExternalAssetDependencies(flexProjectData);
        uint24 assetCount = flexProjectData.externalAssetDependencyCount;
        require(_index < assetCount, "Asset index out of range");
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependency
            storage _oldDependency = flexProjectData.externalAssetDependencies[
                _index
            ];
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependencyType _oldDependencyType = _oldDependency
                .dependencyType;
        flexProjectData
            .externalAssetDependencies[_index]
            .dependencyType = _dependencyType;
        // if the incoming dependency type is onchain, we need to write the data to bytecode
        if (
            _dependencyType ==
            IGenArt721CoreContractV3_Engine_Flex
                .ExternalAssetDependencyType
                .ONCHAIN
        ) {
            if (
                _oldDependencyType !=
                IGenArt721CoreContractV3_Engine_Flex
                    .ExternalAssetDependencyType
                    .ONCHAIN
            ) {
                // we only need to set the cid to an empty string if we are replacing an offchain asset
                // an onchain asset will already have an empty cid
                flexProjectData.externalAssetDependencies[_index].cid = "";
            }

            flexProjectData
                .externalAssetDependencies[_index]
                .bytecodeAddress = _cidOrData.writeToBytecode();
            // we don't want to emit data, so we emit the cid as an empty string
            _cidOrData = "";
        } else {
            flexProjectData.externalAssetDependencies[_index].cid = _cidOrData;
        }
        emit ExternalAssetDependencyUpdated(
            _projectId,
            _index,
            _cidOrData,
            _dependencyType,
            assetCount
        );
    }

    /**
     * @notice Removes external asset dependency for project `_projectId` at index `_index`.
     * Removal is done by swapping the element to be removed with the last element in the array, then deleting this last element.
     * Assets with indices higher than `_index` can have their indices adjusted as a result of this operation.
     * @param _projectId Project to be updated.
     * @param _index Asset index
     */
    function removeProjectExternalAssetDependency(
        uint256 _projectId,
        uint256 _index
    ) external {
        FlexProjectData storage flexProjectData = getFlexProjectData(
            _projectId
        );
        _onlyUnlockedProjectExternalAssetDependencies(flexProjectData);
        uint24 assetCount = flexProjectData.externalAssetDependencyCount;
        require(_index < assetCount, "Asset index out of range");

        uint24 lastElementIndex = assetCount - 1;

        // copy last element to index of element to be removed
        flexProjectData.externalAssetDependencies[_index] = flexProjectData
            .externalAssetDependencies[lastElementIndex];

        delete flexProjectData.externalAssetDependencies[lastElementIndex];

        flexProjectData.externalAssetDependencyCount = lastElementIndex;

        emit ExternalAssetDependencyRemoved(_projectId, _index);
    }

    /**
     * @notice Adds external asset dependency for project `_projectId`.
     * @dev Making this an external function adds roughly 1% to the gas cost of adding an asset, but
     * significantly reduces the bytecode of contracts using this library.
     * @param _projectId Project to be updated.
     * @param _cidOrData Asset cid (Content identifier) or data string to be translated into bytecode.
     * @param _dependencyType Asset dependency type.
     *  0 - IPFS
     *  1 - ARWEAVE
     *  2 - ONCHAIN
     */
    function addProjectExternalAssetDependency(
        uint256 _projectId,
        string memory _cidOrData,
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependencyType _dependencyType
    ) external {
        FlexProjectData storage flexProjectData = getFlexProjectData(
            _projectId
        );
        _onlyUnlockedProjectExternalAssetDependencies(flexProjectData);
        uint24 assetCount = flexProjectData.externalAssetDependencyCount;
        address _bytecodeAddress = address(0);
        // if the incoming dependency type is onchain, we need to write the data to bytecode
        if (
            _dependencyType ==
            IGenArt721CoreContractV3_Engine_Flex
                .ExternalAssetDependencyType
                .ONCHAIN
        ) {
            _bytecodeAddress = _cidOrData.writeToBytecode();
            // we don't want to emit data, so we emit the cid as an empty string
            _cidOrData = "";
        }
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependency
            memory asset = IGenArt721CoreContractV3_Engine_Flex
                .ExternalAssetDependency({
                    cid: _cidOrData,
                    dependencyType: _dependencyType,
                    bytecodeAddress: _bytecodeAddress
                });
        flexProjectData.externalAssetDependencies[assetCount] = asset;
        flexProjectData.externalAssetDependencyCount = assetCount + 1;

        emit ExternalAssetDependencyUpdated(
            _projectId,
            assetCount,
            _cidOrData,
            _dependencyType,
            assetCount + 1
        );
    }

    /**
     * @notice Returns external asset dependency count for project `_projectId` at index `_index`.
     */
    function projectExternalAssetDependencyCount(
        uint256 _projectId
    ) external view returns (uint256) {
        FlexProjectData storage flexProjectData = getFlexProjectData(
            _projectId
        );
        return uint256(flexProjectData.externalAssetDependencyCount);
    }

    /**
     * @notice Returns external asset dependency for project `_projectId` at index `_index`.
     * If the dependencyType is ONCHAIN, the `data` field will contain the extrated bytecode data and `cid`
     * will be an empty string. Conversly, for any other dependencyType, the `data` field will be an empty string
     * and the `bytecodeAddress` will point to the zero address.
     */
    function projectExternalAssetDependencyByIndex(
        uint256 _projectId,
        uint256 _index
    )
        external
        view
        returns (
            IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependencyWithData
                memory
        )
    {
        FlexProjectData storage flexProjectData = getFlexProjectData(
            _projectId
        );
        IGenArt721CoreContractV3_Engine_Flex.ExternalAssetDependency
            storage _dependency = flexProjectData.externalAssetDependencies[
                _index
            ];
        address _bytecodeAddress = _dependency.bytecodeAddress;

        return
            IGenArt721CoreContractV3_Engine_Flex
                .ExternalAssetDependencyWithData({
                    dependencyType: _dependency.dependencyType,
                    cid: _dependency.cid,
                    bytecodeAddress: _bytecodeAddress,
                    data: (_dependency.dependencyType ==
                        IGenArt721CoreContractV3_Engine_Flex
                            .ExternalAssetDependencyType
                            .ONCHAIN)
                        ? BytecodeStorageReader.readFromBytecode(
                            _bytecodeAddress
                        )
                        : ""
                });
    }

    /**
     * @notice Returns the preferred IPFS gateway.
     */
    function preferredIPFSGateway() external view returns (string memory) {
        return s().preferredIPFSGateway;
    }

    /**
     * @notice Returns the preferred Arweave gateway.
     */
    function preferredArweaveGateway() external view returns (string memory) {
        return s().preferredArweaveGateway;
    }

    /**
     * @notice Loads the FlexProjectData for a given project.
     * @param projectId Project Id to get FlexProjectData for
     */
    function getFlexProjectData(
        uint256 projectId
    ) internal view returns (FlexProjectData storage) {
        return s().flexProjectsData[projectId];
    }

    /**
     * @notice Return the storage struct for reading and writing. This library
     * uses a diamond storage pattern when managing storage.
     * @return storageStruct The V3FlexLibStorage struct.
     */
    function s()
        internal
        pure
        returns (V3FlexLibStorage storage storageStruct)
    {
        bytes32 position = V3_FLEX_LIB_STORAGE_POSITION;
        assembly ("memory-safe") {
            storageStruct.slot := position
        }
    }

    function _onlyUnlockedProjectExternalAssetDependencies(
        FlexProjectData storage flexProjectData
    ) private view {
        require(
            !flexProjectData.externalAssetDependenciesLocked,
            "External dependencies locked"
        );
    }
}