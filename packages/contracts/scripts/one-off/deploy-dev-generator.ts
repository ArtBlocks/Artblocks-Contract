// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

import hre, { ethers, upgrades } from "hardhat";
import {
  BytecodeStorageV1Writer__factory,
  GenArt721GeneratorV0,
} from "../contracts";
import { GenArt721GeneratorV0__factory } from "../contracts/factories/generator/GenArt721GeneratorV0__factory";
import { getNetworkName } from "../util/utils";
import { GUNZIP_SCRIPT_BASE64 } from "../util/constants";
import { StorageContractCreatedEvent } from "../contracts/BytecodeStorageV1Writer";

const universalBytecodeStorageReaderAddress =
  "0x000000069EbaecF0d656897bA5527f2145560086";
const dependencyRegistryAddress = "0x5Fcc415BCFb164C5F826B5305274749BeB684e9b";
const scriptyBuilderV2Address = "0xD7587F110E08F4D120A231bA97d3B577A81Df022";

async function main() {
  const [deployer] = await ethers.getSigners();
  const networkName = await getNetworkName();
  if (networkName != "sepolia") {
    throw new Error("This script is intended to be run on sepolia only");
  }
  //////////////////////////////////////////////////////////////////////////////
  // DEPLOYMENT BEGINS HERE
  //////////////////////////////////////////////////////////////////////////////
  // Deploy BytecodeStorageV1Writer contract
  const bytecodeStorageV1WriterFactory = new BytecodeStorageV1Writer__factory(
    deployer
  );
  const bytecodeStorageV1Writer = await bytecodeStorageV1WriterFactory.deploy();
  console.log(
    `BytecodeStorageV1Writer deployed at ${bytecodeStorageV1Writer.address}`
  );

  // Use BytecodeStorageV1Writer to upload gunzip script
  const gunzipUploadTransaction = await bytecodeStorageV1Writer
    .connect(deployer)
    .writeStringToBytecodeStorage(GUNZIP_SCRIPT_BASE64);

  // Get address of gunzip storage contract from StorageContractCreated event
  const gunzipUploadReceipt = await gunzipUploadTransaction.wait();
  const storageContractCreatedEvent = gunzipUploadReceipt.events?.find(
    (event) => {
      if (event.event === "StorageContractCreated") {
        return true;
      }
    }
  );
  if (!storageContractCreatedEvent) {
    throw new Error("Failed to find StorageContractCreated event");
  }
  const gunzipStorageContractAddress = (
    storageContractCreatedEvent as StorageContractCreatedEvent
  ).args.storageContract;

  const genArt721GeneratorFactory = new GenArt721GeneratorV0__factory(deployer);
  const genArt721Generator: GenArt721GeneratorV0 = (await upgrades.deployProxy(
    genArt721GeneratorFactory,
    [
      dependencyRegistryAddress,
      scriptyBuilderV2Address,
      gunzipStorageContractAddress,
      universalBytecodeStorageReaderAddress,
    ]
  )) as GenArt721GeneratorV0;
  await genArt721Generator.deployed();

  const genArt721GeneratorAddress = genArt721Generator.address;
  const implementationAddress = await upgrades.erc1967.getImplementationAddress(
    genArt721GeneratorAddress
  );
  console.log(
    `GenArt721GeneratorV0 implementation deployed at ${implementationAddress}`
  );
  console.log(`GenArt721GeneratorV0 deployed at ${genArt721GeneratorAddress}`);

  // Wait for 10 seconds to make sure etherscan has indexed the contracts
  await new Promise((resolve) => setTimeout(resolve, 10000));

  // //////////////////////////////////////////////////////////////////////////////
  // // DEPLOYMENT ENDS HERE
  // //////////////////////////////////////////////////////////////////////////////

  // //////////////////////////////////////////////////////////////////////////////
  // // SETUP BEGINS HERE
  // //////////////////////////////////////////////////////////////////////////////

  try {
    await hre.run("verify:verify", {
      address: bytecodeStorageV1Writer.address,
    });
  } catch (e) {
    console.error("Failed to verify ETHFSFileStorage programatically", e);
  }

  try {
    await hre.run("verify:verify", {
      address: implementationAddress,
    });
  } catch (e) {
    console.error("Failed to verify GenArt721GeneratorV0 programatically", e);
  }

  //////////////////////////////////////////////////////////////////////////////
  // SETUP ENDS HERE
  //////////////////////////////////////////////////////////////////////////////
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
