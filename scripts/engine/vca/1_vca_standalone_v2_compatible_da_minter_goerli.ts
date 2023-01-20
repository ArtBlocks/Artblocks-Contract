// SPDX-License-Identifier: LGPL-3.0-only
// Created By: Art Blocks Inc.

import { ethers } from "hardhat";
import { GenArt721MinterDAExpPBAB__factory } from "../../contracts/factories/GenArt721MinterDAExpPBAB__factory";

//////////////////////////////////////////////////////////////////////////////
// CONFIG BEGINS HERE
//////////////////////////////////////////////////////////////////////////////

// Replace with core contract address of already deployed core contract.
const coreContractAddress = "0xAbf9B1c2c14399CFD1753BE2090b7dA3c0A1434B";

//////////////////////////////////////////////////////////////////////////////
// CONFIG ENDS HERE
//////////////////////////////////////////////////////////////////////////////

async function main() {
  const [deployer] = await ethers.getSigners();
  const network = await ethers.provider.getNetwork();
  const networkName = network.name == "homestead" ? "mainnet" : network.name;

  //////////////////////////////////////////////////////////////////////////////
  // DEPLOYMENT BEGINS HERE
  //////////////////////////////////////////////////////////////////////////////

  // Deploy Randomizer contract.
  const minterFactory = new GenArt721MinterDAExpPBAB__factory(deployer);
  const minter = await minterFactory.deploy(coreContractAddress);

  await minter.deployed();
  console.log(`MinterDAExp deployed at ${minter.address}`);
  console.log(`Verify deployment with:`);
  console.log(
    `yarn hardhat verify --network ${networkName} ${minter.address} ${coreContractAddress}`
  );
  console.log(
    `REMINDER: CoreContract controller (likely a partner) must allowlist this new minter and un-allowlist any old minter.`
  );

  //////////////////////////////////////////////////////////////////////////////
  // DEPLOYMENT ENDS HERE
  //////////////////////////////////////////////////////////////////////////////
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
