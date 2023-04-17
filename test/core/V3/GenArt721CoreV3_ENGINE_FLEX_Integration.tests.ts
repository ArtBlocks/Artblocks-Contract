import {
  BN,
  constants,
  expectEvent,
  expectRevert,
  balance,
  ether,
} from "@openzeppelin/test-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

import {
  T_Config,
  getAccounts,
  assignDefaultConstants,
  deployAndGet,
  deployCoreWithMinterFilter,
  mintProjectUntilRemaining,
  advanceEVMByTime,
} from "../../util/common";
import { FOUR_WEEKS } from "../../util/constants";

// test the following V3 core contract derivatives:
const coreContractsToTest = [
  "GenArt721CoreV3_Engine_Flex", // V3 core Engine Flex contract
  "GenArt721CoreV3_Engine_Flex_PROHIBITION", // V3 core Engine Flex contract
];

/**
 * Flex functionality integration tests for V3 core Engine Flex.
 */
for (const coreContractName of coreContractsToTest) {
  describe(`${coreContractName} Integration`, async function () {
    async function _beforeEach() {
      let config: T_Config = {
        accounts: await getAccounts(),
      };
      config = await assignDefaultConstants(config);

      // deploy and configure minter filter and minter
      ({
        genArt721Core: config.genArt721Core,
        minterFilter: config.minterFilter,
        randomizer: config.randomizer,
        adminACL: config.adminACL,
      } = await deployCoreWithMinterFilter(
        config,
        coreContractName,
        "MinterFilterV1"
      ));

      config.minter = await deployAndGet(config, "MinterSetPriceV2", [
        config.genArt721Core.address,
        config.minterFilter.address,
      ]);

      // add project
      await config.genArt721Core
        .connect(config.accounts.deployer)
        .addProject("name", config.accounts.artist.address);
      await config.genArt721Core
        .connect(config.accounts.deployer)
        .toggleProjectIsActive(config.projectZero);
      await config.genArt721Core
        .connect(config.accounts.artist)
        .updateProjectMaxInvocations(config.projectZero, config.maxInvocations);

      // configure minter for project zero
      await config.minterFilter
        .connect(config.accounts.deployer)
        .addApprovedMinter(config.minter.address);
      await config.minterFilter
        .connect(config.accounts.deployer)
        .setMinterForProject(config.projectZero, config.minter.address);
      await config.minter
        .connect(config.accounts.artist)
        .updatePricePerTokenInWei(config.projectZero, 0);
      return config;
    }

    describe("external asset dependencies", async function () {
      it("can add an external asset dependency (off-chain)", async function () {
        const config = await loadFixture(_beforeEach);
        // add external asset dependency to project 0
        await expect(
          config.genArt721Core
            .connect(config.accounts.artist)
            .addProjectExternalAssetDependency(
              config.projectZero,
              "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
              0
            )
        )
          .to.emit(config.genArt721Core, "ExternalAssetDependencyUpdated")
          .withArgs(
            0,
            0,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
            0,
            1
          );
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);

        expect(externalAssetDependency[0]).to.equal(
          "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo"
        );
        expect(externalAssetDependency[1]).to.equal(0);
        expect(externalAssetDependency[2]).to.equal(constants.ZERO_ADDRESS);
        expect(externalAssetDependency[3]).to.equal("");
      });

      it("can add an external asset dependency (on-chain)", async function () {
        const config = await loadFixture(_beforeEach);
        // add external asset dependency to project 0
        const dataString = "here is some data";
        await expect(
          config.genArt721Core
            .connect(config.accounts.artist)
            .addProjectExternalAssetDependency(
              config.projectZero,
              dataString,
              2
            )
        )
          .to.emit(config.genArt721Core, "ExternalAssetDependencyUpdated")
          .withArgs(0, 0, "", 2, 1);
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);

        expect(externalAssetDependency[0]).to.equal("");
        expect(externalAssetDependency[1]).to.equal(2);
        expect(externalAssetDependency[2]).to.not.equal(constants.ZERO_ADDRESS);
        expect(externalAssetDependency[3]).to.equal(dataString);
      });

      it("can remove an external asset dependency (off-chain)", async function () {
        const config = await loadFixture(_beforeEach);
        // add assets for project 0 at index 0, 1, 2
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
            0
          );
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo2",
            1
          );
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo3",
            0
          );
        // remove external asset at index 1
        await config.genArt721Core
          .connect(config.accounts.artist)
          .removeProjectExternalAssetDependency(0, 1);

        // project external asset info at index 2 should be set back to default values as a result of being deleted
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 2);
        expect(externalAssetDependency[0]).to.equal("");
        expect(externalAssetDependency[1]).to.equal(0);

        // project external asset info at index 1 should be set be set to the same values as index 2, prior to removal
        // config test also validates the deepy copy of the shifted external asset dependency
        const externalAssetDependencyAtIndex1 = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 1);
        expect(externalAssetDependencyAtIndex1[0]).to.equal(
          "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo3"
        );
        expect(externalAssetDependencyAtIndex1[1]).to.equal(0);

        const externalAssetDependencyCount = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyCount(0);
        expect(externalAssetDependencyCount).to.equal(2);
      });

      it("can remove an external asset dependency (on-chain)", async function () {
        const config = await loadFixture(_beforeEach);
        const dataString = "here is some data";
        const dataString2 = "here is some data2";
        // add assets for project 0 at index 0, 1, 2
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
            0
          );
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(config.projectZero, dataString, 1);
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            dataString2,
            2
          );

        const externalAssetDependencyAtIndex2BeforeDeletion =
          await config.genArt721Core
            .connect(config.accounts.artist)
            .projectExternalAssetDependencyByIndex(0, 2);

        // remove external asset at index 1
        await config.genArt721Core
          .connect(config.accounts.artist)
          .removeProjectExternalAssetDependency(0, 1);

        // project external asset info at index 2 should be set back to default values as a result of being deleted
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 2);
        expect(externalAssetDependency[0]).to.equal("");
        expect(externalAssetDependency[1]).to.equal(0);
        expect(externalAssetDependency[2]).to.equal(constants.ZERO_ADDRESS);
        expect(externalAssetDependency[3]).to.equal("");

        // project external asset info at index 1 should be set be set to the same values as index 2, prior to removal
        // config test also validates the deepy copy of the shifted external asset dependency
        const externalAssetDependencyAtIndex1 = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 1);
        expect(externalAssetDependencyAtIndex1[0]).to.equal("");
        expect(externalAssetDependencyAtIndex1[1]).to.equal(2);
        expect(externalAssetDependencyAtIndex1[2]).to.equal(
          externalAssetDependencyAtIndex2BeforeDeletion[2]
        );
        expect(externalAssetDependencyAtIndex1[3]).to.equal(dataString2);

        const externalAssetDependencyCount = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyCount(0);
        expect(externalAssetDependencyCount).to.equal(2);
      });

      it("can update an external asset dependency (off-chain)", async function () {
        const config = await loadFixture(_beforeEach);
        // add assets for project 0 at index 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
            0
          );
        // get asset info at index 0 for project 0
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);
        expect(externalAssetDependency[0]).to.equal(
          "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo"
        );
        expect(externalAssetDependency[1]).to.equal(0);
        // update asset info at index 0 for project 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectExternalAssetDependency(
            0,
            0,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo2",
            1
          );

        const externalAssetDependency2 = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);
        expect(externalAssetDependency2[0]).to.equal(
          "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo2"
        );
        expect(externalAssetDependency2[1]).to.equal(1);
      });

      it("can update an external asset dependency (on-chain)", async function () {
        const config = await loadFixture(_beforeEach);
        // validating that an off-chain asset dependency can be updated to an on-chain asset dependency
        const exampleCID = "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo";
        const dataString = "here is some data";
        // add assets for project 0 at index 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(config.projectZero, exampleCID, 0);
        // get asset info at index 0 for project 0
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);
        expect(externalAssetDependency[0]).to.equal(exampleCID);
        expect(externalAssetDependency[1]).to.equal(0);

        // update asset info at index 0 for project 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectExternalAssetDependency(0, 0, dataString, 2);

        const externalAssetDependency2 = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);
        expect(externalAssetDependency2[0]).to.equal("");
        expect(externalAssetDependency2[1]).to.equal(2);
        expect(externalAssetDependency2[2]).to.not.equal(
          constants.ZERO_ADDRESS
        );
        expect(externalAssetDependency2[3]).to.equal(dataString);

        // validate updating an on-chain asset with another on-chain asset
        const externalAssetDependency2ByteCodeAddress =
          externalAssetDependency2[2];
        const dataString2 = "here is some more data2";
        // update asset info at index 0 for project 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectExternalAssetDependency(0, 0, dataString2, 2);

        const externalAssetDependency3 = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);
        expect(externalAssetDependency3[0]).to.equal("");
        expect(externalAssetDependency3[1]).to.equal(2);
        expect(externalAssetDependency3[2]).to.not.equal(
          constants.ZERO_ADDRESS
        );
        expect(externalAssetDependency3[2]).to.not.equal(
          externalAssetDependency2ByteCodeAddress
        );
        expect(externalAssetDependency3[3]).to.equal(dataString2);

        // update asset info at index 0 for project 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectExternalAssetDependency(0, 0, exampleCID, 0);
        // get asset info at index 0 for project 0
        const externalAssetDependency4 = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);
        expect(externalAssetDependency4[0]).to.equal(exampleCID);
        expect(externalAssetDependency4[1]).to.equal(0);
      });

      it("can lock a projects external asset dependencies", async function () {
        const config = await loadFixture(_beforeEach);
        // add assets for project 0 at index 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
            0
          );
        // lock external asset dependencies for project 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .lockProjectExternalAssetDependencies(0);

        // get asset info at index 0 for project 0
        const externalAssetDependency = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyByIndex(0, 0);

        expect(externalAssetDependency[0]).to.equal(
          "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo"
        );
        expect(externalAssetDependency[1]).to.equal(0);

        await expectRevert(
          config.genArt721Core
            .connect(config.accounts.artist)
            .updateProjectExternalAssetDependency(
              0,
              0,
              "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo2",
              1
            ),
          "External dependencies locked"
        );
      });

      it("can use projectExternalAssetDependencyCount getter", async function () {
        const config = await loadFixture(_beforeEach);
        const externalAssetDependencyCountA = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyCount(0);
        expect(externalAssetDependencyCountA).to.equal(0);
        // add assets for project 0 at index 0
        await config.genArt721Core
          .connect(config.accounts.artist)
          .addProjectExternalAssetDependency(
            config.projectZero,
            "QmbCdEwHebtpLZSRLGnELbJmmVVJQJPfMEVo1vq2QBEoEo",
            0
          );

        const externalAssetDependencyCountB = await config.genArt721Core
          .connect(config.accounts.artist)
          .projectExternalAssetDependencyCount(0);
        expect(externalAssetDependencyCountB).to.equal(1);
      });

      it("can update contract preferred IPFS & Arweave gateways", async function () {
        const config = await loadFixture(_beforeEach);
        // setting IPFS gateway
        await expect(
          config.genArt721Core
            .connect(config.accounts.deployer)
            .updateIPFSGateway("https://ipfs.io/ipfs/")
        )
          .to.emit(config.genArt721Core, "GatewayUpdated")
          .withArgs(0, "https://ipfs.io/ipfs/");

        // setting Arweave gateway
        await expect(
          config.genArt721Core
            .connect(config.accounts.deployer)
            .updateArweaveGateway("https://arweave.net/")
        )
          .to.emit(config.genArt721Core, "GatewayUpdated")
          .withArgs(1, "https://arweave.net/");
      });
    });
  });
}
