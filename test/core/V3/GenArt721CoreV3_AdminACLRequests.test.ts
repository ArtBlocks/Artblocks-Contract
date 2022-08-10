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

import {
  getAccounts,
  assignDefaultConstants,
  deployAndGet,
  fullyMintProject,
  advanceEVMByTime,
  deployCoreWithMinterFilter,
} from "../../util/common";
import { FOUR_WEEKS } from "../../util/constants";

async function validateAdminACLRequest(functionName: string, args: any[]) {
  const targetSelector = this.coreInterface.getSighash(functionName);
  // emits event when being minted out
  expect(
    await this.genArt721Core
      .connect(this.accounts.deployer)
      [functionName](...args)
  )
    .to.emit(this.adminACL, "ACLCheck")
    .withArgs(this.accounts.deployer.address, targetSelector);
}

/**
 * Tests for V3 core dealing with funcitons requesting proper Admin ACL while
 * authenticating caller.
 * @dev Most or all of these tests rely on our mock AdminACL contract, which
 * emits an event for debugging purposes indicating what the core contract is
 * requesting to authenticate.
 */
describe("GenArt721CoreV3 AminACL Requests", async function () {
  beforeEach(async function () {
    // standard accounts and constants
    this.accounts = await getAccounts();
    await assignDefaultConstants.call(this);

    const randomizerFactory = await ethers.getContractFactory(
      "BasicRandomizer"
    );
    this.randomizer = await randomizerFactory.deploy();
    const adminACLFactory = await ethers.getContractFactory(
      "MockAdminACLV0Events"
    );
    this.adminACL = await adminACLFactory.deploy();
    this.artblocksFactory = await ethers.getContractFactory("GenArt721CoreV3");
    this.coreInterface = this.artblocksFactory.interface;
    this.genArt721Core = await this.artblocksFactory
      .connect(this.accounts.deployer)
      .deploy(
        this.name,
        this.symbol,
        this.randomizer.address,
        this.adminACL.address
      );

    // TBD - V3 DOES NOT CURRENTLY HAVE A WORKING MINTER

    // allow artist to mint on contract
    await this.genArt721Core
      .connect(this.accounts.deployer)
      .updateMinterContract(this.accounts.artist.address);

    // add project zero
    await this.genArt721Core
      .connect(this.accounts.deployer)
      .addProject("name", this.accounts.artist.address);
    await this.genArt721Core
      .connect(this.accounts.deployer)
      .toggleProjectIsActive(this.projectZero);
    await this.genArt721Core
      .connect(this.accounts.artist)
      .updateProjectMaxInvocations(this.projectZero, this.maxInvocations);

    // add project one without setting it to active or setting max invocations
    await this.genArt721Core
      .connect(this.accounts.deployer)
      .addProject("name", this.accounts.artist2.address);
  });

  describe("requests appropriate selectors from AdminACL", function () {
    it("updateArtblocksAddress", async function () {
      await validateAdminACLRequest.call(this, "updateArtblocksAddress", [
        this.accounts.user.address,
      ]);
    });

    it("updateArtblocksPercentage", async function () {
      await validateAdminACLRequest.call(this, "updateArtblocksPercentage", [
        11,
      ]);
    });

    it("updateMinterContract", async function () {
      await validateAdminACLRequest.call(this, "updateMinterContract", [
        this.accounts.user.address,
      ]);
    });

    it("updateRandomizerAddress", async function () {
      await validateAdminACLRequest.call(this, "updateRandomizerAddress", [
        this.accounts.user.address,
      ]);
    });

    it("toggleProjectIsActive", async function () {
      await validateAdminACLRequest.call(this, "toggleProjectIsActive", [
        this.projectZero,
      ]);
    });

    it("updateProjectArtistAddress", async function () {
      await validateAdminACLRequest.call(this, "updateProjectArtistAddress", [
        this.projectZero,
        this.accounts.artist2.address,
      ]);
    });

    it("addProject", async function () {
      await validateAdminACLRequest.call(this, "addProject", [
        "Project Name",
        this.accounts.artist2.address,
      ]);
    });

    it("updateProjectName", async function () {
      await validateAdminACLRequest.call(this, "updateProjectName", [
        this.projectZero,
        "New Project Name",
      ]);
    });

    it("updateProjectArtistName", async function () {
      await validateAdminACLRequest.call(this, "updateProjectArtistName", [
        this.projectZero,
        "New Artist Name",
      ]);
    });

    it("updateProjectLicense", async function () {
      await validateAdminACLRequest.call(this, "updateProjectLicense", [
        this.projectZero,
        "New Project License",
      ]);
    });

    it("addProjectScript", async function () {
      await validateAdminACLRequest.call(this, "addProjectScript", [
        this.projectZero,
        "console.log('hello world')",
      ]);
    });

    describe("update/remove project scripts", async function () {
      beforeEach(async function () {
        // add a project to be modified
        await this.genArt721Core
          .connect(this.accounts.deployer)
          .addProjectScript(this.projectZero, "console.log('hello world')");
      });

      it("updateProjectScript", async function () {
        // update the script
        await validateAdminACLRequest.call(this, "updateProjectScript", [
          this.projectZero,
          0,
          "console.log('hello big world')",
        ]);
      });

      it("removeProjectLastScript", async function () {
        // update the script
        await validateAdminACLRequest.call(this, "removeProjectLastScript", [
          this.projectZero,
        ]);
      });
    });

    it("updateProjectScriptType", async function () {
      await validateAdminACLRequest.call(this, "updateProjectScriptType", [
        this.projectZero,
        "p5js",
        "v1.4.2",
      ]);
    });

    it("updateProjectAspectRatio", async function () {
      await validateAdminACLRequest.call(this, "updateProjectAspectRatio", [
        this.projectZero,
        "1.7777778",
      ]);
    });

    it("updateProjectIpfsHash", async function () {
      await validateAdminACLRequest.call(this, "updateProjectAspectRatio", [
        this.projectZero,
        "0x",
      ]);
    });

    it("updateProjectDescription", async function () {
      // admin may only call when in a locked state
      await fullyMintProject.call(this, this.projectZero, this.accounts.artist);
      await advanceEVMByTime(FOUR_WEEKS + 1);
      // ensure admin requests expected selector
      await validateAdminACLRequest.call(this, "updateProjectDescription", [
        this.projectZero,
        "post-locked admin description",
      ]);
    });
  });
});
