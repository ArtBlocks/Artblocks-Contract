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

import { GenArt721MinterV1V2_Common } from "./GenArt721CoreV1V2.common";
/**
 * These tests are intended to check integration of the MinterFilter suite with
 * the V2 PRTNR core contract.
 * Some basic core tests, and basic functional tests to ensure purchase
 * does in fact mint tokens to purchaser.
 */
describe("GenArt721CoreV2_PRTNR_Integration", async function () {
  const projectZero = 0;
  // common tests
  GenArt721MinterV1V2_Common(
    "GenArt721CoreV2_PRTNR",
    "MinterFilterV0",
    "MinterSetPriceV1",
    projectZero
  );
  // additional tests
  const name = "Non Fungible Token";
  const symbol = "NFT";

  const firstTokenId = new BN(projectZero.toString()).mul(new BN("1000000"));

  const pricePerTokenInWei = ethers.utils.parseEther("1");
  const maxInvocations = 15;

  beforeEach(async function () {
    const [owner, newOwner, artist, additional, deployer] =
      await ethers.getSigners();
    this.accounts = {
      owner: owner,
      newOwner: newOwner,
      artist: artist,
      additional: additional,
      deployer: deployer,
    };
    const randomizerFactory = await ethers.getContractFactory(
      "BasicRandomizer"
    );
    this.randomizer = await randomizerFactory.deploy();
    const coreFactory = await ethers.getContractFactory(
      "GenArt721CoreV2_PRTNR"
    );
    this.token = await coreFactory
      .connect(deployer)
      .deploy(name, symbol, this.randomizer.address);
    // deploy and configure minter filter and minter
    const minterFilterFactory = await ethers.getContractFactory(
      "MinterFilterV0"
    );
    this.minterFilter = await minterFilterFactory.deploy(this.token.address);
    const minterFactory = await ethers.getContractFactory("MinterSetPriceV1");
    this.minter = await minterFactory.deploy(
      this.token.address,
      this.minterFilter.address
    );
    await this.minterFilter
      .connect(deployer)
      .addApprovedMinter(this.minter.address);
    await this.token
      .connect(deployer)
      .addMintWhitelisted(this.minterFilter.address);
    // add project
    await this.token.connect(deployer).addProject("name", artist.address, 0);
    await this.token.connect(deployer).toggleProjectIsActive(projectZero);
    await this.token
      .connect(artist)
      .updateProjectMaxInvocations(projectZero, maxInvocations);
    // set project's minter and price
    await this.minter
      .connect(artist)
      .updatePricePerTokenInWei(projectZero, pricePerTokenInWei);
    await this.minterFilter
      .connect(artist)
      .setMinterForProject(projectZero, this.minter.address);
    // get project's info
    this.projectZeroInfo = await this.token.projectTokenInfo(projectZero);
  });

  describe("purchase payments and gas", async function () {
    it("can create a token then funds distributed (no additional payee)", async function () {
      const artistBalance = await this.accounts.artist.getBalance();
      const ownerBalance = await this.accounts.owner.getBalance();
      const deployerBalance = await this.accounts.deployer.getBalance();

      this.token
        .connect(this.accounts.artist)
        .toggleProjectIsPaused(projectZero);

      // pricePerTokenInWei setup above to be 1 ETH
      await expect(
        this.minter.connect(this.accounts.owner).purchase(projectZero, {
          value: pricePerTokenInWei,
        })
      )
        .to.emit(this.token, "Transfer")
        .withArgs(
          constants.ZERO_ADDRESS,
          this.accounts.owner.address,
          firstTokenId
        );

      this.projectZeroInfo = await this.token.projectTokenInfo(projectZero);
      expect(this.projectZeroInfo.invocations).to.equal("1");
      expect(
        (await this.accounts.deployer.getBalance()).sub(deployerBalance)
      ).to.equal(ethers.utils.parseEther("0.1"));
      expect(
        (await this.accounts.artist.getBalance()).sub(artistBalance)
      ).to.equal(ethers.utils.parseEther("0.8971195"));
      expect(
        (await this.accounts.owner.getBalance()).sub(ownerBalance)
      ).to.equal(ethers.utils.parseEther("1.0216789").mul("-1")); // spent 1 ETH
    });

    it("can create a token then funds distributed (with additional payee)", async function () {
      const additionalBalance = await this.accounts.additional.getBalance();
      const artistBalance = await this.accounts.artist.getBalance();
      const ownerBalance = await this.accounts.owner.getBalance();
      const deployerBalance = await this.accounts.deployer.getBalance();

      const additionalPayeePercentage = 10;
      this.token
        .connect(this.accounts.artist)
        .updateProjectAdditionalPayeeInfo(
          projectZero,
          this.accounts.additional.address,
          additionalPayeePercentage
        );
      this.token
        .connect(this.accounts.artist)
        .toggleProjectIsPaused(projectZero);

      // pricePerTokenInWei setup above to be 1 ETH
      await expect(
        this.minter.connect(this.accounts.owner).purchase(projectZero, {
          value: pricePerTokenInWei,
        })
      )
        .to.emit(this.token, "Transfer")
        .withArgs(
          constants.ZERO_ADDRESS,
          this.accounts.owner.address,
          firstTokenId
        );

      this.projectZeroInfo = await this.token.projectTokenInfo(projectZero);
      expect(this.projectZeroInfo.invocations).to.equal("1");

      expect(
        (await this.accounts.deployer.getBalance()).sub(deployerBalance)
      ).to.equal(ethers.utils.parseEther("0.1"));
      expect(
        (await this.accounts.additional.getBalance()).sub(additionalBalance)
      ).to.equal(ethers.utils.parseEther("0.09"));
      expect(
        (await this.accounts.owner.getBalance()).sub(ownerBalance)
      ).to.equal(ethers.utils.parseEther("1.0230737").mul("-1")); // spent 1 ETH
      expect(
        (await this.accounts.artist.getBalance()).sub(artistBalance)
      ).to.equal(ethers.utils.parseEther("0.8002442"));
    });

    it("can create a token then funds distributed (with additional payee getting 100%)", async function () {
      const additionalBalance = await this.accounts.additional.getBalance();
      const artistBalance = await this.accounts.artist.getBalance();
      const ownerBalance = await this.accounts.owner.getBalance();
      const deployerBalance = await this.accounts.deployer.getBalance();

      const additionalPayeePercentage = 100;
      this.token
        .connect(this.accounts.artist)
        .updateProjectAdditionalPayeeInfo(
          projectZero,
          this.accounts.additional.address,
          additionalPayeePercentage
        );
      this.token
        .connect(this.accounts.artist)
        .toggleProjectIsPaused(projectZero);

      // pricePerTokenInWei setup above to be 1 ETH
      await expect(
        this.minter.connect(this.accounts.owner).purchase(projectZero, {
          value: pricePerTokenInWei,
        })
      )
        .to.emit(this.token, "Transfer")
        .withArgs(
          constants.ZERO_ADDRESS,
          this.accounts.owner.address,
          firstTokenId
        );

      this.projectZeroInfo = await this.token.projectTokenInfo(projectZero);
      expect(this.projectZeroInfo.invocations).to.equal("1");

      expect(
        (await this.accounts.deployer.getBalance()).sub(deployerBalance)
      ).to.equal(ethers.utils.parseEther("0.1"));
      expect(
        (await this.accounts.additional.getBalance()).sub(additionalBalance)
      ).to.equal(ethers.utils.parseEther("0.9"));
      expect(
        (await this.accounts.owner.getBalance()).sub(ownerBalance)
      ).to.equal(ethers.utils.parseEther("1.0218145").mul("-1")); // spent 1 ETH
      expect(
        (await this.accounts.artist.getBalance()).sub(artistBalance)
      ).to.equal(ethers.utils.parseEther("0.0097558").mul("-1"));
    });
  });
});
