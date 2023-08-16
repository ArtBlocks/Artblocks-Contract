import { expectRevert } from "@openzeppelin/test-helpers";
import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { setupConfigWitMinterFilterV2Suite } from "../../../util/fixtures";
import { deployAndGet, deployCore, safeAddProject } from "../../../util/common";
import { ethers } from "hardhat";
import { revertMessages } from "../../constants";
import { ONE_MINUTE, ONE_HOUR, ONE_DAY } from "../../../util/constants";
import {
  configureProjectZeroAuction,
  configureProjectZeroAuctionAndAdvanceOneDay,
  configureProjectZeroAuctionAndAdvanceToStart,
} from "./helpers";
import { Common_Views } from "../../common.views";
import { Logger } from "@ethersproject/logger";
// hide nuisance logs about event overloading
Logger.setLogLevel(Logger.levels.ERROR);

const TARGET_MINTER_NAME = "MinterDAExpV5";
const TARGET_MINTER_VERSION = "v5.0.0";

const runForEach = [
  {
    core: "GenArt721CoreV3",
  },
  {
    core: "GenArt721CoreV3_Explorations",
  },
  {
    core: "GenArt721CoreV3_Engine",
  },
  {
    core: "GenArt721CoreV3_Engine_Flex",
  },
];

runForEach.forEach((params) => {
  describe(`${TARGET_MINTER_NAME} Views w/ core ${params.core}`, async function () {
    async function _beforeEach() {
      // load minter filter V2 fixture
      const config = await loadFixture(setupConfigWitMinterFilterV2Suite);
      // deploy core contract and register on core registry
      ({
        genArt721Core: config.genArt721Core,
        randomizer: config.randomizer,
        adminACL: config.adminACL,
      } = await deployCore(config, params.core, config.coreRegistry));

      // update core's minter as the minter filter
      await config.genArt721Core.updateMinterContract(
        config.minterFilter.address
      );

      config.minter = await deployAndGet(config, TARGET_MINTER_NAME, [
        config.minterFilter.address,
      ]);
      await config.minterFilter
        .connect(config.accounts.deployer)
        .approveMinterGlobally(config.minter.address);

      // Project setup
      await safeAddProject(
        config.genArt721Core,
        config.accounts.deployer,
        config.accounts.artist.address
      );
      await safeAddProject(
        config.genArt721Core,
        config.accounts.deployer,
        config.accounts.artist.address
      );
      await config.minterFilter
        .connect(config.accounts.deployer)
        .setMinterForProject(
          config.projectZero,
          config.genArt721Core.address,
          config.minter.address
        );

      const blockNumber = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNumber);
      config.startTime = block.timestamp + ONE_MINUTE;
      config.defaultHalfLife = 60; // seconds
      config.basePrice = config.pricePerTokenInWei;
      config.startingPrice = config.basePrice.mul(5);

      // some tests assume project one to be "configured"
      await config.minter
        .connect(config.accounts.artist)
        .setAuctionDetails(
          config.projectOne,
          config.genArt721Core.address,
          config.startTime,
          config.defaultHalfLife,
          config.startingPrice,
          config.basePrice
        );

      config.isEngine = params.core.includes("Engine");

      return config;
    }

    describe("Common Minter Views Tests", async function () {
      await Common_Views(_beforeEach);
    });

    describe("projectMaxHasBeenInvoked", async function () {
      it("should return true if project has been minted out", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndAdvanceToStart(config);
        await config.minter
          .connect(config.accounts.artist)
          .manuallyLimitProjectMaxInvocations(
            config.projectZero,
            config.genArt721Core.address,
            1
          );
        await config.minter
          .connect(config.accounts.artist)
          .purchase(config.projectZero, config.genArt721Core.address, {
            value: config.startingPrice,
          });
        let result = await config.minter.projectMaxHasBeenInvoked(
          config.projectZero,
          config.genArt721Core.address
        );
        expect(result).to.equal(true);
      });
    });

    describe("isEngineView", async function () {
      it("uses cached value when available", async function () {
        const config = await loadFixture(_beforeEach);

        // purchase token to trigger isEngine caching
        await configureProjectZeroAuctionAndAdvanceToStart(config);
        await config.minter
          .connect(config.accounts.artist)
          .purchase(config.projectZero, config.genArt721Core.address, {
            value: config.startingPrice,
          });

        const isEngineView = await config.minter
          .connect(config.accounts.artist)
          .isEngineView(config.genArt721Core.address);
        expect(isEngineView).to.be.equal(config.isEngine);
      });
    });

    describe("minterVersion", async function () {
      it("correctly reports minterVersion", async function () {
        const config = await loadFixture(_beforeEach);
        const minterVersion = await config.minter.minterVersion();
        expect(minterVersion).to.equal(TARGET_MINTER_VERSION);
      });
    });

    describe("minterType", async function () {
      it("correctly reports minterType", async function () {
        const config = await loadFixture(_beforeEach);
        const minterType = await config.minter.minterType();
        expect(minterType).to.equal(TARGET_MINTER_NAME);
      });
    });

    describe("getPriceInfo", async function () {
      it("returns correct price of zero when unconfigured auction", async function () {
        const config = await loadFixture(_beforeEach);
        const priceInfo = await config.minter.getPriceInfo(
          config.projectZero,
          config.genArt721Core.address
        );
        expect(priceInfo.isConfigured).to.equal(false);
        expect(priceInfo.tokenPriceInWei).to.equal(0);
      });

      it("returns correct price mid-auction", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndAdvanceToStart(config);
        let priceInfo = await config.minter.getPriceInfo(
          config.projectZero,
          config.genArt721Core.address
        );
        expect(priceInfo.isConfigured).to.equal(true);
        expect(priceInfo.tokenPriceInWei).to.equal(config.startingPrice);
        // advance exactly one half life and check that price is halved
        await ethers.provider.send("evm_mine", [
          config.startTime + config.defaultHalfLife,
        ]);
        priceInfo = await config.minter.getPriceInfo(
          config.projectZero,
          config.genArt721Core.address
        );
        const targetPriceAfterOneHalfLife = config.startingPrice.div(2);
        expect(priceInfo.isConfigured).to.equal(true);
        expect(priceInfo.tokenPriceInWei).to.equal(targetPriceAfterOneHalfLife);
        // advance exactly 1.5 half lives, and check that price is down another 25%
        // @dev this ensures that between half life points, the price is decaying linearly as expected
        await ethers.provider.send("evm_mine", [
          config.startTime + config.defaultHalfLife * 1.5,
        ]);
        priceInfo = await config.minter.getPriceInfo(
          config.projectZero,
          config.genArt721Core.address
        );
        const targetPriceAfterOneAndAHalfHalfLives = targetPriceAfterOneHalfLife
          .mul(3)
          .div(4);
        expect(priceInfo.isConfigured).to.equal(true);
        expect(priceInfo.tokenPriceInWei).to.equal(
          targetPriceAfterOneAndAHalfHalfLives
        );
        // advance exactly 2 half lives, and check that price is down to 1/4 of starting price
        await ethers.provider.send("evm_mine", [
          config.startTime + config.defaultHalfLife * 2,
        ]);
        priceInfo = await config.minter.getPriceInfo(
          config.projectZero,
          config.genArt721Core.address
        );
        const targetPriceAfterTwoHalfLives = config.startingPrice.div(4);
        expect(priceInfo.isConfigured).to.equal(true);
        expect(priceInfo.tokenPriceInWei).to.equal(
          targetPriceAfterTwoHalfLives
        );
      });

      it("returns correct price after auction", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndAdvanceOneDay(config);
        const priceInfo = await config.minter.getPriceInfo(
          config.projectZero,
          config.genArt721Core.address
        );
        expect(priceInfo.isConfigured).to.equal(true);
        expect(priceInfo.tokenPriceInWei).to.equal(config.basePrice);
      });
    });

    describe("minimumPriceDecayHalfLifeSeconds", async function () {
      it("returns correct initial value", async function () {
        const config = await loadFixture(_beforeEach);
        const minimumPriceDecayHalfLifeSeconds =
          await config.minter.minimumPriceDecayHalfLifeSeconds();
        expect(minimumPriceDecayHalfLifeSeconds).to.equal(45);
      });
    });

    describe("projectAuctionParameters", async function () {
      it("returns correct unconfigured values", async function () {
        const config = await loadFixture(_beforeEach);
        const projectAuctionParameters =
          await config.minter.projectAuctionParameters(
            config.projectZero,
            config.genArt721Core.address
          );
        expect(projectAuctionParameters.timestampStart).to.equal(0);
        expect(projectAuctionParameters.priceDecayHalfLifeSeconds).to.equal(0);
        expect(projectAuctionParameters.startPrice.toString()).to.equal("0");
        expect(projectAuctionParameters.basePrice.toString()).to.equal("0");
      });

      it("returns correct configured values", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuction(config);
        const projectAuctionParameters =
          await config.minter.projectAuctionParameters(
            config.projectZero,
            config.genArt721Core.address
          );
        expect(projectAuctionParameters.timestampStart).to.equal(
          config.startTime
        );
        expect(projectAuctionParameters.priceDecayHalfLifeSeconds).to.equal(
          config.defaultHalfLife
        );
        expect(projectAuctionParameters.startPrice).to.equal(
          config.startingPrice
        );
        expect(projectAuctionParameters.basePrice).to.equal(config.basePrice);
      });
    });
  });
});
