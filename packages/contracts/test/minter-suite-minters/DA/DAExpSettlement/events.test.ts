import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { setupConfigWitMinterFilterV2Suite } from "../../../util/fixtures";
import { deployAndGet, deployCore, safeAddProject } from "../../../util/common";
import { ethers } from "hardhat";
import { AbiCoder } from "ethers/lib/utils";
import { ONE_MINUTE } from "../../../util/constants";
import {
  configureProjectZeroAuction,
  configureProjectZeroAuctionAndAdvanceOneDayAndWithdrawRevenues,
  configureProjectZeroAuctionAndAdvanceToStart,
  configureProjectZeroAuctionAndSellout,
  configureProjectOneOnNewCoreAndSellout,
} from "./helpers";
import { Common_Events } from "../../common.events";
import { Logger } from "@ethersproject/logger";
// hide nuisance logs about event overloading
Logger.setLogLevel(Logger.levels.ERROR);

const TARGET_MINTER_NAME = "MinterDAExpSettlementV3";
const TARGET_MINTER_VERSION = "v3.0.0";

const runForEach = [
  {
    core: "GenArt721CoreV3",
  },
  // {
  //   core: "GenArt721CoreV3_Explorations",
  // },
  // {
  //   core: "GenArt721CoreV3_Engine",
  // },
  // {
  //   core: "GenArt721CoreV3_Engine_Flex",
  // },
];

runForEach.forEach((params) => {
  describe(`${TARGET_MINTER_NAME} Events w/ core ${params.core}`, async function () {
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

      config.higherPricePerTokenInWei = config.pricePerTokenInWei.add(
        ethers.utils.parseEther("0.1")
      );

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

      await config.genArt721Core
        .connect(config.accounts.deployer)
        .toggleProjectIsActive(config.projectZero);
      await config.genArt721Core
        .connect(config.accounts.deployer)
        .toggleProjectIsActive(config.projectOne);

      await config.genArt721Core
        .connect(config.accounts.artist)
        .toggleProjectIsPaused(config.projectZero);
      await config.genArt721Core
        .connect(config.accounts.artist)
        .toggleProjectIsPaused(config.projectOne);

      await config.minterFilter
        .connect(config.accounts.deployer)
        .setMinterForProject(
          config.projectZero,
          config.genArt721Core.address,
          config.minter.address
        );
      await config.minterFilter
        .connect(config.accounts.deployer)
        .setMinterForProject(
          config.projectOne,
          config.genArt721Core.address,
          config.minter.address
        );

      await config.genArt721Core
        .connect(config.accounts.artist)
        .updateProjectMaxInvocations(config.projectZero, config.maxInvocations);
      await config.genArt721Core
        .connect(config.accounts.artist)
        .updateProjectMaxInvocations(config.projectOne, config.maxInvocations);

      const blockNumber = await ethers.provider.getBlockNumber();
      const block = await ethers.provider.getBlock(blockNumber);
      config.startTime = block.timestamp + ONE_MINUTE;
      config.defaultHalfLife = 60; // seconds
      config.basePrice = config.pricePerTokenInWei;
      config.startingPrice = config.basePrice.mul(5);

      return config;
    }

    describe("Common Minter Events Tests", async function () {
      await Common_Events(_beforeEach);
    });

    describe("AuctionMinHalfLifeSecondsUpdated", async function () {
      it("emits during deploy", async function () {
        const config = await loadFixture(_beforeEach);
        const contractFactory = await ethers.getContractFactory(
          TARGET_MINTER_NAME
        );
        const tx = await contractFactory.deploy(config.minterFilter.address);
        const receipt = await tx.deployTransaction.wait();
        // target event "AuctionMinHalfLifeSecondsUpdated" is the log at index 0
        let targetLog = receipt.logs[0];
        // expect log 0 to be AuctionMinHalfLifeSecondsUpdated
        expect(targetLog.topics[0]).to.be.equal(
          ethers.utils.keccak256(
            ethers.utils.toUtf8Bytes(
              "AuctionMinHalfLifeSecondsUpdated(uint256)"
            )
          )
        );
        // expect field to be the hard-coded default value
        const abiCoder = new AbiCoder();
        expect(targetLog.data).to.be.equal(abiCoder.encode(["uint256"], [45]));
      });

      it("emits when being configured", async function () {
        const config = await loadFixture(_beforeEach);
        await expect(
          config.minter
            .connect(config.accounts.deployer)
            .setMinimumPriceDecayHalfLifeSeconds(1)
        )
          .to.emit(config.minter, "AuctionMinHalfLifeSecondsUpdated")
          .withArgs(1);
      });
    });

    describe("SetAuctionDetailsExp", async function () {
      it("emits when auction is configured", async function () {
        const config = await loadFixture(_beforeEach);
        await expect(
          config.minter
            .connect(config.accounts.artist)
            .setAuctionDetails(
              config.projectZero,
              config.genArt721Core.address,
              config.startTime,
              config.defaultHalfLife,
              config.startingPrice,
              config.basePrice
            )
        )
          .to.emit(config.minter, "SetAuctionDetailsExp")
          .withArgs(
            config.projectZero,
            config.genArt721Core.address,
            config.startTime,
            config.defaultHalfLife,
            config.startingPrice,
            config.basePrice
          );
      });
    });

    describe("ResetAuctionDetails", async function () {
      it("emits when auction is reset", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuction(config);
        await expect(
          config.minter
            .connect(config.accounts.deployer)
            .resetAuctionDetails(
              config.projectZero,
              config.genArt721Core.address
            )
        )
          .to.emit(config.minter, "ResetAuctionDetails")
          .withArgs(config.projectZero, config.genArt721Core.address);
      });
    });

    describe("Generic: SelloutPriceUpdated", async function () {
      it("emits when admin emergency updates sellout price", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndSellout(config);
        // expect no revert
        // @dev target a unique sellout price value
        const targetNewSelloutPrice = config.basePrice.add(1);
        await expect(
          config.minter
            .connect(config.accounts.deployer)
            .adminEmergencyReduceSelloutPrice(
              config.projectZero,
              config.genArt721Core.address,
              targetNewSelloutPrice
            )
        )
          .to.emit(config.minter, "ConfigValueSet")
          .withArgs(
            config.projectZero,
            config.genArt721Core.address,
            ethers.utils.formatBytes32String("currentSettledPrice"),
            targetNewSelloutPrice
          );
      });
    });

    describe("Generic: ArtistAndAdminRevenuesWithdrawn", async function () {
      it("emits when artist and admin revenues are withdrawn", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndSellout(config);
        // expect no revert
        await expect(
          config.minter
            .connect(config.accounts.artist)
            .withdrawArtistAndAdminRevenues(
              config.projectZero,
              config.genArt721Core.address
            )
        )
          .to.emit(config.minter, "ConfigValueSet")
          .withArgs(
            config.projectZero,
            config.genArt721Core.address,
            ethers.utils.formatBytes32String("auctionRevenuesCollected"),
            true
          );
      });
    });

    describe("ReceiptUpdated", async function () {
      it("emits during reclaimable purchases", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndAdvanceToStart(config);
        // expect purchase to emit event
        await expect(
          config.minter
            .connect(config.accounts.user)
            .purchase(config.projectZero, config.genArt721Core.address, {
              value: config.startingPrice,
            })
        )
          .to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectZero,
            config.genArt721Core.address,
            1, // one sale
            config.startingPrice // posted amount
          );
        // expect another purchase to emit event
        await expect(
          config.minter
            .connect(config.accounts.user)
            .purchase(config.projectZero, config.genArt721Core.address, {
              value: config.startingPrice,
            })
        )
          .to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectZero,
            config.genArt721Core.address,
            2, // two sales
            config.startingPrice.mul(2) // posted amount * 2
          );
      });

      it("emits during non-reclaimable purchases", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndAdvanceOneDayAndWithdrawRevenues(
          config
        );
        // expect purchase to emit event
        await expect(
          config.minter
            .connect(config.accounts.user)
            .purchase(config.projectZero, config.genArt721Core.address, {
              value: config.startingPrice,
            })
        )
          .to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectZero,
            config.genArt721Core.address,
            1, // one sale
            config.startingPrice // posted amount
          );
        // expect another purchase to emit event
        await expect(
          config.minter
            .connect(config.accounts.user)
            .purchase(config.projectZero, config.genArt721Core.address, {
              value: config.startingPrice,
            })
        )
          .to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectZero,
            config.genArt721Core.address,
            2, // two sales
            config.startingPrice.mul(2) // posted amount * 2
          );
      });

      it("emits during reclaimProjectExcessSettlementFundsTo", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndSellout(config);
        const selloutPrice = await config.minter.getProjectLatestPurchasePrice(
          config.projectZero,
          config.genArt721Core.address
        );
        // expect call to emit event
        await expect(
          config.minter
            .connect(config.accounts.user)
            .reclaimProjectExcessSettlementFundsTo(
              config.accounts.user.address,
              config.projectZero,
              config.genArt721Core.address
            )
        )
          .to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectZero,
            config.genArt721Core.address,
            1, // one sale
            selloutPrice // actual amount due (not necessarily posted amount)
          );
      });

      it("emits during reclaimProjectsExcessSettlementFundsTo (multi-project)", async function () {
        const config = await loadFixture(_beforeEach);
        await configureProjectZeroAuctionAndSellout(config);
        const selloutPrice = await config.minter.getProjectLatestPurchasePrice(
          config.projectZero,
          config.genArt721Core.address
        );
        // also deploy a second project on different core contract, and sellout
        const newCore = await configureProjectOneOnNewCoreAndSellout(config);
        const selloutPriceTwo =
          await config.minter.getProjectLatestPurchasePrice(
            config.projectOne,
            newCore.address
          );
        // expect call to emit event
        await expect(
          config.minter
            .connect(config.accounts.user)
            .reclaimProjectsExcessSettlementFundsTo(
              config.accounts.user.address,
              [config.projectZero, config.projectOne],
              [config.genArt721Core.address, newCore.address]
            )
        )
          .to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectZero,
            config.genArt721Core.address,
            1, // one sale
            selloutPrice // actual amount due (not necessarily posted amount)
          )
          .and.to.emit(config.minter, "ReceiptUpdated")
          .withArgs(
            config.accounts.user.address,
            config.projectOne,
            newCore.address,
            1, // one sale
            selloutPriceTwo // actual amount due (not necessarily posted amount)
          );
      });
    });
  });
});
