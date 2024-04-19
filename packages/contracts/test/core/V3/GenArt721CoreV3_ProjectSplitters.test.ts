import { constants, expectRevert } from "@openzeppelin/test-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

import {
  T_Config,
  getAccounts,
  assignDefaultConstants,
  deployAndGet,
  deployCoreWithMinterFilter,
  mintProjectUntilRemaining,
  advanceEVMByTime,
  deployWithStorageLibraryAndGet,
  GENART721_ERROR_NAME,
  GENART721_ERROR_CODES,
} from "../../util/common";
import { FOUR_WEEKS } from "../../util/constants";
import {
  SQUIGGLE_SCRIPT,
  SKULPTUUR_SCRIPT_APPROX,
  CONTRACT_SIZE_LIMIT_SCRIPT,
  GREATER_THAN_CONTRACT_SIZE_LIMIT_SCRIPT,
  MULTI_BYTE_UTF_EIGHT_SCRIPT,
  MUCH_GREATER_THAN_CONTRACT_SIZE_LIMIT_SCRIPT,
} from "../../util/example-scripts";

import {
  Mock0xSplitsV2Splitter,
  Mock0xSplitsV2Splitter__factory,
} from "../../../scripts/contracts";

// test the following V3 core contract derivatives:
const coreContractsToTest = [
  "GenArt721CoreV3_Engine", // V3 core Engine contract
  "GenArt721CoreV3_Engine_Flex", // V3 core Engine Flex contract
];

/**
 * Tests for V3 core dealing with configuring projects.
 */
for (const coreContractName of coreContractsToTest) {
  describe(`${coreContractName} Project Configure`, async function () {
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

      // add project zero
      await config.genArt721Core
        .connect(config.accounts.deployer)
        .addProject("name", config.accounts.artist.address);
      await config.genArt721Core
        .connect(config.accounts.deployer)
        .toggleProjectIsActive(config.projectZero);
      await config.genArt721Core
        .connect(config.accounts.artist)
        .updateProjectMaxInvocations(config.projectZero, config.maxInvocations);

      // add project one without setting it to active or setting max invocations
      await config.genArt721Core
        .connect(config.accounts.deployer)
        .addProject("name", config.accounts.artist2.address);

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

    describe("splitter is created with appropriate splits", function () {
      it("should create a splitter with the correct splits", async function () {
        const config = await _beforeEach();
        // project zero should already have a splitter
        const projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const splitterContractAddress = projectFinance.royaltySplitter;
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          splitterContractAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist.address,
          config.accounts.deployer.address,
          config.accounts.additional.address, // additional is default platform fee recipient
        ]);
        expect(splits.allocations).to.deep.equal([500, 250, 250]);
        expect(splits.totalAllocation).to.equal(1000);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("should reflect updates to every field to a new splitter with the correct splits", async function () {
        const config = await _beforeEach();
        // update artist royalty split info
        // 10% total artist royalty
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectSecondaryMarketRoyaltyPercentage(
            config.projectZero,
            10
          );
        // add additional payee receiving 40% of total artist royalty
        const paymentArgs = [
          config.projectZero,
          config.accounts.artist.address,
          constants.ZERO_ADDRESS, // primary
          0, // primary additional percentage
          config.accounts.additional2.address, // secondary
          40, // secondary additional percentage
        ];
        await config.genArt721Core
          .connect(config.accounts.artist)
          .proposeArtistPaymentAddressesAndSplits(...paymentArgs);
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .adminAcceptArtistAddressesAndSplits(...paymentArgs);
        // update provider fees and recipients
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSecondarySalesBPS(
            200, // render secondary of 2%
            300 // platform provider secondary of 3%
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSalesAddresses(
            config.accounts.deployer.address, // render primary (unused here)
            config.accounts.user.address, // render secondary
            config.accounts.additional.address, // platform provider primary (unused here)
            config.accounts.user2.address // platform provider secondary
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .syncProviderSecondaryForProjectToDefaults(config.projectZero);
        // project zero should already have had new splitter deployed, so get
        const projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const splitterContractAddress = projectFinance.royaltySplitter;
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          splitterContractAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist.address,
          config.accounts.additional2.address, // additional2 is artist's new secondary recipient
          config.accounts.user.address, // render provider is now user address
          config.accounts.user2.address, // platform provider is now user2 address
        ]);
        expect(splits.allocations).to.deep.equal([600, 400, 200, 300]);
        expect(splits.totalAllocation).to.equal(1500);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("should handle a single payment address with a splitter still", async function () {
        const config = await _beforeEach();
        // update artist royalty split info
        // 1% total artist royalty
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectSecondaryMarketRoyaltyPercentage(config.projectZero, 1);
        // add additional payee receiving 40% of total artist royalty
        const paymentArgs = [
          config.projectZero,
          config.accounts.artist.address,
          constants.ZERO_ADDRESS, // primary
          0, // primary additional percentage
          config.accounts.additional2.address, // secondary
          100, // secondary additional percentage
        ];
        await config.genArt721Core
          .connect(config.accounts.artist)
          .proposeArtistPaymentAddressesAndSplits(...paymentArgs);
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .adminAcceptArtistAddressesAndSplits(...paymentArgs);
        // update provider fees and recipients
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSecondarySalesBPS(
            0, // render secondary of 0%
            0 // platform provider secondary of 0%
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .syncProviderSecondaryForProjectToDefaults(config.projectZero);
        // project zero should already have had new splitter deployed, so get
        const projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const splitterContractAddress = projectFinance.royaltySplitter;
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          splitterContractAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.additional2.address, // additional2 is artist's new secondary recipient
        ]);
        expect(splits.allocations).to.deep.equal([100]);
        expect(splits.totalAllocation).to.equal(100);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("should handle entirely null secondary royalties", async function () {
        const config = await _beforeEach();
        // update artist royalty split info
        // 0% total artist royalty
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectSecondaryMarketRoyaltyPercentage(config.projectZero, 0);
        // add additional payee receiving 40% of total artist royalty
        const paymentArgs = [
          config.projectZero,
          config.accounts.artist.address,
          constants.ZERO_ADDRESS, // primary
          0, // primary additional percentage
          config.accounts.additional2.address, // secondary
          40, // secondary additional percentage
        ];
        await config.genArt721Core
          .connect(config.accounts.artist)
          .proposeArtistPaymentAddressesAndSplits(...paymentArgs);
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .adminAcceptArtistAddressesAndSplits(...paymentArgs);
        // update provider fees and recipients
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSecondarySalesBPS(
            0, // render secondary of 0%
            0 // platform provider secondary of 0%
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSalesAddresses(
            config.accounts.deployer.address, // render primary (unused here)
            config.accounts.user.address, // render secondary
            config.accounts.additional.address, // platform provider primary (unused here)
            config.accounts.user2.address // platform provider secondary
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .syncProviderSecondaryForProjectToDefaults(config.projectZero);
        // project zero should already have had new splitter deployed, so get
        const projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const splitterContractAddress = projectFinance.royaltySplitter;
        expect(splitterContractAddress).to.equal(constants.ZERO_ADDRESS);
      });
    });

    // this section checks that the core contract is asking the split provider
    // to update the splitter when relevant fields are updated
    describe("splitter is updated after relevant updates", function () {
      it("updates splitter upon project creation", async function () {
        const config = await _beforeEach();
        // project one should not have a splitter yet
        const projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectTwo
        );
        expect(projectFinance.royaltySplitter).to.equal(constants.ZERO_ADDRESS);
        // add project two
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .addProject("name", config.accounts.artist2.address);
        // project one should now have a splitter
        const projectFinance2 =
          await config.genArt721Core.projectIdToFinancials(config.projectTwo);
        const splitterContractAddress = projectFinance2.royaltySplitter;
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          splitterContractAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist2.address,
          config.accounts.deployer.address,
          config.accounts.additional.address, // additional is default platform fee recipient
        ]);
        expect(splits.allocations).to.deep.equal([500, 250, 250]);
        expect(splits.totalAllocation).to.equal(1000);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("updates splitter upon auto-approval in proposeArtistPaymentAddressesAndSplits", async function () {
        // deploy new core with auto-approve set to true
        let config = await _beforeEach();

        const differentGenArt721Core = await deployWithStorageLibraryAndGet(
          config,
          coreContractName,
          [
            config.name,
            config.symbol,
            config.accounts.deployer.address,
            config.accounts.additional.address,
            config.randomizer.address,
            config.adminACL.address,
            0, // next project ID
            true, // auto-approve
            config.splitProvider.address,
          ]
        );

        // add project one
        await differentGenArt721Core
          .connect(config.accounts.deployer)
          .addProject("name", config.accounts.artist.address);
        // get current project zero splitter
        let projectFinance = await differentGenArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // update artist payment info for project zero, auto-approved
        const paymentArgs = [
          config.projectZero,
          config.accounts.artist.address,
          constants.ZERO_ADDRESS, // primary
          0, // primary additional percentage
          config.accounts.additional2.address, // secondary
          50, // secondary additional percentage
        ];
        await differentGenArt721Core
          .connect(config.accounts.artist)
          .proposeArtistPaymentAddressesAndSplits(...paymentArgs);
        // get updated project zero splitter (since auto-approved should be true)
        projectFinance = await differentGenArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const updatedSplitterAddress = projectFinance.royaltySplitter;
        expect(updatedSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        expect(updatedSplitterAddress).to.not.equal(initialSplitterAddress);
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          updatedSplitterAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist.address,
          config.accounts.additional2.address, // additional2 is artist's new secondary recipient
          config.accounts.deployer.address,
          config.accounts.additional.address, // additional is default platform fee recipient
        ]);
        expect(splits.allocations).to.deep.equal([250, 250, 250, 250]);
        expect(splits.totalAllocation).to.equal(1000);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("updates splitter upon admin approval in proposeArtistPaymentAddressesAndSplits", async function () {
        const config = await _beforeEach();
        // update artist payment info for project zero, not auto-approved
        const paymentArgs = [
          config.projectZero,
          config.accounts.artist.address,
          constants.ZERO_ADDRESS, // primary
          0, // primary additional percentage
          config.accounts.additional2.address, // secondary
          50, // secondary additional percentage
        ];
        await config.genArt721Core
          .connect(config.accounts.artist)
          .proposeArtistPaymentAddressesAndSplits(...paymentArgs);
        // get current project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // admin approve artist payment info for project zero
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .adminAcceptArtistAddressesAndSplits(...paymentArgs);
        // get updated project zero splitter
        projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const updatedSplitterAddress = projectFinance.royaltySplitter;
        expect(updatedSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        expect(updatedSplitterAddress).to.not.equal(initialSplitterAddress);
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          updatedSplitterAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist.address,
          config.accounts.additional2.address, // additional2 is artist's new secondary recipient
          config.accounts.deployer.address,
          config.accounts.additional.address, // additional is default platform fee recipient
        ]);
        expect(splits.allocations).to.deep.equal([250, 250, 250, 250]);
        expect(splits.totalAllocation).to.equal(1000);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("updates splitter upon updateProjectArtistAddress", async function () {
        const config = await _beforeEach();
        // get current project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // update artist address for project zero
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProjectArtistAddress(
            config.projectZero,
            config.accounts.artist2.address
          );
        // get updated project zero splitter
        projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const updatedSplitterAddress = projectFinance.royaltySplitter;
        expect(updatedSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        expect(updatedSplitterAddress).to.not.equal(initialSplitterAddress);
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          updatedSplitterAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist2.address, // updated artist address
          config.accounts.deployer.address,
          config.accounts.additional.address, // additional is default platform fee recipient
        ]);
        expect(splits.allocations).to.deep.equal([500, 250, 250]);
        expect(splits.totalAllocation).to.equal(1000);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("updates splitter upon updateProjectSecondaryMarketRoyaltyPercentage", async function () {
        const config = await _beforeEach();
        // get current project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // update artist royalty split info
        // 10% total artist royalty
        await config.genArt721Core
          .connect(config.accounts.artist)
          .updateProjectSecondaryMarketRoyaltyPercentage(
            config.projectZero,
            10
          );
        // get updated project zero splitter
        projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const updatedSplitterAddress = projectFinance.royaltySplitter;
        expect(updatedSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        expect(updatedSplitterAddress).to.not.equal(initialSplitterAddress);
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          updatedSplitterAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist.address,
          config.accounts.deployer.address,
          config.accounts.additional.address, // additional is default platform fee recipient
        ]);
        expect(splits.allocations).to.deep.equal([1000, 250, 250]);
        expect(splits.totalAllocation).to.equal(1500);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("updates splitter upon syncProviderSecondaryForProjectToDefaults", async function () {
        const config = await _beforeEach();
        // get current project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // update provider fees and recipients
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSecondarySalesBPS(
            200, // render secondary of 2%
            300 // platform provider secondary of 3%
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProviderSalesAddresses(
            config.accounts.deployer.address, // render primary (unused here)
            config.accounts.user.address, // render secondary
            config.accounts.additional.address, // platform provider primary (unused here)
            config.accounts.user2.address // platform provider secondary
          );
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .syncProviderSecondaryForProjectToDefaults(config.projectZero);
        // get updated project zero splitter
        projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const updatedSplitterAddress = projectFinance.royaltySplitter;
        expect(updatedSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        expect(updatedSplitterAddress).to.not.equal(initialSplitterAddress);
        // call the splitter contract to get the splits
        const splitter = (await ethers.getContractAt(
          "Mock0xSplitsV2Splitter",
          updatedSplitterAddress
        )) as Mock0xSplitsV2Splitter;
        const splits = await splitter.getSplitParams();
        expect(splits.recipients).to.deep.equal([
          config.accounts.artist.address,
          config.accounts.user.address, // render provider is now user address
          config.accounts.user2.address, // platform provider is now user2 address
        ]);
        expect(splits.allocations).to.deep.equal([500, 200, 300]);
        expect(splits.totalAllocation).to.equal(1000);
        expect(splits.distributionIncentive).to.equal(0);
        const owner = await splitter.getOwner();
        expect(owner).to.equal(constants.ZERO_ADDRESS);
      });

      it("does not update splitter when proposal is not auto-approved", async function () {
        const config = await _beforeEach();
        // get current project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // update artist payment info for project zero, not auto-approved
        const paymentArgs = [
          config.projectZero,
          config.accounts.artist.address,
          constants.ZERO_ADDRESS, // primary
          0, // primary additional percentage
          config.accounts.additional2.address, // secondary
          50, // secondary additional percentage
        ];
        await config.genArt721Core
          .connect(config.accounts.artist)
          .proposeArtistPaymentAddressesAndSplits(...paymentArgs);
        // get new project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const newSplitterAddress = projectFinance.royaltySplitter;
        // splitter should not have changed
        expect(newSplitterAddress).to.equal(initialSplitterAddress);
      });
    });

    describe("splitter is not updated when values are unchanged, because deterministic", function () {
      it("updates splitter upon updateProjectArtistAddress", async function () {
        const config = await _beforeEach();
        // get current project zero splitter
        let projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const initialSplitterAddress = projectFinance.royaltySplitter;
        expect(initialSplitterAddress).to.not.equal(constants.ZERO_ADDRESS);
        // update artist address for project zero, but to the same address
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProjectArtistAddress(
            config.projectZero,
            config.accounts.artist.address
          );
        // get updated project zero splitter
        projectFinance = await config.genArt721Core.projectIdToFinancials(
          config.projectZero
        );
        const updatedSplitterAddress = projectFinance.royaltySplitter;
        // address should be unchanged because it is deterministic based on split parameters and core contract
        expect(updatedSplitterAddress).to.equal(initialSplitterAddress);
      });
    });
  });
}
