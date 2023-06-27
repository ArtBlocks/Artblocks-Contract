import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { T_Config } from "../util/common";

/**
 * These tests are intended to check common events Minter functionality
 * for minters in our minter suite.
 * @dev assumes common BeforeEach to populate accounts, constants, and setup
 */
export const Common_Events = async (_beforeEach: () => Promise<T_Config>) => {
  describe("manuallyLimitProjectMaxInvocations", async function () {
    it("emits event upon manual limit", async function () {
      const config = await loadFixture(_beforeEach);
      // artist manually limits
      await expect(
        config.minter
          .connect(config.accounts.artist)
          .manuallyLimitProjectMaxInvocations(
            config.projectZero,
            config.genArt721Core.address,
            config.maxInvocations
          )
      )
        .to.emit(config.minter, "ProjectMaxInvocationsLimitUpdated")
        .withArgs(
          config.projectZero,
          config.genArt721Core.address,
          config.maxInvocations
        );
    });

    it("emits event upon sync", async function () {
      const config = await loadFixture(_beforeEach);
      // artist manually limits
      await expect(
        config.minter
          .connect(config.accounts.artist)
          .syncProjectMaxInvocationsToCore(
            config.projectZero,
            config.genArt721Core.address
          )
      )
        .to.emit(config.minter, "ProjectMaxInvocationsLimitUpdated")
        .withArgs(
          config.projectZero,
          config.genArt721Core.address,
          config.maxInvocations
        );
    });
  });
};
