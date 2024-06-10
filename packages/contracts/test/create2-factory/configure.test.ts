import { expect } from "chai";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";
import { setupConfig } from "../util/fixtures";

import { Logger } from "@ethersproject/logger";
// hide nuisance logs about event overloading
Logger.setLogLevel(Logger.levels.ERROR);

import { T_Config } from "../util/common";
import { OwnedCreate2FactoryV0 } from "../../scripts/contracts";
import { OwnedCreate2FactoryV0__factory } from "../../scripts/contracts/factories";

interface T_Create2FactoryTestConfig extends T_Config {
  ownedCreate2Factory: OwnedCreate2FactoryV0;
}

describe(`OwnedCreate2FactoryV0 Configure`, async function () {
  async function _beforeEach() {
    const config = await loadFixture(setupConfig);
    // deploy new owned create2 factory
    const ownedCreate2FactoryFactory = new OwnedCreate2FactoryV0__factory(
      config.accounts.deployer
    );
    config.ownedCreate2Factory = await ownedCreate2FactoryFactory.deploy(
      config.accounts.deployer.address // owner
    );

    return config as T_Create2FactoryTestConfig;
  }

  describe("Deployment", async function () {
    it("sets owner in constructor", async function () {
      const config = await loadFixture(_beforeEach);
      const expectedOwner = config.accounts.deployer.address;
      const actualOwner = await config.ownedCreate2Factory.owner();
      expect(actualOwner).to.equal(expectedOwner);
    });
  });

  describe("change ownership", async function () {
    it("allows owner to transfer ownership", async function () {
      const config = await loadFixture(_beforeEach);
      await config.ownedCreate2Factory.transferOwnership(
        config.accounts.user.address
      );
      const newOwner = await config.ownedCreate2Factory.owner();
      expect(newOwner).to.equal(config.accounts.user.address);
    });
  });
});
