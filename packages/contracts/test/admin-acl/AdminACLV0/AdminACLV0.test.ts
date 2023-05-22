import {
  T_Config,
  getAccounts,
  assignDefaultConstants,
  deployAndGet,
  deployCoreWithMinterFilter,
  mintProjectUntilRemaining,
  advanceEVMByTime,
} from "../../util/common";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

import { AdminACLV0V1_Common } from "../AdminACLV0V1.common";

/**
 * Tests for functionality of AdminACLV0.
 */
describe(`AdminACLV0`, async function () {
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
      "GenArt721CoreV3",
      "MinterFilterV1"
    ));

    config.minter = await deployAndGet(config, "MinterSetPriceV2", [
      config.genArt721Core.address,
      config.minterFilter.address,
    ]);

    // deploy alternate admin ACL that does not broadcast support of IAdminACLV0
    config.adminACL_NoInterfaceBroadcast = await deployAndGet(
      config,
      "MockAdminACLV0Events",
      []
    );

    // deploy another admin ACL that does broadcast support of IAdminACLV0
    config.adminACL_InterfaceBroadcast = await deployAndGet(
      config,
      "AdminACLV0",
      []
    );
    return config;
  }

  describe(`common tests`, async function () {
    await AdminACLV0V1_Common(_beforeEach, "AdminACLV0");
  });
});
