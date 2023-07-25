import { expectRevert, constants } from "@openzeppelin/test-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";
import { Contract } from "ethers";
import Mocha from "mocha";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

import {
  AdminACLV0,
  AdminACLV0__factory,
  DependencyRegistryV0,
  GenArt721CoreV1,
  GenArt721CoreV3,
  BytecodeV1TextCR_DMock,
  SSTORE2Mock,
} from "../../scripts/contracts";

import {
  T_Config,
  getAccounts,
  assignDefaultConstants,
  deployAndGet,
  deployWithStorageLibraryAndGet,
  deployCoreWithMinterFilter,
} from "../util/common";

const ONLY_ADMIN_ACL_ERROR = "Only Admin ACL allowed";
const ONLY_EXISTING_DEPENDENCY_TYPE_ERROR = "Dependency type does not exist";
const ONLY_NON_EMPTY_STRING_ERROR = "Must input non-empty string";

// test the following V3 core contract derivatives:
const coreContractsToTest = [
  "GenArt721CoreV3", // flagship V3 core
  "GenArt721CoreV3_Explorations", // V3 core explorations contract
];

interface DependencyRegistryV0TestContext extends Mocha.Context {
  dependencyRegistry: DependencyRegistryV0;
  genArt721Core: GenArt721CoreV3;
  adminACL: AdminACLV0;
}

/**
 * Tests for V3 core dealing with configuring projects.
 */
describe(`DependencyRegistryV0`, async function () {
  const dependencyType = "p5js@1.0.0";
  const dependencyTypeBytes = ethers.utils.formatBytes32String(dependencyType);
  const preferredCDN =
    "https://cdnjs.cloudflare.com/ajax/libs/p5.js/1.0.0/p5.min.js";
  const preferredRepository = "https://github.com/processing/p5.js";
  const referenceWebsite = "https://p5js.org/";

  // Helper that retrieves the address of the most recently deployed contract
  // containing bytecode for storage, from the SSTORE2 library.
  async function getLatestTextDeploymentAddressSSTORE2(sstore2Mock: Contract) {
    const nextTextSlotId = await sstore2Mock.nextTextSlotId();
    // decrement from `nextTextSlotId` to get last updated slot
    const textSlotId = nextTextSlotId - 1;
    const textBytecodeAddress = await sstore2Mock.storedTextBytecodeAddresses(
      textSlotId
    );
    return textBytecodeAddress;
  }

  // Helper that retrieves the address of the most recently deployed contract
  // containing bytecode for storage, from the V0 ByteCode storage library.
  async function getLatestTextDeploymentAddressV1(
    bytecodeV1TextCR_DMock: Contract
  ) {
    const nextTextSlotId = await bytecodeV1TextCR_DMock.nextTextSlotId();
    // decrement from `nextTextSlotId` to get last updated slot
    const textSlotId = nextTextSlotId - 1;
    const textBytecodeAddress =
      await bytecodeV1TextCR_DMock.storedTextBytecodeAddresses(textSlotId);
    return textBytecodeAddress;
  }

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

    config.dependencyRegistry = await deployWithStorageLibraryAndGet(
      config,
      "DependencyRegistryV0"
    );
    await config.dependencyRegistry
      .connect(config.accounts.deployer)
      .initialize(config.adminACL.address);

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

    // set up library mocks
    // deploy the V1 library mock
    config.bytecodeV1TextCR_DMock = await deployWithStorageLibraryAndGet(
      config,
      "BytecodeV1TextCR_DMock",
      [] // no deployment args
    );
    // deploy the SSTORE2 library mock
    config.sstore2Mock = await deployAndGet(
      config,
      "SSTORE2Mock",
      [] // no deployment args
    );

    return config;
  }

  describe("registered dependencies", function () {
    describe("addDependency", function () {
      it("does not allow non-admins to add a dependency", async function () {
        const config = await loadFixture(_beforeEach);
        // deployer cannot update
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.artist)
            .addDependency(
              ethers.utils.formatBytes32String("p5js@1.0.0"),
              preferredCDN,
              preferredRepository,
              referenceWebsite
            ),
          "Only Admin ACL allowed"
        );
      });

      it("does not allow a dependency to be added without exactly one @ symbol", async function () {
        const config = await loadFixture(_beforeEach);
        // deployer cannot update
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependency(
              ethers.utils.formatBytes32String("p5js"),
              preferredCDN,
              preferredRepository,
              referenceWebsite
            ),
          "must contain exactly one @"
        );
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependency(
              ethers.utils.formatBytes32String("p5@js@1.0.0"),
              preferredCDN,
              preferredRepository,
              referenceWebsite
            ),
          "must contain exactly one @"
        );
      });

      it("allows admin to add a dependency", async function () {
        const config = await loadFixture(_beforeEach);
        // admin can update
        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependency(
              dependencyTypeBytes,
              preferredCDN,
              preferredRepository,
              referenceWebsite
            )
        )
          .to.emit(config.dependencyRegistry, "DependencyAdded")
          .withArgs(
            dependencyTypeBytes,
            preferredCDN,
            preferredRepository,
            referenceWebsite
          );

        const registeredDependencyCount =
          await config.dependencyRegistry.getDependencyTypeCount();
        expect(registeredDependencyCount).to.eq(1);

        const storedDepType =
          await config.dependencyRegistry.getDependencyTypeAtIndex(0);
        expect(storedDepType).to.eq(dependencyType);

        const dependencyTypes =
          await config.dependencyRegistry.getDependencyTypes();
        expect(dependencyTypes).to.deep.eq([dependencyType]);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );
        expect(dependencyDetails).to.deep.eq([
          dependencyType, // type@version
          preferredCDN, // preferredCDN
          0, // aadditionalCDNCount
          preferredRepository, // preferredRepository
          0, // additionalRepositoryCount
          referenceWebsite, // referenceWebsite
          false, // availableOnChain
          0, // scriptCount
        ]);
      });
    });

    describe("removeDependency", function () {
      it("does not allow non-admins to remove a dependency", async function () {
        const config = await loadFixture(_beforeEach);
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependency(
            dependencyTypeBytes,
            preferredCDN,
            preferredRepository,
            referenceWebsite
          );

        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .removeDependency(dependencyTypeBytes),
          ONLY_ADMIN_ACL_ERROR
        );
      });

      it("does not allow removal of a dependency that does not exist", async function () {
        const config = await loadFixture(_beforeEach);
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependency(ethers.utils.formatBytes32String(dependencyType)),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });

      it("does not allow removal of a dependency with additional CDNs, repositories, or scripts", async function () {
        const config = await loadFixture(_beforeEach);
        const noAssociatedDataError =
          "Cannot remove dependency with additional CDNs, repositories, or scripts";

        // Add dependency
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependency(
            dependencyTypeBytes,
            preferredCDN,
            preferredRepository,
            referenceWebsite
          );

        // Cannot remove with additional CDNs
        await config.dependencyRegistry.addDependencyAdditionalCDN(
          dependencyTypeBytes,
          "https://additionalCDN.com"
        );

        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependency(dependencyTypeBytes),
          noAssociatedDataError
        );

        // Remove additional CDNs
        await config.dependencyRegistry.removeDependencyAdditionalCDNAtIndex(
          dependencyTypeBytes,
          0
        );

        // Cannot remove with additional repositories
        await config.dependencyRegistry.addDependencyAdditionalRepository(
          dependencyTypeBytes,
          "https://additionalRepository.com"
        );

        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependency(dependencyTypeBytes),
          noAssociatedDataError
        );

        // Remove additional repositories
        await config.dependencyRegistry.removeDependencyAdditionalRepositoryAtIndex(
          dependencyTypeBytes,
          0
        );

        // Cannot remove with scripts
        await config.dependencyRegistry.addDependencyScript(
          dependencyTypeBytes,
          "on-chain script"
        );

        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependency(dependencyTypeBytes),
          noAssociatedDataError
        );

        // Remove scripts
        await config.dependencyRegistry.removeDependencyLastScript(
          dependencyTypeBytes
        );

        await config.dependencyRegistry.removeDependency(dependencyTypeBytes);
      });

      it("allows admin to remove a dependency", async function () {
        const config = await loadFixture(_beforeEach);
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependency(
            dependencyTypeBytes,
            preferredCDN,
            preferredRepository,
            referenceWebsite
          );

        await expect(
          config.dependencyRegistry.removeDependency(dependencyTypeBytes)
        )
          .to.emit(config.dependencyRegistry, "DependencyRemoved")
          .withArgs(dependencyTypeBytes);

        const registeredDependencyCount =
          await config.dependencyRegistry.getDependencyTypeCount();
        expect(registeredDependencyCount).to.eq(0);

        const dependencyTypes =
          await config.dependencyRegistry.getDependencyTypes();
        expect(dependencyTypes).to.deep.eq([]);
      });
    });
    describe("update", function () {
      beforeEach(async function () {
        const config = await loadFixture(_beforeEach);
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependency(
            dependencyTypeBytes,
            preferredCDN,
            preferredRepository,
            referenceWebsite
          );
        // pass config to tests in this describe block
        this.config = config;
      });

      describe("updateDependencyPreferredCDN", function () {
        it("does not allow non-admins to update preferred cdn", async function () {
          // get config from beforeEach
          const config = this.config;
          await expectRevert(
            config.dependencyRegistry
              .connect(config.accounts.user)
              .updateDependencyPreferredCDN(
                dependencyTypeBytes,
                "https://cdn.com"
              ),
            ONLY_ADMIN_ACL_ERROR
          );
        });
        it("does not allow updating preferred cdn for a dependency that does not exist", async function () {
          // get config from beforeEach
          const config = this.config;
          await expectRevert(
            config.dependencyRegistry
              .connect(config.accounts.deployer)
              .updateDependencyPreferredCDN(
                ethers.utils.formatBytes32String("nonExistentDependencyType"),
                "https://cdn.com"
              ),
            ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
          );
        });
        it("allows admin to update preferred cdn", async function () {
          // get config from beforeEach
          const config = this.config;
          await config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com");

          await expect(
            config.dependencyRegistry
              .connect(config.accounts.deployer)
              .updateDependencyPreferredCDN(
                dependencyTypeBytes,
                "https://cdn2.com"
              )
          )
            .to.emit(config.dependencyRegistry, "DependencyPreferredCDNUpdated")
            .withArgs(dependencyTypeBytes, "https://cdn2.com");

          const dependencyDetails =
            await config.dependencyRegistry.getDependencyDetails(
              dependencyTypeBytes
            );

          expect(dependencyDetails.preferredCDN).to.eq("https://cdn2.com");
        });
      });
      describe("updateDependencyPreferredRepository", function () {
        it("does not allow non-admins to update preferred repository", async function () {
          // get config from beforeEach
          const config = this.config;
          await expectRevert(
            config.dependencyRegistry
              .connect(config.accounts.user)
              .updateDependencyPreferredRepository(
                dependencyTypeBytes,
                "https://github.com"
              ),
            ONLY_ADMIN_ACL_ERROR
          );
        });
        it("does not allow updating preferred repository for a dependency that does not exist", async function () {
          // get config from beforeEach
          const config = this.config;
          await expectRevert(
            config.dependencyRegistry
              .connect(config.accounts.deployer)
              .updateDependencyPreferredRepository(
                ethers.utils.formatBytes32String("nonExistentDependencyType"),
                "https://github.com"
              ),
            ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
          );
        });
        it("allows admin to update preferred repository", async function () {
          // get config from beforeEach
          const config = this.config;
          await expect(
            config.dependencyRegistry
              .connect(config.accounts.deployer)
              .updateDependencyPreferredRepository(
                dependencyTypeBytes,
                "https://github.com"
              )
          )
            .to.emit(
              config.dependencyRegistry,
              "DependencyPreferredRepositoryUpdated"
            )
            .withArgs(dependencyTypeBytes, "https://github.com");

          const dependencyDetails =
            await config.dependencyRegistry.getDependencyDetails(
              dependencyTypeBytes
            );

          expect(dependencyDetails.preferredRepository).to.eq(
            "https://github.com"
          );
        });
      });
      describe("updateDependencyReferenceWebsite", function () {
        it("does not allow non-admins to update reference website", async function () {
          // get config from beforeEach
          const config = this.config;
          await expectRevert(
            config.dependencyRegistry
              .connect(config.accounts.user)
              .updateDependencyReferenceWebsite(
                dependencyTypeBytes,
                "https://reference.com"
              ),
            ONLY_ADMIN_ACL_ERROR
          );
        });
        it("does not allow updating reference website for a dependency that does not exist", async function () {
          // get config from beforeEach
          const config = this.config;
          await expectRevert(
            config.dependencyRegistry
              .connect(config.accounts.deployer)
              .updateDependencyReferenceWebsite(
                ethers.utils.formatBytes32String("nonExistentDependencyType"),
                "https://reference.com"
              ),
            ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
          );
        });
        it("allows admin to update reference website", async function () {
          // get config from beforeEach
          const config = this.config;
          await expect(
            config.dependencyRegistry
              .connect(config.accounts.deployer)
              .updateDependencyReferenceWebsite(
                dependencyTypeBytes,
                "https://reference.com"
              )
          )
            .to.emit(
              config.dependencyRegistry,
              "DependencyReferenceWebsiteUpdated"
            )
            .withArgs(dependencyTypeBytes, "https://reference.com");

          const dependencyDetails =
            await config.dependencyRegistry.getDependencyDetails(
              dependencyTypeBytes
            );

          expect(dependencyDetails.referenceWebsite).to.eq(
            "https://reference.com"
          );
        });
      });
    });
  });
  describe("dependency scripts", function () {
    beforeEach(async function () {
      const config = await loadFixture(_beforeEach);
      await config.dependencyRegistry
        .connect(config.accounts.deployer)
        .addDependency(
          dependencyTypeBytes,
          preferredCDN,
          preferredRepository,
          referenceWebsite
        );
      // pass config to tests in this describe block
      this.config = config;
    });

    // TODO!
    describe("direct pointer compatibility", function () {
      it("does not allow non-admins to add a script pointer", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .addDependencyScriptPointer(dependencyTypeBytes, "on-chain script"),
          ONLY_ADMIN_ACL_ERROR
        );
      });
    });

    describe("addDependencyScript", function () {
      it("does not allow non-admins to add a script", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .addDependencyScript(dependencyTypeBytes, "on-chain script"),
          ONLY_ADMIN_ACL_ERROR
        );
      });

      it("does not allow adding a script to a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyScript(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              "on-chain script"
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });

      it("does not allow adding an empty string as a script", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyScript(dependencyTypeBytes, ""),
          ONLY_NON_EMPTY_STRING_ERROR
        );
      });

      it("allows admin to add a script", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";
        await expect(
          config.dependencyRegistry.addDependencyScript(
            dependencyTypeBytes,
            script
          )
        )
          .to.emit(config.dependencyRegistry, "DependencyScriptUpdated")
          .withArgs(dependencyTypeBytes);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.scriptCount).to.eq(1);

        const scriptCount =
          await config.dependencyRegistry.getDependencyScriptCount(
            dependencyTypeBytes
          );
        expect(scriptCount).to.eq(1);

        const storedScript =
          await config.dependencyRegistry.getDependencyScriptAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedScript).to.eq(script);
      });
    });

    describe("removeDependencyLastScript", function () {
      it("does not allow non-admins to remove a script", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .removeDependencyLastScript(dependencyTypeBytes),
          ONLY_ADMIN_ACL_ERROR
        );
      });

      it("does not allow removing a script from a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependency(
              ethers.utils.formatBytes32String("nonExistentDependencyType")
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });

      it("does not allow removing the last script if non-existent", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyLastScript(dependencyTypeBytes),
          "there are no scripts to remove"
        );
      });

      it("allows admin to remove last script", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyScript(dependencyTypeBytes, script);

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyLastScript(dependencyTypeBytes)
        )
          .to.emit(config.dependencyRegistry, "DependencyScriptUpdated")
          .withArgs(dependencyTypeBytes);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.scriptCount).to.eq(0);

        const scriptCount =
          await config.dependencyRegistry.getDependencyScriptCount(
            dependencyTypeBytes
          );
        expect(scriptCount).to.eq(0);

        const storedScript =
          await config.dependencyRegistry.getDependencyScriptAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedScript).to.eq("");
      });
    });

    describe("updateDependencyScript", function () {
      it("does not allow non-admins to update a script", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .updateDependencyScript(dependencyTypeBytes, 0, "on-chain script"),
          ONLY_ADMIN_ACL_ERROR
        );
      });

      it("does not allow updating a script for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyScript(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              0,
              "on-chain script"
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });

      it("does not allow updating a script that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyScript(dependencyTypeBytes, 0, "on-chain script"),
          "scriptId out of range"
        );
      });

      it("does not allow updating an empty string as a script", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyScript(dependencyTypeBytes, script);

        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyScript(dependencyTypeBytes, 0, ""),
          ONLY_NON_EMPTY_STRING_ERROR
        );
      });

      it("allows admin to update a script", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyScript(dependencyTypeBytes, script);

        const updatedScript = "updated on-chain script";

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyScript(dependencyTypeBytes, 0, updatedScript)
        )
          .to.emit(config.dependencyRegistry, "DependencyScriptUpdated")
          .withArgs(dependencyTypeBytes);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.scriptCount).to.eq(1);

        const scriptCount =
          await config.dependencyRegistry.getDependencyScriptCount(
            dependencyTypeBytes
          );
        expect(scriptCount).to.eq(1);

        const storedScript =
          await config.dependencyRegistry.getDependencyScriptAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedScript).to.eq(updatedScript);
      });
    });
    describe("views", function () {
      it("getDependencyDetails", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyScript(dependencyTypeBytes, script);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.scriptCount).to.eq(1);
        expect(dependencyDetails.availableOnChain).to.eq(true);
      });

      it("getDependencyScriptAtIndex", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyScript(dependencyTypeBytes, script);

        const storedScript =
          await config.dependencyRegistry.getDependencyScriptAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedScript).to.eq(script);
      });

      it("getDependencyScriptBytecodeAddressAtIndex", async function () {
        // get config from beforeEach
        const config = this.config;
        const script = "on-chain script";

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyScript(dependencyTypeBytes, script);

        const storedScriptByteCodeAddress =
          await config.dependencyRegistry.getDependencyScriptBytecodeAddressAtIndex(
            dependencyTypeBytes,
            0
          );

        const scriptBytecode = await ethers.provider.getCode(
          storedScriptByteCodeAddress
        );
        expect(scriptBytecode).to.contain(
          ethers.utils.hexlify(ethers.utils.toUtf8Bytes(script)).substring(2)
        );
      });
    });
  });
  describe("dependency additional cdns", function () {
    beforeEach(async function () {
      const config = await loadFixture(_beforeEach);
      await config.dependencyRegistry
        .connect(config.accounts.deployer)
        .addDependency(
          dependencyTypeBytes,
          preferredCDN,
          preferredRepository,
          referenceWebsite
        );
      // pass config to tests in this describe block
      this.config = config;
    });

    describe("addDependencyAdditionalCDN", function () {
      it("does not allow non-admins to add a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com"),
          ONLY_ADMIN_ACL_ERROR
        );
      });

      it("does not allow adding a cdn for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalCDN(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              "https://cdn.com"
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });

      it("does not allow adding an empty string as a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalCDN(dependencyTypeBytes, ""),
          ONLY_NON_EMPTY_STRING_ERROR
        );
      });

      it("allows admin to add a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com")
        )
          .to.emit(config.dependencyRegistry, "DependencyAdditionalCDNUpdated")
          .withArgs(dependencyTypeBytes, "https://cdn.com", 0);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalCDNCount).to.eq(1);

        const storedCDN =
          await config.dependencyRegistry.getDependencyAdditionalCDNAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedCDN).to.eq("https://cdn.com");
      });
    });
    describe("removeDependencyAdditionalCDNAtIndex", function () {
      it("does not allow non-admins to remove a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .removeDependencyAdditionalCDNAtIndex(dependencyTypeBytes, 0),
          ONLY_ADMIN_ACL_ERROR
        );
      });

      it("does not allow removing a cdn for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyAdditionalCDNAtIndex(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              0
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });

      it("does not allow removing a cdn with out of range index", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyAdditionalCDNAtIndex(dependencyTypeBytes, 0),
          "Asset index out of range"
        );
      });

      it("allows admin to remove a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com");

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyAdditionalCDNAtIndex(dependencyTypeBytes, 0)
        )
          .to.emit(config.dependencyRegistry, "DependencyAdditionalCDNRemoved")
          .withArgs(dependencyTypeBytes, 0);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalCDNCount).to.eq(0);
      });
    });

    describe("updateDependencyAdditionalCDNAtIndex", function () {
      it("does not allow non-admins to update a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .updateDependencyAdditionalCDNAtIndex(
              dependencyTypeBytes,
              0,
              "https://cdn.com"
            ),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow updating a cdn for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalCDNAtIndex(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              0,
              "https://cdn.com"
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });
      it("does not allow updating a cdn with out of range index", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalCDNAtIndex(
              dependencyTypeBytes,
              0,
              "https://cdn.com"
            ),
          "Asset index out of range"
        );
      });
      it("does not allow updating a cdn with empty string", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalCDNAtIndex(dependencyTypeBytes, 0, ""),
          ONLY_NON_EMPTY_STRING_ERROR
        );
      });
      it("allows admin to update a cdn", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com");

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalCDNAtIndex(
              dependencyTypeBytes,
              0,
              "https://cdn2.com"
            )
        )
          .to.emit(config.dependencyRegistry, "DependencyAdditionalCDNUpdated")
          .withArgs(dependencyTypeBytes, "https://cdn2.com", 0);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalCDNCount).to.eq(1);

        const storedCDN =
          await config.dependencyRegistry.getDependencyAdditionalCDNAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedCDN).to.eq("https://cdn2.com");
      });
    });
    describe("views", function () {
      it("getdependencyDetails", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com");

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalCDNCount).to.eq(1);
      });

      it("getDependencyAdditionalCDNAtIndex", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalCDN(dependencyTypeBytes, "https://cdn.com");

        const storedCDN =
          await config.dependencyRegistry.getDependencyAdditionalCDNAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedCDN).to.eq("https://cdn.com");
      });
    });
  });
  describe("dependency additional repositories", function () {
    beforeEach(async function () {
      const config = await loadFixture(_beforeEach);
      await config.dependencyRegistry
        .connect(config.accounts.deployer)
        .addDependency(
          dependencyTypeBytes,
          preferredCDN,
          preferredRepository,
          referenceWebsite
        );
      // pass config to tests in this describe block
      this.config = config;
    });

    describe("addDependencyAdditionalRepository", function () {
      it("does not allow non-admins to add additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .addDependencyAdditionalRepository(
              dependencyTypeBytes,
              "https://github.com"
            ),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow adding additional repository for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalRepository(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              "https://github.com"
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });
      it("does not allow adding empty string as additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalRepository(dependencyTypeBytes, ""),
          ONLY_NON_EMPTY_STRING_ERROR
        );
      });
      it("allows admin to add additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addDependencyAdditionalRepository(
              dependencyTypeBytes,
              "https://github.com"
            )
        )
          .to.emit(
            config.dependencyRegistry,
            "DependencyAdditionalRepositoryUpdated"
          )
          .withArgs(dependencyTypeBytes, "https://github.com", 0);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalRepositoryCount).to.eq(1);

        const storedRepository =
          await config.dependencyRegistry.getDependencyAdditionalRepositoryAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedRepository).to.eq("https://github.com");
      });
    });
    describe("removeDependencyAdditionalRepositoryAtIndex", function () {
      it("does not allow non-admins to remove additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .removeDependencyAdditionalRepositoryAtIndex(
              dependencyTypeBytes,
              0
            ),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow removing additional repository for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyAdditionalRepositoryAtIndex(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              0
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });
      it("does not allow removing additional repository at index that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyAdditionalRepositoryAtIndex(
              dependencyTypeBytes,
              1
            ),
          "Asset index out of range"
        );
      });
      it("allows admin to remove additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalRepository(
            dependencyTypeBytes,
            "https://github.com"
          );

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeDependencyAdditionalRepositoryAtIndex(dependencyTypeBytes, 0)
        )
          .to.emit(
            config.dependencyRegistry,
            "DependencyAdditionalRepositoryRemoved"
          )
          .withArgs(dependencyTypeBytes, 0);

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalRepositoryCount).to.eq(0);

        const storedRepository =
          await config.dependencyRegistry.getDependencyAdditionalRepositoryAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedRepository).to.eq("");
      });
    });
    describe("updateDependencyAdditionalRepositoryAtIndex", function () {
      it("does not allow non-admins to update additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .updateDependencyAdditionalRepositoryAtIndex(
              dependencyTypeBytes,
              0,
              "https://github.com"
            ),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow updating additional repository for a dependency that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalRepositoryAtIndex(
              ethers.utils.formatBytes32String("nonExistentDependencyType"),
              0,
              "https://github.com"
            ),
          ONLY_EXISTING_DEPENDENCY_TYPE_ERROR
        );
      });
      it("does not allow updating additional repository at index that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalRepositoryAtIndex(
              dependencyTypeBytes,
              1,
              "https://github.com"
            ),
          "Asset index out of range"
        );
      });
      it("does not allow updating additional repository to empty string", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalRepositoryAtIndex(
              dependencyTypeBytes,
              0,
              ""
            ),
          ONLY_NON_EMPTY_STRING_ERROR
        );
      });
      it("allows admin to update additional repository", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalRepository(
            dependencyTypeBytes,
            "https://github.com"
          );

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .updateDependencyAdditionalRepositoryAtIndex(
              dependencyTypeBytes,
              0,
              "https://bitbucket.com"
            )
        )
          .to.emit(
            config.dependencyRegistry,
            "DependencyAdditionalRepositoryUpdated"
          )
          .withArgs(dependencyTypeBytes, "https://bitbucket.com", 0);

        const storedRepository =
          await config.dependencyRegistry.getDependencyAdditionalRepositoryAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedRepository).to.eq("https://bitbucket.com");
      });
    });

    describe("views", function () {
      it("getdependencyDetails", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalRepository(
            dependencyTypeBytes,
            "https://github.com"
          );

        const dependencyDetails =
          await config.dependencyRegistry.getDependencyDetails(
            dependencyTypeBytes
          );

        expect(dependencyDetails.additionalRepositoryCount).to.eq(1);
      });
      it("getDependencyAdditionalRepositoryAtIndex", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addDependencyAdditionalRepository(
            dependencyTypeBytes,
            "https://github.com"
          );

        const storedRepository =
          await config.dependencyRegistry.getDependencyAdditionalRepositoryAtIndex(
            dependencyTypeBytes,
            0
          );
        expect(storedRepository).to.eq("https://github.com");
      });
    });
  });
  describe("project dependency override", function () {
    beforeEach(async function () {
      const config = await loadFixture(_beforeEach);
      await config.dependencyRegistry
        .connect(config.accounts.deployer)
        .addDependency(
          dependencyTypeBytes,
          preferredCDN,
          preferredRepository,
          referenceWebsite
        );
      // pass config to tests in this describe block
      this.config = config;
    });
    describe("addSupportedCoreContract", function () {
      it("does not allow non-admins to add supported core contract", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .addSupportedCoreContract(config.genArt721Core.address),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow adding supported core contract that already exists", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(config.genArt721Core.address);

        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addSupportedCoreContract(config.genArt721Core.address),
          "Contract already supported"
        );
      });
      it("does not allow the zero addresss", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addSupportedCoreContract(ethers.constants.AddressZero),
          "Must input non-zero address"
        );
      });

      it("allows admin to add supported core contract", async function () {
        // get config from beforeEach
        const config = this.config;
        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addSupportedCoreContract(config.genArt721Core.address)
        )
          .to.emit(config.dependencyRegistry, "SupportedCoreContractAdded")
          .withArgs(config.genArt721Core.address);

        const supportedCoreContractCount =
          await config.dependencyRegistry.getSupportedCoreContractCount();
        expect(supportedCoreContractCount).to.eq(1);

        const storedCoreContract =
          await config.dependencyRegistry.getSupportedCoreContractAtIndex(0);
        expect(storedCoreContract).to.eq(config.genArt721Core.address);

        const supportedCoreContracts =
          await config.dependencyRegistry.getSupportedCoreContracts();
        expect(supportedCoreContracts).to.deep.eq([
          config.genArt721Core.address,
        ]);

        const isSupportedCoreContract =
          await config.dependencyRegistry.isSupportedCoreContract(
            config.genArt721Core.address
          );
        expect(isSupportedCoreContract).to.eq(true);
      });
    });
    describe("removeSupportedCoreContract", function () {
      it("does not allow non-admins to remove supported core contract", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .removeSupportedCoreContract(config.genArt721Core.address),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow removing supported core contract that does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeSupportedCoreContract(config.genArt721Core.address),
          "Core contract not supported"
        );
      });
      it("allows admin to remove supported core contract", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(config.genArt721Core.address);

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeSupportedCoreContract(config.genArt721Core.address)
        )
          .to.emit(config.dependencyRegistry, "SupportedCoreContractRemoved")
          .withArgs(config.genArt721Core.address);

        const supportedCoreContractCount =
          await config.dependencyRegistry.getSupportedCoreContractCount();
        expect(supportedCoreContractCount).to.eq(0);

        await expectRevert(
          config.dependencyRegistry.getSupportedCoreContractAtIndex(0),
          "Index out of bounds"
        );

        const supportedCoreContracts =
          await config.dependencyRegistry.getSupportedCoreContracts();
        expect(supportedCoreContracts).to.deep.eq([]);

        const isSupportedCoreContract =
          await config.dependencyRegistry.isSupportedCoreContract(
            config.genArt721Core.address
          );
        expect(isSupportedCoreContract).to.eq(false);
      });
    });
    describe("addProjectDependencyTypeOverride", function () {
      it("does not allow non-admins to add project dependency override", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .addProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0,
              dependencyTypeBytes
            ),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("does not allow adding override that is not a registered dependency", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0,
              ethers.utils.formatBytes32String("not@registered")
            ),
          "Dependency type does not exist"
        );
      });
      it("does not allow adding override for a project that is not on a supported core contract", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0,
              dependencyTypeBytes
            ),
          "Core contract not supported"
        );
      });
      it("allows admin to add project dependency override", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(config.genArt721Core.address);

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .addProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0,
              dependencyTypeBytes
            )
        )
          .to.emit(
            config.dependencyRegistry,
            "ProjectDependencyTypeOverrideAdded"
          )
          .withArgs(config.genArt721Core.address, 0, dependencyTypeBytes);

        const storedDependencyType =
          await config.dependencyRegistry.getDependencyTypeForProject(
            config.genArt721Core.address,
            0
          );
        expect(storedDependencyType).to.eq(dependencyType);
      });
    });
    describe("removeProjectDependencyTypeOverride", function () {
      it("does not allow non-admins to remove project dependency override", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.user)
            .removeProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0
            ),
          ONLY_ADMIN_ACL_ERROR
        );
      });
      it("reverts if override does not exist", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0
            ),
          "No override set for project"
        );
      });
      it("allows admin to remove project dependency override", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(config.genArt721Core.address);

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addProjectDependencyTypeOverride(
            config.genArt721Core.address,
            0,
            dependencyTypeBytes
          );

        await expect(
          config.dependencyRegistry
            .connect(config.accounts.deployer)
            .removeProjectDependencyTypeOverride(
              config.genArt721Core.address,
              0
            )
        )
          .to.emit(
            config.dependencyRegistry,
            "ProjectDependencyTypeOverrideRemoved"
          )
          .withArgs(config.genArt721Core.address, 0);

        const storedDependencyType =
          await config.dependencyRegistry.getDependencyTypeForProject(
            config.genArt721Core.address,
            0
          );
        expect(storedDependencyType).to.eq("");
      });
    });
    describe("getDependencyTypeForProject", function () {
      it("reverts if core contract is not supported", async function () {
        // get config from beforeEach
        const config = this.config;
        await expectRevert(
          config.dependencyRegistry.getDependencyTypeForProject(
            config.genArt721Core.address,
            0
          ),
          "Core contract not supported"
        );
      });

      it("reverts if no override and contract does not support projectScriptDetails", async function () {
        // get config from beforeEach
        const config = this.config;
        const {
          genArt721Core: genArt721CoreV1,
        }: { genArt721Core: GenArt721CoreV1 } =
          await deployCoreWithMinterFilter(
            config,
            "GenArt721CoreV1",
            "MinterFilterV0"
          );

        await genArt721CoreV1.addProject(
          "v1 project",
          config.accounts.artist.address,
          ethers.utils.parseEther("0.1"),
          true
        );

        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(genArt721CoreV1.address);

        await expectRevert(
          config.dependencyRegistry.getDependencyTypeForProject(
            genArt721CoreV1.address,
            0
          ),
          "Contract does not implement projectScriptDetails and has no override set."
        );
      });

      it("returns the overridden value if present", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(config.genArt721Core.address);

        const coreDepType = "core@0";
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProjectScriptType(
            0,
            ethers.utils.formatBytes32String(coreDepType)
          );

        const override = dependencyType;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addProjectDependencyTypeOverride(
            config.genArt721Core.address,
            0,
            ethers.utils.formatBytes32String(override)
          );

        const regDepType =
          await config.dependencyRegistry.getDependencyTypeForProject(
            config.genArt721Core.address,
            0
          );

        expect(regDepType).to.eq(override);
      });

      it("returns the dependency type from the core contract if no override is set", async function () {
        // get config from beforeEach
        const config = this.config;
        await config.dependencyRegistry
          .connect(config.accounts.deployer)
          .addSupportedCoreContract(config.genArt721Core.address);

        const coreDepType = "core@0";
        await config.genArt721Core
          .connect(config.accounts.deployer)
          .updateProjectScriptType(
            0,
            ethers.utils.formatBytes32String(coreDepType)
          );

        const regDepType =
          await config.dependencyRegistry.getDependencyTypeForProject(
            config.genArt721Core.address,
            0
          );

        expect(regDepType).to.eq(coreDepType);
      });
    });
  });
  describe("adminACLContract", function () {
    it("returns expected adminACLContract address", async function () {
      const config = await loadFixture(_beforeEach);
      expect(await config.genArt721Core.adminACLContract()).to.be.equal(
        config.adminACL.address
      );
    });

    it("behaves as expected when transferring ownership", async function () {
      const config = await loadFixture(_beforeEach);
      // deploy new ACL with user as superAdmin
      const userAdminACLFactory = new AdminACLV0__factory(config.accounts.user);
      const userAdminACL = await userAdminACLFactory.deploy();

      // update owner of core to new userAdminACL, expect OwnershipTransferred event
      await expect(
        config.adminACL
          .connect(config.accounts.deployer)
          .transferOwnershipOn(
            config.dependencyRegistry.address,
            userAdminACL.address
          )
      )
        .to.emit(config.dependencyRegistry, "OwnershipTransferred")
        .withArgs(config.adminACL.address, userAdminACL.address);
      // ensure owner + public adminACLContract has been updated
      expect(await config.dependencyRegistry.owner()).to.be.equal(
        userAdminACL.address
      );
      expect(await config.dependencyRegistry.adminACLContract()).to.be.equal(
        userAdminACL.address
      );
      // ensure new userAdminACL may update project
      await config.dependencyRegistry
        .connect(config.accounts.user)
        .addDependency(
          ethers.utils.formatBytes32String("three@0.0.24"),
          "preferredCDN",
          "preferredRepository",
          "referenceWebsite"
        );
    });

    it("behaves as expected when renouncing ownership", async function () {
      const config = await loadFixture(_beforeEach);
      // update owner of core to null address, expect OwnershipTransferred event
      await expect(
        await config.adminACL
          .connect(config.accounts.deployer)
          .renounceOwnershipOn(config.dependencyRegistry.address)
      )
        .to.emit(config.dependencyRegistry, "OwnershipTransferred")
        .withArgs(config.adminACL.address, constants.ZERO_ADDRESS);

      // ensure owner + public adminACLContract has been updated
      expect(await config.dependencyRegistry.owner()).to.be.equal(
        constants.ZERO_ADDRESS
      );
      expect(await config.dependencyRegistry.adminACLContract()).to.be.equal(
        constants.ZERO_ADDRESS
      );
      // ensure prior adminACL may not perform an admin function
      await expectRevert(
        // ensure new userAdminACL may update project
        config.dependencyRegistry
          .connect(config.accounts.user)
          .addDependency(
            ethers.utils.formatBytes32String("three@0.0.24"),
            "preferredCDN",
            "preferredRepository",
            "referenceWebsite"
          ),
        "Only Admin ACL allowed"
      );
    });
  });
});
