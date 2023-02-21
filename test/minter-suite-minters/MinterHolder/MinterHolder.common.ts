import {
  BN,
  constants,
  expectEvent,
  expectRevert,
  balance,
  ether,
} from "@openzeppelin/test-helpers";
import { expect } from "chai";
import { BigNumber, Contract } from "ethers";
import { ethers } from "hardhat";
import { Minter_Common } from "../Minter.common";
import { deployAndGetPBAB, isCoreV3 } from "../../util/common";

import EthersAdapter from "@gnosis.pm/safe-ethers-lib";
import Safe from "@gnosis.pm/safe-core-sdk";
import { SafeTransactionDataPartial } from "@gnosis.pm/safe-core-sdk-types";
import { getGnosisSafe } from "../../util/GnosisSafeNetwork";

/**
 * These tests are intended to check common MinterHolder functionality.
 * @dev assumes common BeforeEach to populate accounts, constants, and setup
 */
export const MinterHolder_Common = async () => {
  describe("common minter tests", async () => {
    await Minter_Common();
  });

  describe("updatePricePerTokenInWei", async function () {
    it("only allows artist to update price", async function () {
      const onlyArtistErrorMessage = "Only Artist";
      // doesn't allow user
      await expectRevert(
        this.minter
          .connect(this.accounts.user)
          .updatePricePerTokenInWei(
            this.projectZero,
            this.higherPricePerTokenInWei
          ),
        onlyArtistErrorMessage
      );
      // doesn't allow deployer
      await expectRevert(
        this.minter
          .connect(this.accounts.deployer)
          .updatePricePerTokenInWei(
            this.projectZero,
            this.higherPricePerTokenInWei
          ),
        onlyArtistErrorMessage
      );
      // doesn't allow additional
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          .updatePricePerTokenInWei(
            this.projectZero,
            this.higherPricePerTokenInWei
          ),
        onlyArtistErrorMessage
      );
      // does allow artist
      await this.minter
        .connect(this.accounts.artist)
        .updatePricePerTokenInWei(
          this.projectZero,
          this.higherPricePerTokenInWei
        );
    });

    it("enforces price update", async function () {
      const needMoreValueErrorMessage = "Must send minimum value to mint!";
      // artist increases price
      await this.minter
        .connect(this.accounts.artist)
        .updatePricePerTokenInWei(
          this.projectZero,
          this.higherPricePerTokenInWei
        );
      // cannot purchase token at lower price
      // note: purchase function is overloaded, so requires full signature
      await expectRevert(
        this.minter
          .connect(this.accounts.artist)
          ["purchase(uint256,address,uint256)"](
            this.projectZero,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei,
            }
          ),
        needMoreValueErrorMessage
      );
      // can purchase token at higher price
      await this.minter
        .connect(this.accounts.artist)
        ["purchase(uint256,address,uint256)"](
          this.projectZero,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber(),
          {
            value: this.higherPricePerTokenInWei,
          }
        );
    });

    it("emits event upon price update", async function () {
      // artist increases price
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(
            this.projectZero,
            this.higherPricePerTokenInWei
          )
      )
        .to.emit(this.minter, "PricePerTokenInWeiUpdated")
        .withArgs(this.projectZero, this.higherPricePerTokenInWei);
    });
  });

  describe("allowHoldersOfProjects", async function () {
    it("only allows artist to update allowed holders", async function () {
      // user not allowed
      await expectRevert(
        this.minter
          .connect(this.accounts.user)
          .allowHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne]
          ),
        "Only Artist"
      );
      // additional not allowed
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          .allowHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne]
          ),
        "Only Artist"
      );
      // artist allowed
      await this.minter
        .connect(this.accounts.artist)
        .allowHoldersOfProjects(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne]
        );
    });

    it("length of array args must match", async function () {
      await expectRevert(
        this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne]
          ),
        "Length of add arrays must match"
      );
    });

    it("emits event when update allowed holders for a single project", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne]
          )
      )
        .to.emit(this.minter, "AllowedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne]
        );
    });

    it("emits event when update allowed holders for a multiple projects", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne, this.projectTwo]
          )
      )
        .to.emit(this.minter, "AllowedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address, this.genArt721Core.address],
          [this.projectOne, this.projectTwo]
        );
    });

    it("does not allow allowlisting a project on an unregistered contract", async function () {
      // deploy different contract (for this case, use PBAB contract)
      const { pbabToken, pbabMinter } = await deployAndGetPBAB.bind(this)();
      await pbabMinter
        .connect(this.accounts.artist)
        .purchaseTo(this.accounts.additional.address, 0, {
          value: this.pricePerTokenInWei,
        });
      // allow holders of PBAB project 0 to purchase tokens on this.projectTwo
      await expectRevert(
        this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectTwo,
            [pbabToken.address],
            [this.projectZero]
          ),
        "Only Registered NFT Addresses"
      );
    });
  });

  describe("removeHoldersOfProjects", async function () {
    it("only allows artist to update allowed holders", async function () {
      // user not allowed
      await expectRevert(
        this.minter
          .connect(this.accounts.user)
          .removeHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne]
          ),
        "Only Artist"
      );
      // additional not allowed
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          .removeHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne]
          ),
        "Only Artist"
      );
      // artist allowed
      await this.minter
        .connect(this.accounts.artist)
        .removeHoldersOfProjects(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne]
        );
    });

    it("only allows equal length array args", async function () {
      await expectRevert(
        this.minter
          .connect(this.accounts.artist)
          .removeHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne]
          ),
        "Length of remove arrays must match"
      );
    });

    it("emits event when removing allowed holders for a single project", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .removeHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne]
          )
      )
        .to.emit(this.minter, "RemovedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne]
        );
    });

    it("emits event when removing allowed holders for multiple projects", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .removeHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne, this.projectTwo]
          )
      )
        .to.emit(this.minter, "RemovedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address, this.genArt721Core.address],
          [this.projectOne, this.projectTwo]
        );
    });
  });

  describe("allowRemoveHoldersOfProjects", async function () {
    it("only allows artist to update allowed holders", async function () {
      // user not allowed
      await expectRevert(
        this.minter
          .connect(this.accounts.user)
          .allowRemoveHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne],
            [this.genArt721Core.address],
            [this.projectOne]
          ),
        "Only Artist"
      );
      // additional not allowed
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          .allowRemoveHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne],
            [this.genArt721Core.address],
            [this.projectOne]
          ),
        "Only Artist"
      );
      // artist allowed
      await this.minter
        .connect(this.accounts.artist)
        .allowRemoveHoldersOfProjects(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne],
          [this.genArt721Core.address],
          [this.projectOne]
        );
    });

    it("emits event when removing allowed holders for a single project", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .allowRemoveHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne],
            [this.genArt721Core.address],
            [this.projectOne]
          )
      )
        .to.emit(this.minter, "AllowedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne]
        );
      // remove event (for same operation, since multiple events)
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .allowRemoveHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address],
            [this.projectOne],
            [this.genArt721Core.address],
            [this.projectOne]
          )
      )
        .to.emit(this.minter, "RemovedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address],
          [this.projectOne]
        );
    });

    it("emits event when adding allowed holders for multiple projects", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .allowRemoveHoldersOfProjects(
            this.projectZero,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne, this.projectTwo],
            [],
            []
          )
      )
        .to.emit(this.minter, "AllowedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address, this.genArt721Core.address],
          [this.projectOne, this.projectTwo]
        );
    });

    it("emits event when removing allowed holders for multiple projects", async function () {
      await expect(
        this.minter
          .connect(this.accounts.artist)
          .allowRemoveHoldersOfProjects(
            this.projectZero,
            [],
            [],
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne, this.projectTwo]
          )
      )
        .to.emit(this.minter, "RemovedHoldersOfProjects")
        .withArgs(
          this.projectZero,
          [this.genArt721Core.address, this.genArt721Core.address],
          [this.projectOne, this.projectTwo]
        );
    });
  });

  describe("isAllowlistedNFT", async function () {
    it("returns true when queried NFT is allowlisted", async function () {
      const isAllowlisted = await this.minter
        .connect(this.accounts.additional)
        .isAllowlistedNFT(
          this.projectZero,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber()
        );
      expect(isAllowlisted).to.be.true;
    });

    it("returns false when queried NFT is not allowlisted", async function () {
      const isAllowlisted = await this.minter
        .connect(this.accounts.additional)
        .isAllowlistedNFT(
          this.projectZero,
          this.genArt721Core.address,
          this.projectOneTokenZero.toNumber()
        );
      expect(isAllowlisted).to.be.false;
    });
  });

  describe("purchase", async function () {
    it("does not allow purchase without NFT ownership args", async function () {
      // expect revert due to price not being configured
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          ["purchase(uint256)"](this.projectZero, {
            value: this.pricePerTokenInWei,
          }),
        "Must claim NFT ownership"
      );
    });

    it("does not allow purchase prior to configuring price", async function () {
      // expect revert due to price not being configured
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          ["purchase(uint256,address,uint256)"](
            this.projectTwo,
            this.genArt721Core.address,
            this.projectTwoTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei,
            }
          ),
        "Price not configured"
      );
    });

    it("does not allow purchase without sending enough funds", async function () {
      // expect revert due when sending zero funds
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          ["purchase(uint256,address,uint256)"](
            this.projectOne,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: 0,
            }
          ),
        "Must send minimum value to mint"
      );
      // expect revert due when sending funds less than price
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          ["purchase(uint256,address,uint256)"](
            this.projectOne,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei.sub(1),
            }
          ),
        "Must send minimum value to mint"
      );
    });

    describe("allows/disallows based on allowed project holder configuration", async function () {
      it("does not allow purchase when using token of unallowed project", async function () {
        // allow holders of this.projectOne to purchase tokens on this.projectTwo
        await this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectTwo,
            [this.genArt721Core.address],
            [this.projectOne]
          );
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // do not allow purchase when holder token in this.projectZero is used as pass
        await expectRevert(
          this.minter
            .connect(this.accounts.additional)
            ["purchase(uint256,address,uint256)"](
              this.projectTwo,
              this.genArt721Core.address,
              this.projectZeroTokenZero.toNumber(),
              {
                value: this.pricePerTokenInWei,
              }
            ),
          "Only allowlisted NFTs"
        );
      });

      it("does not allow purchase when using token of allowed then unallowed project", async function () {
        // allow holders of this.projectZero and this.projectOne, then remove this.projectZero
        await this.minter
          .connect(this.accounts.artist)
          .allowRemoveHoldersOfProjects(
            this.projectTwo,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectZero, this.projectOne],
            [this.genArt721Core.address],
            [this.projectZero]
          );
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // do not allow purchase when holder token in this.projectZero is used as pass
        await expectRevert(
          this.minter
            .connect(this.accounts.additional)
            ["purchase(uint256,address,uint256)"](
              this.projectTwo,
              this.genArt721Core.address,
              this.projectZeroTokenZero.toNumber(),
              {
                value: this.pricePerTokenInWei,
              }
            ),
          "Only allowlisted NFTs"
        );
      });

      it("does allow purchase when using token of allowed project", async function () {
        // allow holders of this.projectZero to purchase tokens on this.projectTwo
        await this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectTwo,
            [this.genArt721Core.address],
            [this.projectZero]
          );
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // does allow purchase when holder token in this.projectZero is used as pass
        await this.minter
          .connect(this.accounts.artist)
          ["purchase(uint256,address,uint256)"](
            this.projectTwo,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei,
            }
          );
      });

      it("does allow purchase when using token of allowed project (when set in bulk)", async function () {
        // allow holders of this.projectOne and this.projectZero to purchase tokens on this.projectTwo
        await this.minter
          .connect(this.accounts.artist)
          .allowRemoveHoldersOfProjects(
            this.projectTwo,
            [this.genArt721Core.address, this.genArt721Core.address],
            [this.projectOne, this.projectZero],
            [],
            []
          );
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // does allow purchase when holder token in this.projectZero is used as pass
        await this.minter
          .connect(this.accounts.artist)
          ["purchase(uint256,address,uint256)"](
            this.projectTwo,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei,
            }
          );
      });

      it("does not allow purchase when using token not owned", async function () {
        // allow holders of this.projectZero to purchase tokens on this.projectTwo
        await this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(
            this.projectTwo,
            [this.genArt721Core.address],
            [this.projectZero]
          );
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // does allow purchase when holder token in this.projectZero is used as pass
        await expectRevert(
          this.minter
            .connect(this.accounts.additional)
            ["purchase(uint256,address,uint256)"](
              this.projectTwo,
              this.genArt721Core.address,
              this.projectZeroTokenZero.toNumber(),
              {
                value: this.pricePerTokenInWei,
              }
            ),
          "Only owner of NFT"
        );
      });

      it("does not allow purchase when using token of an unallowed project on a different contract", async function () {
        const { pbabToken, pbabMinter } = await deployAndGetPBAB.bind(this)();
        await pbabMinter
          .connect(this.accounts.artist)
          .purchaseTo(this.accounts.additional.address, 0, {
            value: this.pricePerTokenInWei,
          });
        // register the PBAB token on our minter
        await this.minter
          .connect(this.accounts.deployer)
          .registerNFTAddress(pbabToken.address);
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // expect failure when using PBAB token because it is not allowlisted for this.projectTwo
        await expectRevert(
          this.minter
            .connect(this.accounts.additional)
            ["purchase(uint256,address,uint256)"](
              this.projectTwo,
              pbabToken.address,
              0,
              {
                value: this.pricePerTokenInWei,
              }
            ),
          "Only allowlisted NFTs"
        );
      });

      it("does allow purchase when using token of allowed project on a different contract", async function () {
        // deploy different contract (for this case, use PBAB contract)
        const { pbabToken, pbabMinter } = await deployAndGetPBAB.bind(this)();
        await pbabMinter
          .connect(this.accounts.artist)
          .purchaseTo(this.accounts.additional.address, 0, {
            value: this.pricePerTokenInWei,
          });
        // register the PBAB token on our minter
        await this.minter
          .connect(this.accounts.deployer)
          .registerNFTAddress(pbabToken.address);
        // allow holders of PBAB project 0 to purchase tokens on this.projectTwo
        await this.minter
          .connect(this.accounts.artist)
          .allowHoldersOfProjects(this.projectTwo, [pbabToken.address], [0]);
        // configure price per token to be zero
        await this.minter
          .connect(this.accounts.artist)
          .updatePricePerTokenInWei(this.projectTwo, 0);
        // does allow purchase when holder of token in PBAB this.projectZero is used as pass
        await this.minter
          .connect(this.accounts.additional)
          ["purchase(uint256,address,uint256)"](
            this.projectTwo,
            pbabToken.address,
            0,
            {
              value: this.pricePerTokenInWei,
            }
          );
      });
    });

    it("does allow purchase with a price of zero when intentionally configured", async function () {
      // allow holders of this.projectZero to purchase tokens on this.projectTwo
      await this.minter
        .connect(this.accounts.artist)
        .allowHoldersOfProjects(
          this.projectTwo,
          [this.genArt721Core.address],
          [this.projectZero]
        );
      // configure price per token to be zero
      await this.minter
        .connect(this.accounts.artist)
        .updatePricePerTokenInWei(this.projectTwo, 0);
      // allow purchase when intentionally configured price of zero
      await this.minter
        .connect(this.accounts.artist)
        ["purchase(uint256,address,uint256)"](
          this.projectTwo,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber(),
          {
            value: this.pricePerTokenInWei,
          }
        );
    });

    it("auto-configures if setProjectMaxInvocations is not called (fails correctly)", async function () {
      // allow holders of project zero to mint on project one
      await this.minter
        .connect(this.accounts.artist)
        .allowHoldersOfProjects(
          this.projectOne,
          [this.genArt721Core.address],
          [this.projectZero]
        );
      for (let i = 0; i < this.maxInvocations; i++) {
        await this.minter
          .connect(this.accounts.artist)
          ["purchase(uint256,address,uint256)"](
            this.projectOne,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei,
            }
          );
      }

      // since auto-configured, we should see the minter's revert message
      await expectRevert(
        this.minter
          .connect(this.accounts.artist)
          ["purchase(uint256,address,uint256)"](
            this.projectOne,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.pricePerTokenInWei,
            }
          ),
        "Maximum number of invocations reached"
      );
    });

    it("doesnt add too much gas if setProjectMaxInvocations is set", async function () {
      // Try without setProjectMaxInvocations, store gas cost
      const minterType = await this.minter.minterType();
      const accountToTestWith =
        minterType.includes("V0") || minterType.includes("V1")
          ? this.accounts.deployer
          : this.accounts.artist;

      const tx = await this.minter
        .connect(this.accounts.artist)
        ["purchase(uint256,address,uint256)"](
          this.projectZero,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber(),
          {
            value: this.pricePerTokenInWei,
          }
        );

      const receipt = await ethers.provider.getTransactionReceipt(tx.hash);
      let gasCostNoMaxInvocations: any = receipt.effectiveGasPrice
        .mul(receipt.gasUsed)
        .toString();
      gasCostNoMaxInvocations = parseFloat(
        ethers.utils.formatUnits(gasCostNoMaxInvocations, "ether")
      );

      // Try with setProjectMaxInvocations, store gas cost
      await this.minter
        .connect(accountToTestWith)
        .setProjectMaxInvocations(this.projectZero);
      const maxSetTx = await this.minter
        .connect(this.accounts.artist)
        ["purchase(uint256,address,uint256)"](
          this.projectZero,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber(),
          {
            value: this.pricePerTokenInWei,
          }
        );
      const receipt2 = await ethers.provider.getTransactionReceipt(
        maxSetTx.hash
      );
      let gasCostMaxInvocations: any = receipt2.effectiveGasPrice
        .mul(receipt2.gasUsed)
        .toString();
      gasCostMaxInvocations = parseFloat(
        ethers.utils.formatUnits(gasCostMaxInvocations, "ether")
      );

      console.log(
        "Gas cost for a successful mint with setProjectMaxInvocations: ",
        gasCostMaxInvocations.toString(),
        "ETH"
      );
      console.log(
        "Gas cost for a successful mint without setProjectMaxInvocations: ",
        gasCostNoMaxInvocations.toString(),
        "ETH"
      );

      // Check that with setProjectMaxInvocations it's not too much moer expensive
      expect(gasCostMaxInvocations < (gasCostNoMaxInvocations * 110) / 100).to
        .be.true;
    });
  });

  describe("purchaseTo", async function () {
    it("does not allow purchaseTo without NFT ownership args", async function () {
      // expect revert due to price not being configured
      await expectRevert(
        this.minter
          .connect(this.accounts.additional)
          ["purchaseTo(address,uint256)"](
            this.accounts.additional.address,
            this.projectZero,
            {
              value: this.pricePerTokenInWei,
            }
          ),
        "Must claim NFT ownership"
      );
    });

    it("allows `purchaseTo` by default", async function () {
      await this.minter
        .connect(this.accounts.artist)
        ["purchaseTo(address,uint256,address,uint256)"](
          this.accounts.additional.address,
          this.projectZero,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber(),
          {
            value: this.pricePerTokenInWei,
          }
        );
    });

    it("does not support toggling of `purchaseToDisabled`", async function () {
      await expectRevert(
        this.minter
          .connect(this.accounts.artist)
          .togglePurchaseToDisabled(this.projectOne),
        "Action not supported"
      );
      // still allows `purchaseTo`.
      await this.minter
        .connect(this.accounts.artist)
        ["purchaseTo(address,uint256,address,uint256)"](
          this.accounts.additional.address,
          this.projectZero,
          this.genArt721Core.address,
          this.projectZeroTokenZero.toNumber(),
          {
            value: this.pricePerTokenInWei,
          }
        );
    });
  });

  describe("setProjectMaxInvocations", async function () {
    it("handles getting tokenInfo invocation info with V1 core", async function () {
      const minterType = await this.minter.minterType();
      const accountToTestWith =
        minterType.includes("V0") || minterType.includes("V1")
          ? this.accounts.deployer
          : this.accounts.artist;

      await this.minter
        .connect(accountToTestWith)
        .setProjectMaxInvocations(this.projectOne);
      // minter should update storage with accurate this.maxInvocations
      let maxInvocations = await this.minter
        .connect(accountToTestWith)
        .projectMaxInvocations(this.projectOne);
      expect(maxInvocations).to.be.equal(this.maxInvocations);
      // ensure hasMaxBeenReached did not unexpectedly get set as true
      let hasMaxBeenInvoked = await this.minter
        .connect(accountToTestWith)
        .projectMaxHasBeenInvoked(this.projectOne);
      expect(hasMaxBeenInvoked).to.be.false;
    });

    it("reverts for unconfigured/non-existent project", async function () {
      // trying to set this on unconfigured project (e.g. 99) should cause
      // revert on the underlying CoreContract.
      const minterType = await this.minter.minterType();
      const accountToTestWith =
        minterType.includes("V0") || minterType.includes("V1")
          ? this.accounts.deployer
          : this.accounts.artist;

      expectRevert(
        this.minter.connect(accountToTestWith).setProjectMaxInvocations(99),
        "Project ID does not exist"
      );
    });
  });

  describe("registered NFT address enumeration", async function () {
    it("reports expected number of registered NFT addresses after add/remove", async function () {
      const numRegisteredNFTAddresses = await this.minter
        .connect(this.accounts.additional)
        .getNumRegisteredNFTAddresses();
      expect(numRegisteredNFTAddresses).to.be.equal(BigNumber.from("1"));
      // allow a different NFT address
      await this.minter
        .connect(this.accounts.deployer)
        .registerNFTAddress(this.accounts.deployer.address); // dummy address
      // expect number of registered NFT addresses to be increased by one
      const newNumRegisteredNFTAddresses = await this.minter
        .connect(this.accounts.additional)
        .getNumRegisteredNFTAddresses();
      expect(numRegisteredNFTAddresses.add(1)).to.be.equal(
        newNumRegisteredNFTAddresses
      );
      // deny an NFT address
      await this.minter
        .connect(this.accounts.deployer)
        .unregisterNFTAddress(this.accounts.deployer.address);
      // expect number of registered NFT addresses to be increased by one
      const removedNumRegisteredNFTAddresses = await this.minter
        .connect(this.accounts.additional)
        .getNumRegisteredNFTAddresses();
      expect(numRegisteredNFTAddresses).to.be.equal(
        removedNumRegisteredNFTAddresses
      );
    });

    it("gets registered NFT address at index", async function () {
      // register another NFT address
      await this.minter
        .connect(this.accounts.deployer)
        .registerNFTAddress(this.accounts.deployer.address); // dummy address
      // expect NFT address at index zero to be token
      let NFTAddressAtZero = await this.minter
        .connect(this.accounts.additional)
        .getRegisteredNFTAddressAt(0);
      expect(NFTAddressAtZero).to.be.equal(this.genArt721Core.address);
      // expect NFT address at index one to be deployer
      const NFTAddressAtOne = await this.minter
        .connect(this.accounts.additional)
        .getRegisteredNFTAddressAt(1);
      expect(NFTAddressAtOne).to.be.equal(this.accounts.deployer.address);
      // unregister an token NFT address
      await this.minter
        .connect(this.accounts.deployer)
        .unregisterNFTAddress(this.genArt721Core.address);
      // expect NFT address at index zero to be deployer
      NFTAddressAtZero = await this.minter
        .connect(this.accounts.additional)
        .getRegisteredNFTAddressAt(0);
      expect(NFTAddressAtZero).to.be.equal(this.accounts.deployer.address);
    });
  });

  describe("reentrancy attack", async function () {
    it("does not allow reentrant purchaseTo", async function () {
      // attacker deploys reentrancy contract specifically for TokenHolder Merkle
      const reentrancyMockFactory = await ethers.getContractFactory(
        "ReentrancyHolderMock"
      );
      const reentrancyMock = await reentrancyMockFactory
        .connect(this.accounts.deployer)
        .deploy();

      // artist sents token zero of project zero to reentrant contract
      await this.genArt721Core
        .connect(this.accounts.artist)
        .transferFrom(
          this.accounts.artist.address,
          reentrancyMock.address,
          this.projectZeroTokenZero.toNumber()
        );

      // attacker should see revert when performing reentrancy attack
      let totalTokensToMint = 2;
      let numTokensToMint = BigNumber.from(totalTokensToMint.toString());
      let totalValue = this.higherPricePerTokenInWei.mul(numTokensToMint);
      await expectRevert(
        reentrancyMock
          .connect(this.accounts.deployer)
          .attack(
            numTokensToMint,
            this.minter.address,
            this.projectZero,
            this.higherPricePerTokenInWei,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: totalValue,
            }
          ),
        // failure message occurs during refund, where attack reentrency occurs
        "Refund failed"
      );
      // attacker should be able to purchase ONE token w/refunds
      totalTokensToMint = 1;
      numTokensToMint = BigNumber.from("1");
      totalValue = this.higherPricePerTokenInWei.mul(numTokensToMint);
      for (let i = 0; i < totalTokensToMint; i++) {
        await reentrancyMock
          .connect(this.accounts.deployer)
          .attack(
            numTokensToMint,
            this.minter.address,
            this.projectZero,
            this.higherPricePerTokenInWei,
            this.genArt721Core.address,
            this.projectZeroTokenZero.toNumber(),
            {
              value: this.higherPricePerTokenInWei,
            }
          );
      }
    });
  });

  describe("gnosis safe", async function () {
    it("allows gnosis safe to purchase in ETH", async function () {
      // deploy new Gnosis Safe
      const safeSdk: Safe = await getGnosisSafe(
        this.accounts.artist,
        this.accounts.additional,
        this.accounts.user
      );
      const safeAddress = safeSdk.getAddress();

      // artist sents token zero of project zero to safe
      await this.genArt721Core
        .connect(this.accounts.artist)
        .transferFrom(
          this.accounts.artist.address,
          safeAddress,
          this.projectZeroTokenZero.toNumber()
        );

      // create a transaction
      const unsignedTx = await this.minter.populateTransaction[
        "purchase(uint256,address,uint256)"
      ](
        this.projectZero,
        this.genArt721Core.address,
        this.projectZeroTokenZero.toNumber()
      );
      const transaction: SafeTransactionDataPartial = {
        to: this.minter.address,
        data: unsignedTx.data,
        value: this.pricePerTokenInWei.toHexString(),
      };
      const safeTransaction = await safeSdk.createTransaction(transaction);
      // signers sign and execute the transaction
      // artist signs
      await safeSdk.signTransaction(safeTransaction);
      // additional signs
      const ethAdapterOwner2 = new EthersAdapter({
        ethers,
        signer: this.accounts.additional,
      });
      const safeSdk2 = await safeSdk.connect({
        ethAdapter: ethAdapterOwner2,
        safeAddress,
      });
      const txHash = await safeSdk2.getTransactionHash(safeTransaction);
      const approveTxResponse = await safeSdk2.approveTransactionHash(txHash);
      await approveTxResponse.transactionResponse?.wait();
      // fund the safe and execute transaction
      await this.accounts.artist.sendTransaction({
        to: safeAddress,
        value: this.pricePerTokenInWei,
      });

      const viewFunctionWithInvocations = (await isCoreV3(this.genArt721Core))
        ? this.genArt721Core.projectStateData
        : this.genArt721Core.projectTokenInfo;
      const projectStateDataBefore = await viewFunctionWithInvocations(
        this.projectZero
      );
      const executeTxResponse = await safeSdk2.executeTransaction(
        safeTransaction
      );
      await executeTxResponse.transactionResponse?.wait();
      const projectStateDataAfter = await viewFunctionWithInvocations(
        this.projectZero
      );
      expect(projectStateDataAfter.invocations).to.be.equal(
        projectStateDataBefore.invocations.add(1)
      );
    });
  });
};
