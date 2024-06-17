# Deployments: EngineFactoryV0

## Description

The keyless create2 factory was used to deterministically deploy the EngineFactoryV0, permissioned to deployer wallet 0x00df4E8d293d57718aac0B18cBfBE128c5d484Ef.

_Note: The EngineFactoryV0 is intentionally deployed to different addresses on different networks/environments, due to unique constructor args._

The following were the inputs used to get initcode for deployment, via `scripts/get-init-code.ts`:

```typescript
const inputs: T_Inputs = {
  contractName: "EngineFactoryV0",
  args: [
    "0x00000000559cA3F3f1279C0ec121c302ed010457", // engine
    "0x000000008DD9A7CD3f4A267A88082d4a1E2f6553", // flex
    "0xdAe755c2944Ec125a0D8D5CB082c22837593441a", // core registry
    "0x62DC3F6C7Bf5FA8A834E6B97dee3daB082873600", // owner of this factory
    "https://token.sepolia.artblocks.io/", // token uri host
    "0x000000069EbaecF0d656897bA5527f2145560086", // universal bytecode
  ],
  libraries: {},
};
```

## Results:

salt: `0x00df4e8d293d57718aac0b18cbfbe128c5d484ef46561b3672b68dad50000000`
Deployed to address: `0x0000A9AA9b00F46c009f15b3F68122e1878D7d18`

### Deployment transactions:

- https://sepolia.etherscan.io/tx/
