const { ethers } = require("hardhat");

async function main() {
  console.log("Deploying VerifiableDBAvs contract...");

  // For a real deployment, replace these with actual EigenLayer addresses
  // These are just placeholder values for the example
  const mockServiceManagerAddress = "0x0000000000000000000000000000000000000001";
  const mockRegistryCoordinatorAddress = "0x0000000000000000000000000000000000000002";

  // Get the contract factory
  const VerifiableDBAvs = await ethers.getContractFactory("VerifiableDBAvs");

  // Deploy the contract
  const verifiableDBAvs = await VerifiableDBAvs.deploy(
    mockServiceManagerAddress,
    mockRegistryCoordinatorAddress
  );

  // Wait for the contract to be deployed
  await verifiableDBAvs.waitForDeployment();

  // Get the deployed contract address
  const contractAddress = await verifiableDBAvs.getAddress();

  console.log(`VerifiableDBAvs deployed to: ${contractAddress}`);
  console.log("Contract details:");
  console.log(`- ServiceManager: ${mockServiceManagerAddress}`);
  console.log(`- RegistryCoordinator: ${mockRegistryCoordinatorAddress}`);
  console.log(`- Version: ${await verifiableDBAvs.VERSION()}`);

  console.log("\nDeployment complete!");

  // For testnets, we can also verify the contract immediately
  if (network.name !== "hardhat" && network.name !== "localhost") {
    console.log("\nVerifying contract on Etherscan...");
    try {
      await run("verify:verify", {
        address: contractAddress,
        constructorArguments: [
          mockServiceManagerAddress,
          mockRegistryCoordinatorAddress,
        ],
      });
      console.log("Contract verified successfully!");
    } catch (error) {
      console.error("Error verifying contract:", error);
    }
  }
}

// Execute the deployment function
main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  }); 