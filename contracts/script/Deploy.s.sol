// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../src/VerifiableDBAvs.sol";

contract DeployVerifiableDBAvs is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        console.log("Deploying VerifiableDBAvs contract...");
        
        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);
        
        // Deploy the VerifiableDBAvs contract
        VerifiableDBAvs avs = new VerifiableDBAvs();
        
        // Register initial operators if specified
        address[] memory initialOperators = getInitialOperators();
        if (initialOperators.length > 0) {
            console.log("Registering initial operators...");
            for (uint i = 0; i < initialOperators.length; i++) {
                avs.registerOperator(initialOperators[i]);
                console.log("Registered operator:", initialOperators[i]);
            }
        }
        
        // Configure challenge parameters if environment variables are provided
        bool configureParams = vm.envBool("CONFIGURE_PARAMETERS");
        if (configureParams) {
            console.log("Configuring challenge parameters...");
            
            uint256 challengePeriod = vm.envUint("CHALLENGE_PERIOD");
            uint256 baseChallengeBond = vm.envUint("BASE_CHALLENGE_BOND");
            uint256 slashAmount = vm.envUint("SLASH_AMOUNT");
            uint256 challengeResolutionWindow = vm.envUint("CHALLENGE_RESOLUTION_WINDOW");
            
            avs.updateChallengeParameters(
                challengePeriod,
                baseChallengeBond,
                slashAmount,
                challengeResolutionWindow
            );
            
            console.log("Challenge parameters configured:");
            console.log("  Challenge period:", challengePeriod);
            console.log("  Base challenge bond:", baseChallengeBond);
            console.log("  Slash amount:", slashAmount);
            console.log("  Resolution window:", challengeResolutionWindow);
        }
        
        // Stop broadcasting transactions
        vm.stopBroadcast();
        
        console.log("VerifiableDBAvs deployed at:", address(avs));
        console.log("VerifiableDBAvs version:", avs.VERSION());
    }
    
    function getInitialOperators() internal view returns (address[] memory) {
        string memory operatorsEnv = vm.envString("INITIAL_OPERATORS");
        if (bytes(operatorsEnv).length == 0) {
            return new address[](0);
        }
        
        // Parse comma-separated addresses
        bytes memory operatorsBytes = bytes(operatorsEnv);
        uint operatorCount = 1;
        for (uint i = 0; i < operatorsBytes.length; i++) {
            if (operatorsBytes[i] == ',') {
                operatorCount++;
            }
        }
        
        address[] memory operators = new address[](operatorCount);
        
        uint currentIndex = 0;
        uint lastCommaIndex = 0;
        for (uint i = 0; i < operatorsBytes.length; i++) {
            if (operatorsBytes[i] == ',' || i == operatorsBytes.length - 1) {
                uint endIndex = i;
                if (i == operatorsBytes.length - 1) {
                    endIndex = i + 1;
                }
                
                bytes memory addressBytes = new bytes(endIndex - lastCommaIndex);
                for (uint j = lastCommaIndex; j < endIndex; j++) {
                    addressBytes[j - lastCommaIndex] = operatorsBytes[j];
                }
                
                string memory addressStr = string(addressBytes);
                operators[currentIndex] = vm.parseAddress(addressStr);
                
                currentIndex++;
                lastCommaIndex = i + 1;
            }
        }
        
        return operators;
    }
} 