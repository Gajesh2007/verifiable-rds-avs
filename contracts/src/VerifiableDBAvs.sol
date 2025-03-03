// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title VerifiableDBAvs
/// @notice Smart contract for a Verifiable Database Autonomous Verifiable Service
/// @dev Implements operator registration, state commitments, and challenge resolution
contract VerifiableDBAvs is Ownable, Pausable, ReentrancyGuard {
    // Version of the contract
    string public constant VERSION = "1.0.0";
    
    // Challenge parameters
    uint256 public challengePeriod = 7 days;
    uint256 public baseChallengeBond = 0.1 ether;
    uint256 public slashAmount = 1 ether;
    uint256 public challengeResolutionWindow = 3 days;
    
    // Challenge type enum - aligned with core module
    enum ChallengeType {
        InvalidStateTransition,
        InvalidTransactionExecution,
        InvalidProof,
        TransactionBoundaryViolation,
        NonDeterministicExecution,
        ResourceExhaustion,
        ProtocolViolation,
        SchemaViolation
    }
    
    // Challenge status enum
    enum ChallengeStatus {
        Active,       // Challenge is active and awaiting resolution
        Resolved,     // Challenge has been resolved
        Expired,      // Challenge period expired without resolution
        Slashed,      // Operator was slashed as a result of the challenge
        Rejected,     // Challenge was rejected (invalid or malicious)
        Withdrawn     // Challenge was withdrawn by the challenger
    }
    
    // State commitment structure
    struct StateCommitment {
        bytes32 stateRoot;             // Merkle root of the database state
        uint256 blockNumber;           // Block number for this state root
        uint256 timestamp;             // Timestamp of the commitment
        address committer;             // Address of the operator who committed this state
        bytes32 previousStateRoot;     // Previous state root
        bytes32 transactionHash;       // Hash of transactions included in this state
        uint256 transactionCount;      // Number of transactions included
        string[] modifiedTables;       // Tables modified in this state update
    }
    
    // Challenge structure
    struct Challenge {
        address challenger;            // Address of the challenger
        address operator;              // Address of the challenged operator
        bytes32 stateRootChallenged;   // State root being challenged
        uint256 blockNumber;           // Block number of the challenged state
        uint256 timestamp;             // Timestamp when challenge was submitted
        uint256 bond;                  // Bond amount placed by challenger
        ChallengeStatus status;        // Current status of the challenge
        ChallengeType challengeType;   // Type of challenge
        bytes32 evidenceHash;          // Hash of evidence for the challenge
        string transactionId;          // UUID of the transaction being challenged (if applicable)
        uint8 priorityLevel;           // Priority level of the challenge (1-3)
        bytes evidence;                // Evidence data for the challenge
        uint256 resolutionDeadline;    // Deadline for resolving this challenge
        bytes32 responseHash;          // Hash of operator's response to challenge
    }
    
    // Operator structure
    struct Operator {
        bool isActive;                 // Whether the operator is active
        uint256 stake;                 // Simulated stake amount (for future EigenLayer integration)
        uint256 lastStateCommitment;   // ID of the last state commitment by this operator
        uint256 successfulCommitments; // Count of successful commitments
        uint256 challengesReceived;    // Count of challenges received
        uint256 challengesLost;        // Count of challenges lost
        bool isFrozen;                 // Whether the operator is currently frozen
    }
    
    // Transaction record for a specific database transaction
    struct TransactionRecord {
        string transactionId;          // UUID of the transaction
        bytes32 preStateRoot;          // State root before transaction
        bytes32 postStateRoot;         // State root after transaction
        address operator;              // Operator who processed this transaction
        uint256 timestamp;             // When the transaction was processed
        uint256 gasUsed;               // Computational resources used
        string[] modifiedTables;       // Tables modified in this transaction
        bool isVerified;               // Whether this transaction has been verified
    }
    
    // Mappings
    mapping(uint256 => StateCommitment) public stateCommitments;
    mapping(uint256 => Challenge) public challenges;
    mapping(address => Operator) public operators;
    mapping(string => TransactionRecord) public transactions;
    mapping(address => uint256[]) public operatorStateCommitments;
    mapping(address => uint256[]) public operatorChallenges;
    mapping(bytes32 => bool) public stateRootExists;
    
    // Counters
    uint256 public nextStateCommitmentId = 1;
    uint256 public nextChallengeId = 1;
    uint256 public totalOperators = 0;
    uint256 public totalChallenges = 0;
    uint256 public totalResolvedChallenges = 0;
    uint256 public totalSlashedOperators = 0;
    
    // Events
    event OperatorRegistered(address indexed operator);
    event OperatorDeregistered(address indexed operator);
    event OperatorFrozen(address indexed operator);
    event OperatorUnfrozen(address indexed operator);
    event StateCommitted(uint256 indexed commitmentId, bytes32 stateRoot, uint256 blockNumber, address committer, string[] modifiedTables);
    event TransactionRecorded(string indexed transactionId, bytes32 preStateRoot, bytes32 postStateRoot, address operator);
    event ChallengeSubmitted(uint256 indexed challengeId, address challenger, address operator, ChallengeType challengeType, bytes32 stateRoot, uint256 blockNumber);
    event ChallengeResolved(uint256 indexed challengeId, ChallengeStatus status, address winner);
    event ChallengeResponseSubmitted(uint256 indexed challengeId, address operator, bytes32 responseHash);
    event ChallengeWithdrawn(uint256 indexed challengeId, address challenger);
    event ChallengeParametersUpdated(uint256 challengePeriod, uint256 baseChallengeBond, uint256 slashAmount);
    event DeterministicFunctionVerified(string functionName, string transactionId, bool isValid);
    
    constructor() Ownable(msg.sender) {
    }
    
    /// @notice Register an address as an operator
    function registerOperator(address _operator) external onlyOwner whenNotPaused {
        require(operators[_operator].isActive == false, "Operator already registered");
        
        // Store operator data
        operators[_operator] = Operator({
            isActive: true,
            stake: 100 ether, // Placeholder stake amount
            lastStateCommitment: 0,
            successfulCommitments: 0,
            challengesReceived: 0,
            challengesLost: 0,
            isFrozen: false
        });
        
        totalOperators++;
        emit OperatorRegistered(_operator);
    }
    
    /// @notice Deregister an operator
    function deregisterOperator(address _operator) external onlyOwner {
        require(operators[_operator].isActive == true, "Operator not registered");
        require(operators[_operator].isFrozen == false, "Operator is frozen");
        
        // Deactivate operator
        operators[_operator].isActive = false;
        
        totalOperators--;
        emit OperatorDeregistered(_operator);
    }
    
    /// @notice Freeze an operator - can only be done by owner
    function freezeOperator(address _operator) external onlyOwner {
        require(operators[_operator].isActive == true, "Operator not active");
        require(operators[_operator].isFrozen == false, "Operator already frozen");
        
        operators[_operator].isFrozen = true;
        
        emit OperatorFrozen(_operator);
    }
    
    /// @notice Unfreeze an operator - can only be done by owner
    function unfreezeOperator(address _operator) external onlyOwner {
        require(operators[_operator].isActive == true, "Operator not active");
        require(operators[_operator].isFrozen == true, "Operator not frozen");
        
        operators[_operator].isFrozen = false;
        
        emit OperatorUnfrozen(_operator);
    }
    
    /// @notice Commit a state root to the contract
    /// @param _stateRoot The state root to commit
    /// @param _blockNumber The block number for this state root
    /// @param _previousStateRoot Previous state root
    /// @param _transactionHash Hash of transactions included in this state
    /// @param _transactionCount Number of transactions included
    /// @param _modifiedTables Names of tables modified in this state update
    function commitState(
        bytes32 _stateRoot,
        uint256 _blockNumber,
        bytes32 _previousStateRoot,
        bytes32 _transactionHash,
        uint256 _transactionCount,
        string[] calldata _modifiedTables
    ) external whenNotPaused nonReentrant {
        require(isRegisteredOperator(msg.sender), "Only registered operators can commit state");
        require(!operators[msg.sender].isFrozen, "Frozen operators cannot commit state");
        require(_blockNumber <= block.number, "Cannot commit future state");
        require(!stateRootExists[_stateRoot], "State root already exists");
        
        // Store commitment
        uint256 commitmentId = nextStateCommitmentId++;
        stateCommitments[commitmentId] = StateCommitment({
            stateRoot: _stateRoot,
            blockNumber: _blockNumber,
            timestamp: block.timestamp,
            committer: msg.sender,
            previousStateRoot: _previousStateRoot,
            transactionHash: _transactionHash,
            transactionCount: _transactionCount,
            modifiedTables: _modifiedTables
        });
        
        // Update operator data
        operators[msg.sender].lastStateCommitment = commitmentId;
        operators[msg.sender].successfulCommitments++;
        operatorStateCommitments[msg.sender].push(commitmentId);
        
        // Mark this state root as existing
        stateRootExists[_stateRoot] = true;
        
        emit StateCommitted(commitmentId, _stateRoot, _blockNumber, msg.sender, _modifiedTables);
    }
    
    /// @notice Record a transaction
    /// @param _transactionId UUID of the transaction
    /// @param _preStateRoot State root before transaction
    /// @param _postStateRoot State root after transaction
    /// @param _modifiedTables Tables modified in this transaction
    function recordTransaction(
        string calldata _transactionId,
        bytes32 _preStateRoot,
        bytes32 _postStateRoot,
        string[] calldata _modifiedTables
    ) external whenNotPaused nonReentrant {
        require(isRegisteredOperator(msg.sender), "Only registered operators can record transactions");
        require(!operators[msg.sender].isFrozen, "Frozen operators cannot record transactions");
        
        // Store transaction record
        transactions[_transactionId] = TransactionRecord({
            transactionId: _transactionId,
            preStateRoot: _preStateRoot,
            postStateRoot: _postStateRoot,
            operator: msg.sender,
            timestamp: block.timestamp,
            gasUsed: 0, // Could track actual gas in a real implementation
            modifiedTables: _modifiedTables,
            isVerified: false
        });
        
        emit TransactionRecorded(_transactionId, _preStateRoot, _postStateRoot, msg.sender);
    }
    
    /// @notice Calculate the required bond for a challenge based on challenge type
    /// @param _challengeType The type of challenge
    /// @param _priorityLevel Priority level of the challenge (1-3)
    /// @return The bond amount required
    function calculateChallengeBond(ChallengeType _challengeType, uint8 _priorityLevel) public view returns (uint256) {
        // Base bond amount depends on challenge type
        uint256 typeBond;
        if (_challengeType == ChallengeType.InvalidStateTransition) {
            typeBond = baseChallengeBond * 2;
        } else if (_challengeType == ChallengeType.NonDeterministicExecution) {
            typeBond = baseChallengeBond * 15 / 10; // 1.5x
        } else {
            typeBond = baseChallengeBond;
        }
        
        // Adjust for priority level (higher priority = higher bond)
        return typeBond * uint256(_priorityLevel);
    }
    
    /// @notice Submit a challenge against a state commitment
    /// @param _commitmentId The ID of the state commitment to challenge
    /// @param _challengeType The type of challenge
    /// @param _evidenceHash Hash of evidence for the challenge
    /// @param _transactionId UUID of the transaction being challenged (if applicable)
    /// @param _priorityLevel Priority level (1-3)
    /// @param _evidence Evidence data for the challenge
    function submitChallenge(
        uint256 _commitmentId,
        ChallengeType _challengeType,
        bytes32 _evidenceHash,
        string calldata _transactionId,
        uint8 _priorityLevel,
        bytes calldata _evidence
    ) external payable whenNotPaused nonReentrant {
        require(_priorityLevel >= 1 && _priorityLevel <= 3, "Invalid priority level");
        uint256 requiredBond = calculateChallengeBond(_challengeType, _priorityLevel);
        require(msg.value >= requiredBond, "Insufficient bond");
        
        StateCommitment memory commitment = stateCommitments[_commitmentId];
        require(commitment.timestamp > 0, "State commitment does not exist");
        require(block.timestamp <= commitment.timestamp + challengePeriod, "Challenge period expired");
        
        // Create challenge
        uint256 challengeId = nextChallengeId++;
        challenges[challengeId] = Challenge({
            challenger: msg.sender,
            operator: commitment.committer,
            stateRootChallenged: commitment.stateRoot,
            blockNumber: commitment.blockNumber,
            timestamp: block.timestamp,
            bond: msg.value,
            status: ChallengeStatus.Active,
            challengeType: _challengeType,
            evidenceHash: _evidenceHash,
            transactionId: _transactionId,
            priorityLevel: _priorityLevel,
            evidence: _evidence,
            resolutionDeadline: block.timestamp + challengeResolutionWindow,
            responseHash: bytes32(0)
        });
        
        // Update operator data
        operators[commitment.committer].challengesReceived++;
        operatorChallenges[commitment.committer].push(challengeId);
        
        totalChallenges++;
        
        emit ChallengeSubmitted(
            challengeId, 
            msg.sender, 
            commitment.committer, 
            _challengeType, 
            commitment.stateRoot, 
            commitment.blockNumber
        );
    }
    
    /// @notice Respond to a challenge
    /// @param _challengeId The ID of the challenge to respond to
    /// @param _responseHash Hash of the operator's response to the challenge
    function respondToChallenge(uint256 _challengeId, bytes32 _responseHash) external whenNotPaused nonReentrant {
        Challenge storage challenge = challenges[_challengeId];
        require(challenge.timestamp > 0, "Challenge does not exist");
        require(challenge.status == ChallengeStatus.Active, "Challenge is not active");
        require(challenge.operator == msg.sender, "Only challenged operator can respond");
        require(block.timestamp <= challenge.resolutionDeadline, "Resolution deadline passed");
        
        challenge.responseHash = _responseHash;
        
        emit ChallengeResponseSubmitted(_challengeId, msg.sender, _responseHash);
    }
    
    /// @notice Resolve a challenge
    /// @param _challengeId The ID of the challenge to resolve
    /// @param _isValid Whether the challenge is valid
    function resolveChallenge(uint256 _challengeId, bool _isValid) external onlyOwner nonReentrant {
        Challenge storage challenge = challenges[_challengeId];
        require(challenge.timestamp > 0, "Challenge does not exist");
        require(challenge.status == ChallengeStatus.Active, "Challenge is not active");
        
        address winner;
        
        if (_isValid) {
            // Challenge is valid - slash the operator
            challenge.status = ChallengeStatus.Slashed;
            operators[challenge.operator].challengesLost++;
            operators[challenge.operator].isFrozen = true;
            totalSlashedOperators++;
            
            // Reward the challenger with their bond back plus reward
            uint256 reward = challenge.bond + slashAmount;
            
            // Use try/catch to handle transfer failures
            try this.sendReward(challenge.challenger, reward) {
                winner = challenge.challenger;
            } catch {
                // If transfer fails, keep the funds in the contract
                winner = challenge.challenger;
            }
        } else {
            // Challenge is invalid - return bond to operator
            challenge.status = ChallengeStatus.Rejected;
            
            // Use try/catch to handle transfer failures
            try this.sendReward(challenge.operator, challenge.bond) {
                winner = challenge.operator;
            } catch {
                // If transfer fails, keep the funds in the contract
                winner = challenge.operator;
            }
        }
        
        totalResolvedChallenges++;
        
        emit ChallengeResolved(_challengeId, challenge.status, winner);
    }
    
    /// @notice Helper function to send rewards (used for try/catch)
    /// @param _recipient The address to send the reward to
    /// @param _amount The amount to send
    function sendReward(address _recipient, uint256 _amount) external payable {
        require(msg.sender == address(this), "Only contract can call");
        (bool success, ) = _recipient.call{value: _amount}("");
        require(success, "Reward transfer failed");
    }
    
    /// @notice Withdraw a challenge
    /// @param _challengeId The ID of the challenge to withdraw
    function withdrawChallenge(uint256 _challengeId) external nonReentrant {
        Challenge storage challenge = challenges[_challengeId];
        require(challenge.timestamp > 0, "Challenge does not exist");
        require(challenge.status == ChallengeStatus.Active, "Challenge is not active");
        require(challenge.challenger == msg.sender, "Only challenger can withdraw");
        
        // Mark as withdrawn
        challenge.status = ChallengeStatus.Withdrawn;
        
        // Return half of the bond as penalty for withdrawing
        uint256 returnAmount = challenge.bond / 2;
        (bool success, ) = msg.sender.call{value: returnAmount}("");
        require(success, "Bond return failed");
        
        totalResolvedChallenges++;
        
        emit ChallengeWithdrawn(_challengeId, msg.sender);
    }
    
    /// @notice Verify deterministic function execution
    /// @param _functionName Name of the deterministic function
    /// @param _transactionId UUID of the transaction
    /// @param _isValid Whether the function execution is valid
    function verifyDeterministicFunction(
        string calldata _functionName,
        string calldata _transactionId,
        bool _isValid
    ) external onlyOwner whenNotPaused {
        emit DeterministicFunctionVerified(_functionName, _transactionId, _isValid);
    }
    
    /// @notice Update challenge parameters
    /// @param _challengePeriod New challenge period in seconds
    /// @param _baseChallengeBond New base challenge bond in wei
    /// @param _slashAmount New slash amount in wei
    /// @param _challengeResolutionWindow New challenge resolution window in seconds
    function updateChallengeParameters(
        uint256 _challengePeriod,
        uint256 _baseChallengeBond,
        uint256 _slashAmount,
        uint256 _challengeResolutionWindow
    ) external onlyOwner {
        challengePeriod = _challengePeriod;
        baseChallengeBond = _baseChallengeBond;
        slashAmount = _slashAmount;
        challengeResolutionWindow = _challengeResolutionWindow;
        
        emit ChallengeParametersUpdated(_challengePeriod, _baseChallengeBond, _slashAmount);
    }
    
    /// @notice Check if an address is a registered operator
    /// @param _operator The address to check
    /// @return Whether the address is a registered and active operator
    function isRegisteredOperator(address _operator) public view returns (bool) {
        return operators[_operator].isActive && !operators[_operator].isFrozen;
    }
    
    /// @notice Get operator information
    /// @param _operator The address of the operator
    /// @return isActive Whether the operator is active
    /// @return isFrozen Whether the operator is frozen
    /// @return challengesReceived Number of challenges received
    /// @return challengesLost Number of challenges lost
    function getOperator(address _operator) external view returns (
        bool isActive,
        bool isFrozen,
        uint256 challengesReceived,
        uint256 challengesLost
    ) {
        Operator memory op = operators[_operator];
        return (
            op.isActive,
            op.isFrozen,
            op.challengesReceived,
            op.challengesLost
        );
    }
    
    /// @notice Get the list of state commitments by an operator
    /// @param _operator The address of the operator
    /// @return Array of commitment IDs by the operator
    function getOperatorStateCommitments(address _operator) external view returns (uint256[] memory) {
        return operatorStateCommitments[_operator];
    }
    
    /// @notice Get the list of challenges for an operator
    /// @param _operator The address of the operator
    /// @return Array of challenge IDs for the operator
    function getOperatorChallenges(address _operator) external view returns (uint256[] memory) {
        return operatorChallenges[_operator];
    }
    
    /// Get transaction details
    function getTransaction(string calldata _transactionId) external view returns (TransactionRecord memory) {
        return transactions[_transactionId];
    }
    
    /// Get challenge details
    function getChallenge(uint256 _challengeId) external view returns (Challenge memory) {
        return challenges[_challengeId];
    }
    
    /// Get state commitment details
    function getStateCommitment(uint256 _commitmentId) external view returns (StateCommitment memory) {
        return stateCommitments[_commitmentId];
    }
    
    /// Pause the contract
    function pause() external onlyOwner {
        _pause();
    }
    
    /// Unpause the contract
    function unpause() external onlyOwner {
        _unpause();
    }
    
    // Receive function to accept ETH
    receive() external payable {}
} 