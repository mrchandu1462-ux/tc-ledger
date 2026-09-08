// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/**
 * @dev Minimal interface for ERC20 token transfers required by HTLC.
 */
interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/**
 * @title Htlc
 * @notice On-chain Hash Time-Locked Contract settlement rail for tclk/1 ("evm-htlc").
 * @dev Enforces single lock per contractId, claim only with SHA-256 preimage strictly
 *      before refundTimestamp, and refund only at or after refundTimestamp.
 */
contract Htlc {
    enum EscrowStatus {
        None,       // 0: Uninitialized
        Locked,     // 1: Funds escrowed
        Claimed,    // 2: Terminal - claimed by payee with secret
        Refunded    // 3: Terminal - refunded to payer after timeout
    }

    struct Escrow {
        bytes32 contractId;     // Binds the off-chain tclk contract ID
        address payable payer;  // Payer address
        address payable payee;  // Payee address
        address token;          // address(0) for native ETH; ERC20 token address otherwise
        uint256 amount;         // Amount in wei / token minimal units
        bytes32 hashlock;       // SHA-256 hash statement
        uint64 refundTimestamp; // Unix seconds UTC
        EscrowStatus status;    // Current lifecycle status
    }

    mapping(bytes32 => Escrow) public escrows;

    event Locked(
        bytes32 indexed contractId,
        address indexed payer,
        address indexed payee,
        address token,
        uint256 amount,
        bytes32 hashlock,
        uint64 refundTimestamp
    );

    event Claimed(bytes32 indexed contractId, bytes32 secret);
    event Refunded(bytes32 indexed contractId);

    error AlreadyExists();
    error NotLocked();
    error RefundWindowOpen();
    error InvalidAmount();
    error InvalidPayee();
    error ClaimTooLate();
    error InvalidSecret();
    error RefundTooEarly();
    error TransferFailed();

    /**
     * @notice Escrow funds under a SHA-256 hashlock and refund timeout.
     * @param contractId Global 32-byte tclk contract ID.
     * @param payee Recipient upon preimage reveal.
     * @param token address(0) for native ETH, ERC20 contract address otherwise.
     * @param amount Amount to escrow.
     * @param hashlock SHA-256 digest of secret.
     * @param refundTimestamp Expiration time in Unix seconds.
     */
    function lock(
        bytes32 contractId,
        address payable payee,
        address token,
        uint256 amount,
        bytes32 hashlock,
        uint64 refundTimestamp
    ) external payable {
        if (escrows[contractId].status != EscrowStatus.None) revert AlreadyExists();
        if (block.timestamp >= refundTimestamp) revert RefundWindowOpen();
        if (amount == 0) revert InvalidAmount();
        if (payee == address(0)) revert InvalidPayee();

        // Checks-Effects
        escrows[contractId] = Escrow({
            contractId: contractId,
            payer: payable(msg.sender),
            payee: payee,
            token: token,
            amount: amount,
            hashlock: hashlock,
            refundTimestamp: refundTimestamp,
            status: EscrowStatus.Locked
        });

        emit Locked(contractId, msg.sender, payee, token, amount, hashlock, refundTimestamp);

        // Interactions
        if (token == address(0)) {
            if (msg.value != amount) revert InvalidAmount();
        } else {
            if (msg.value != 0) revert InvalidAmount();
            uint256 balanceBefore = IERC20(token).balanceOf(address(this));
            bool ok = IERC20(token).transferFrom(msg.sender, address(this), amount);
            if (!ok) revert TransferFailed();
            uint256 balanceAfter = IERC20(token).balanceOf(address(this));
            if (balanceAfter - balanceBefore != amount) revert TransferFailed();
        }
    }

    /**
     * @notice Claim escrowed funds by revealing the SHA-256 preimage.
     * @param contractId Global 32-byte tclk contract ID.
     * @param secret 32-byte preimage such that sha256(secret) == hashlock.
     */
    function claim(bytes32 contractId, bytes32 secret) external {
        Escrow storage escrow = escrows[contractId];
        if (escrow.status != EscrowStatus.Locked) revert NotLocked();
        if (block.timestamp >= escrow.refundTimestamp) revert ClaimTooLate();
        if (sha256(abi.encodePacked(secret)) != escrow.hashlock) revert InvalidSecret();

        // Checks-Effects
        escrow.status = EscrowStatus.Claimed;

        address payable payee = escrow.payee;
        uint256 amount = escrow.amount;
        address token = escrow.token;

        emit Claimed(contractId, secret);

        // Interactions
        if (token == address(0)) {
            (bool ok, ) = payee.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            bool ok = IERC20(token).transfer(payee, amount);
            if (!ok) revert TransferFailed();
        }
    }

    /**
     * @notice Return escrowed funds to payer once the refund deadline has arrived.
     * @param contractId Global 32-byte tclk contract ID.
     */
    function refund(bytes32 contractId) external {
        Escrow storage escrow = escrows[contractId];
        if (escrow.status != EscrowStatus.Locked) revert NotLocked();
        if (block.timestamp < escrow.refundTimestamp) revert RefundTooEarly();

        // Checks-Effects
        escrow.status = EscrowStatus.Refunded;

        address payable payer = escrow.payer;
        uint256 amount = escrow.amount;
        address token = escrow.token;

        emit Refunded(contractId);

        // Interactions
        if (token == address(0)) {
            (bool ok, ) = payer.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            bool ok = IERC20(token).transfer(payer, amount);
            if (!ok) revert TransferFailed();
        }
    }

    /**
     * @notice Read the full escrow details for a given contractId.
     */
    function getEscrow(bytes32 contractId) external view returns (Escrow memory) {
        return escrows[contractId];
    }
}
