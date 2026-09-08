// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/Htlc.sol";
import "../contracts/MockERC20.sol";

contract HtlcTest is Test {
    Htlc public htlc;
    MockERC20 public token;

    address payable public payer = payable(address(0x1111));
    address payable public payee = payable(address(0x2222));
    address payable public stranger = payable(address(0x3333));

    bytes32 public secret =
        bytes32(
            hex"11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"
        );

    bytes32 public hashlock;

    bytes32 public contractId =
        bytes32(
            hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

    uint64 public refundTimestamp;

    uint256 public constant ETH_AMOUNT = 1 ether;
    uint256 public constant TOKEN_AMOUNT = 1000e18;

    receive() external payable {}

    function setUp() public {
        htlc = new Htlc();
        token = new MockERC20("Test Token", "TEST");

        hashlock = sha256(abi.encodePacked(secret));
        refundTimestamp = uint64(block.timestamp + 3600);

        vm.deal(payer, 100 ether);
        vm.deal(payee, 10 ether);
        vm.deal(stranger, 10 ether);

        token.mint(payer, 10000e18);
    }

    /* -------------------------------------------------------------------------- */
    /*                                1. ETH Lock                                 */
    /* -------------------------------------------------------------------------- */

    function test_Lock_Eth_Success() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        Htlc.Escrow memory e = htlc.getEscrow(contractId);

        assertEq(e.contractId, contractId);
        assertEq(e.payer, payer);
        assertEq(e.payee, payee);
        assertEq(e.token, address(0));
        assertEq(e.amount, ETH_AMOUNT);
        assertEq(e.hashlock, hashlock);
        assertEq(e.refundTimestamp, refundTimestamp);
        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Locked));
        assertEq(address(htlc).balance, ETH_AMOUNT);
    }

    /* -------------------------------------------------------------------------- */
    /*                        2. Claim with Valid Secret                          */
    /* -------------------------------------------------------------------------- */

    function test_Claim_Eth_Success() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        uint256 payeeBalanceBefore = payee.balance;

        // Anyone possessing the valid preimage can submit the claim.
        vm.prank(stranger);
        htlc.claim(contractId, secret);

        assertEq(payee.balance, payeeBalanceBefore + ETH_AMOUNT);
        assertEq(address(htlc).balance, 0);

        Htlc.Escrow memory e = htlc.getEscrow(contractId);
        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Claimed));
    }

    /* -------------------------------------------------------------------------- */
    /*                           3. Wrong Secret Reverts                          */
    /* -------------------------------------------------------------------------- */

    function test_Claim_WrongSecret_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        bytes32 badSecret =
            bytes32(
                hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            );

        vm.expectRevert(Htlc.InvalidSecret.selector);
        htlc.claim(contractId, badSecret);
    }

    /* -------------------------------------------------------------------------- */
    /*                  4. Claim After Refund Deadline Reverts                    */
    /* -------------------------------------------------------------------------- */

    function test_Claim_AfterRefundDeadline_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp + 1);

        vm.expectRevert(Htlc.ClaimTooLate.selector);
        htlc.claim(contractId, secret);
    }

    /* -------------------------------------------------------------------------- */
    /*                    5. Refund Before Deadline Reverts                       */
    /* -------------------------------------------------------------------------- */

    function test_Refund_BeforeDeadline_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp - 1);

        vm.expectRevert(Htlc.RefundTooEarly.selector);
        htlc.refund(contractId);
    }

    /* -------------------------------------------------------------------------- */
    /*                       6. Refund After Deadline Succeeds                    */
    /* -------------------------------------------------------------------------- */

    function test_Refund_AfterDeadline_Succeeds() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        uint256 payerBalanceBefore = payer.balance;

        vm.warp(refundTimestamp + 10);
        htlc.refund(contractId);

        assertEq(payer.balance, payerBalanceBefore + ETH_AMOUNT);
        assertEq(address(htlc).balance, 0);

        Htlc.Escrow memory e = htlc.getEscrow(contractId);
        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Refunded));
    }

    /* -------------------------------------------------------------------------- */
    /*                 7. Duplicate Claim & Duplicate Refund Reverts             */
    /* -------------------------------------------------------------------------- */

    function test_DuplicateClaim_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        htlc.claim(contractId, secret);

        vm.expectRevert(Htlc.NotLocked.selector);
        htlc.claim(contractId, secret);
    }

    function test_DuplicateRefund_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp);
        htlc.refund(contractId);

        vm.expectRevert(Htlc.NotLocked.selector);
        htlc.refund(contractId);
    }

    /* -------------------------------------------------------------------------- */
    /*                   8. Terminal-State Cross Reverts                          */
    /* -------------------------------------------------------------------------- */

    function test_RefundAfterClaim_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        htlc.claim(contractId, secret);

        vm.warp(refundTimestamp + 10);

        vm.expectRevert(Htlc.NotLocked.selector);
        htlc.refund(contractId);
    }

    function test_ClaimAfterRefund_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp);
        htlc.refund(contractId);

        vm.expectRevert(Htlc.NotLocked.selector);
        htlc.claim(contractId, secret);
    }

    /* -------------------------------------------------------------------------- */
    /*                  9. Invalid / Zero-Value Lock Conditions                  */
    /* -------------------------------------------------------------------------- */

    function test_Lock_AlreadyExists_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.prank(payer);

        vm.expectRevert(Htlc.AlreadyExists.selector);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );
    }

    function test_Lock_RefundWindowOpen_Reverts() public {
        vm.warp(refundTimestamp);

        vm.prank(payer);

        vm.expectRevert(Htlc.RefundWindowOpen.selector);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );
    }

    function test_Lock_ZeroAmount_Reverts() public {
        vm.prank(payer);

        vm.expectRevert(Htlc.InvalidAmount.selector);

        htlc.lock{value: 0}(
            contractId,
            payee,
            address(0),
            0,
            hashlock,
            refundTimestamp
        );
    }

    function test_Lock_ZeroAddressPayee_Reverts() public {
        vm.prank(payer);

        vm.expectRevert(Htlc.InvalidPayee.selector);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payable(address(0)),
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );
    }

    function test_Lock_Eth_MismatchedMsgValue_Reverts() public {
        vm.prank(payer);

        vm.expectRevert(Htlc.InvalidAmount.selector);

        htlc.lock{value: ETH_AMOUNT - 1}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );
    }

    /* -------------------------------------------------------------------------- */
    /*              10. Boundary Behavior at Exact refundTimestamp               */
    /* -------------------------------------------------------------------------- */

    function test_Boundary_Claim_At_RefundTimestamp_Minus_1_Succeeds() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp - 1);

        htlc.claim(contractId, secret);

        Htlc.Escrow memory e = htlc.getEscrow(contractId);

        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Claimed));
    }

    function test_Boundary_Claim_At_Exact_RefundTimestamp_Reverts() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp);

        vm.expectRevert(Htlc.ClaimTooLate.selector);
        htlc.claim(contractId, secret);
    }

    function test_Boundary_Refund_At_Exact_RefundTimestamp_Succeeds() public {
        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp);

        htlc.refund(contractId);

        Htlc.Escrow memory e = htlc.getEscrow(contractId);

        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Refunded));
    }

    /* -------------------------------------------------------------------------- */
    /*                       11. ERC-20 Lock / Claim / Refund                     */
    /* -------------------------------------------------------------------------- */

    function test_Erc20_Lock_And_Claim_Success() public {
        vm.startPrank(payer);

        token.approve(address(htlc), TOKEN_AMOUNT);

        htlc.lock(
            contractId,
            payee,
            address(token),
            TOKEN_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.stopPrank();

        assertEq(token.balanceOf(address(htlc)), TOKEN_AMOUNT);

        uint256 payeeTokensBefore = token.balanceOf(payee);

        htlc.claim(contractId, secret);

        assertEq(
            token.balanceOf(payee),
            payeeTokensBefore + TOKEN_AMOUNT
        );

        assertEq(token.balanceOf(address(htlc)), 0);

        Htlc.Escrow memory e = htlc.getEscrow(contractId);

        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Claimed));
    }

    function test_Erc20_Lock_And_Refund_Success() public {
        vm.startPrank(payer);

        token.approve(address(htlc), TOKEN_AMOUNT);

        htlc.lock(
            contractId,
            payee,
            address(token),
            TOKEN_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.stopPrank();

        uint256 payerTokensBefore = token.balanceOf(payer);

        vm.warp(refundTimestamp);

        htlc.refund(contractId);

        assertEq(
            token.balanceOf(payer),
            payerTokensBefore + TOKEN_AMOUNT
        );

        assertEq(token.balanceOf(address(htlc)), 0);

        Htlc.Escrow memory e = htlc.getEscrow(contractId);

        assertEq(uint8(e.status), uint8(Htlc.EscrowStatus.Refunded));
    }

    function test_Erc20_Lock_WithMsgValue_Reverts() public {
        vm.startPrank(payer);

        token.approve(address(htlc), TOKEN_AMOUNT);

        vm.expectRevert(Htlc.InvalidAmount.selector);

        htlc.lock{value: 1 ether}(
            contractId,
            payee,
            address(token),
            TOKEN_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.stopPrank();
    }

    /* -------------------------------------------------------------------------- */
    /*             12. Complete Payer / Payee Accounting Verification             */
    /* -------------------------------------------------------------------------- */

    function test_Accounting_PayerPayee_ETH() public {
        uint256 payerStart = payer.balance;
        uint256 payeeStart = payee.balance;

        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payee,
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        assertEq(payer.balance, payerStart - ETH_AMOUNT);
        assertEq(address(htlc).balance, ETH_AMOUNT);

        htlc.claim(contractId, secret);

        assertEq(payee.balance, payeeStart + ETH_AMOUNT);
        assertEq(payer.balance, payerStart - ETH_AMOUNT);
        assertEq(address(htlc).balance, 0);
    }

    /* -------------------------------------------------------------------------- */
    /*                   13. Malicious ETH Payee Transfer Revert                 */
    /* -------------------------------------------------------------------------- */

    function test_Claim_Eth_MaliciousPayee_Reverts() public {
        MaliciousPayee maliciousPayee = new MaliciousPayee();

        vm.prank(payer);

        htlc.lock{value: ETH_AMOUNT}(
            contractId,
            payable(address(maliciousPayee)),
            address(0),
            ETH_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.expectRevert(Htlc.TransferFailed.selector);

        htlc.claim(contractId, secret);
    }

    /* -------------------------------------------------------------------------- */
    /*             14. Failing ERC-20 transfer() Reverts (Claim & Refund)        */
    /* -------------------------------------------------------------------------- */

    function test_Erc20_TransferFalse_Claim_Reverts() public {
        MockFailingERC20 failingToken = new MockFailingERC20();

        vm.prank(payer);

        htlc.lock(
            contractId,
            payee,
            address(failingToken),
            TOKEN_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.expectRevert(Htlc.TransferFailed.selector);

        htlc.claim(contractId, secret);
    }

    function test_Erc20_TransferFalse_Refund_Reverts() public {
        MockFailingERC20 failingToken = new MockFailingERC20();

        vm.prank(payer);

        htlc.lock(
            contractId,
            payee,
            address(failingToken),
            TOKEN_AMOUNT,
            hashlock,
            refundTimestamp
        );

        vm.warp(refundTimestamp);

        vm.expectRevert(Htlc.TransferFailed.selector);

        htlc.refund(contractId);
    }

    /* -------------------------------------------------------------------------- */
    /*                 15. Fee-On-Transfer ERC20 Lock Accounting                  */
    /* -------------------------------------------------------------------------- */

    function test_Erc20_FeeOnTransfer_Lock_Reverts() public {
        MockFeeOnTransferERC20 feeToken = new MockFeeOnTransferERC20();

        feeToken.mint(payer, TOKEN_AMOUNT);

        vm.prank(payer);
        feeToken.approve(address(htlc), TOKEN_AMOUNT);

        vm.expectRevert(Htlc.TransferFailed.selector);

        vm.prank(payer);
        htlc.lock(
            contractId,
            payee,
            address(feeToken),
            TOKEN_AMOUNT,
            hashlock,
            refundTimestamp
        );
    }
}

/* -------------------------------------------------------------------------- */
/*                         Malicious ETH recipient                            */
/* -------------------------------------------------------------------------- */

contract MaliciousPayee {
    receive() external payable {
        revert();
    }
}

/* -------------------------------------------------------------------------- */
/*                         ERC-20 transfer failure                            */
/* -------------------------------------------------------------------------- */

contract MockFailingERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        if (allowance[from][msg.sender] >= amount) {
            allowance[from][msg.sender] -= amount;
        }
        if (balanceOf[from] >= amount) {
            balanceOf[from] -= amount;
        }
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }
}

/* -------------------------------------------------------------------------- */
/*                      Fee-On-Transfer ERC-20 Mock                           */
/* -------------------------------------------------------------------------- */

contract MockFeeOnTransferERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    uint256 public constant FEE = 100;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(
        address spender,
        uint256 amount
    ) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(balanceOf[from] >= amount, "insufficient balance");
        require(
            allowance[from][msg.sender] >= amount,
            "insufficient allowance"
        );

        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;

        uint256 received = amount - FEE;
        balanceOf[to] += received;

        return true;
    }

    function transfer(
        address to,
        uint256 amount
    ) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");

        balanceOf[msg.sender] -= amount;

        uint256 received = amount - FEE;
        balanceOf[to] += received;

        return true;
    }
}