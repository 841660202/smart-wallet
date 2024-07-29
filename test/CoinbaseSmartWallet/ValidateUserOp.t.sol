// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "webauthn-sol/../test/Utils.sol";

import {MockEntryPoint} from "../mocks/MockEntryPoint.sol";
import "./SmartWalletTestBase.sol";

contract TestValidateUserOp is SmartWalletTestBase {
    struct _TestTemps {
        bytes32 userOpHash;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 missingAccountFunds;
    }

    // test adapted from Solady
    function test_succeedsWithEOASigner() public {
        _TestTemps memory t;
        t.userOpHash = keccak256("123");
        t.signer = signer;
        t.privateKey = signerPrivateKey;
        (t.v, t.r, t.s) = vm.sign(t.privateKey, t.userOpHash);
        t.missingAccountFunds = 456;
        vm.deal(address(account), 1 ether);
        assertEq(address(account).balance, 1 ether);

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code);
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint()));

        UserOperation memory userOp;
        // Success returns 0.
        userOp.signature = abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(t.r, t.s, t.v)));
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 0);
        assertEq(address(ep).balance, t.missingAccountFunds);
        // Failure returns 1.
        userOp.signature =
            abi.encode(CoinbaseSmartWallet.SignatureWrapper(0, abi.encodePacked(t.r, bytes32(uint256(t.s) ^ 1), t.v)));
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 1);
        assertEq(address(ep).balance, t.missingAccountFunds * 2);
        // Not entry point reverts.
        vm.expectRevert(MultiOwnable.Unauthorized.selector);
        account.validateUserOp(userOp, t.userOpHash, t.missingAccountFunds);
    }
    // 测试使用Passekey签名的成功情况
    function test_succeedsWithPasskeySigner() public {
        _TestTemps memory t; // 定义一个临时变量结构体 t
        t.userOpHash = keccak256("123"); // 计算一个用户操作哈希值
        WebAuthnInfo memory webAuthn = Utils.getWebAuthnStruct(t.userOpHash); // 获取 WebAuthn 结构体

        (bytes32 r, bytes32 s) = vm.signP256(passkeyPrivateKey, webAuthn.messageHash); // 使用 P256 曲线签名
        s = bytes32(Utils.normalizeS(uint256(s))); // 规范化 s 值
        bytes memory sig = abi.encode(
            CoinbaseSmartWallet.SignatureWrapper({
                ownerIndex: 1, // 签名者的索引
                signatureData: abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: webAuthn.authenticatorData, // WebAuthn 验证器数据
                        clientDataJSON: webAuthn.clientDataJSON, // WebAuthn 客户端数据
                        typeIndex: 1, // 类型索引
                        challengeIndex: 23, // 挑战索引
                        r: uint256(r), // 签名的 r 值
                        s: uint256(s) // 签名的 s 值
                    })
                )
            })
        );

        vm.etch(account.entryPoint(), address(new MockEntryPoint()).code); // 使用 MockEntryPoint 替换入口点合约的代码
        MockEntryPoint ep = MockEntryPoint(payable(account.entryPoint())); // 创建 MockEntryPoint 实例

        UserOperation memory userOp; // 定义一个用户操作结构体
        userOp.signature = sig; // 设置用户操作的签名
        assertEq(ep.validateUserOp(address(account), userOp, t.userOpHash, t.missingAccountFunds), 0); // 验证用户操作并断言返回值为 0
    }


    function test_reverts_whenSelectorInvalidForReplayableNonceKey() public {
        UserOperation memory userOp;
        userOp.nonce = 0;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.executeWithoutChainIdValidation.selector, "");
        vm.startPrank(account.entryPoint());
        vm.expectRevert(abi.encodeWithSelector(CoinbaseSmartWallet.InvalidNonceKey.selector, 0));
        account.validateUserOp(userOp, "", 0);
    }

    function test_reverts_whenReplayableNonceKeyInvalidForSelector() public {
        UserOperation memory userOp;
        userOp.nonce = account.REPLAYABLE_NONCE_KEY() << 64;
        userOp.callData = abi.encodeWithSelector(CoinbaseSmartWallet.execute.selector, "");
        vm.startPrank(account.entryPoint());
        vm.expectRevert(
            abi.encodeWithSelector(CoinbaseSmartWallet.InvalidNonceKey.selector, account.REPLAYABLE_NONCE_KEY())
        );
        account.validateUserOp(userOp, "", 0);
    }
}
