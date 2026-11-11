# Group OSCORE 成员身份验证测试报告（aiocoap 0.4.17.post0）

日期：2026-11-11
测试脚本：`group-oscore-identity-check.py`（工作区根目录，可直接 `python3` 运行复现）

## 场景

一个 OSCORE 组（group id `G`），三名成员，均为 Ed25519 签名密钥对 + ECDH-SS/HKDF-256
pairwise 密钥协商，AEAD 为 AES-CCM-16-64-128：

| 成员 | kid | 标识 |
|------|-----|------|
| server | （空） | 公钥 SHA-256 指纹（截断） |
| alice | `01` | 同上 |
| bob | `02` | 同上 |

未输出任何私钥；报告中成员仅以 kid 和公钥指纹标识。

- 合法成员：alice、bob（均持有完整共享组材料：master secret/salt 派生密钥、common IV、
  签名加密密钥）。
- 被冒用身份：alice。冒用者是**组内成员 bob**——这是最强情形：攻击者持有全部共享组
  材料，只缺 alice 的私钥。
- 接收路径完全复刻 `OscoreSiteWrapper.render_to_pipe` 的安全门：`verify_start` →
  `find_oscore`（按 kid 选上下文）→ `unprotect`，成功才计入"交给应用"。
- 所有篡改均**保留密文主体不变**，只替换 kid、成员认证凭据或签名。

## 实测结果（20/20 通过）

| # | 检查 | 结果 |
|---|------|------|
| T0 | alice 真实 group 请求被交付，alice 重放窗口更新 | PASS |
| T1 | 替换 kid（alice 密文改标 bob 的 kid）→ `ProtectionInvalid` 拒绝 | PASS |
| T2a | bob 伪造包（kid=alice，bob 签名）**用共享组材料可正常解密**出明文 | PASS |
| T2b | 同一伪造包被服务器拒绝：alice 的 countersignature 验签失败 | PASS |
| T3 | 把服务器上 alice 的登记凭据换成 bob 的后，**同一伪造包被接受** | PASS（受控演示） |
| T4a/b | 翻转签名位 / 密文位 → 均拒绝 | PASS |
| T5 | 非成员 kid → 上下文查找即拒绝（4.01 路径） | PASS |
| T6 | 伪造包之后 alice 同序列号真实包仍被接受（序列号未被消耗） | PASS |
| T7 | 重放 alice 真实包 → 拒绝，窗口不变（但见下方缺陷） | PASS |
| T8 | 针对 alice 的全部攻击后，bob 正常通信不受影响 | PASS |
| T9a | alice 真实 pairwise 请求被交付 | PASS |
| T9b | pairwise 包替换 kid → 派生密钥不同，AEAD 拒绝 | PASS |
| T9c | bob 伪造 alice 的 pairwise 包（缺 ECDH 私钥）→ AEAD 拒绝 | PASS |
| T10a/b | group 请求的响应**切到 pairwise 上下文**、无 countersignature 位 | PASS |
| T10c | alice 验过 pairwise 响应 | PASS |
| T10d | 响应密文被翻转 → alice 拒绝 | PASS |
| T10e | bob 无法解开发给 alice 的 pairwise 响应 | PASS |
| T10f | pairwise 请求 → pairwise 响应全链路正常 | PASS |

每一次失败包前后，alice 与 bob 的重放窗口状态（`ReplayWindow.persist()`）逐位一致；
应用层只收到 7 条消息，其中唯一一条伪造包（`forged-by-bob-as-alice`）是在 T3 **故意
破坏服务器端凭据绑定**的受控演示中被交付的，凭据恢复后同类包再次被拒。

## 结论：两类材料各自提供什么保证

**共享组材料（master secret 派生的各 sender key、common IV、签名加密密钥）**

- 提供机密性与 AEAD 完整性，但只界定"持有组材料的某人"。T2a 实测：组内成员 bob 能对
  任意 kid 派生出对应 sender key，产生**完全合法、可解密**的密文——"包能解密"丝毫不
  说明发送者是谁。

**成员身份材料**

- group 模式：发送者的 countersignature 私钥 + 验证方登记的 `(kid → 成员认证凭据)`
  绑定。T2b：bob 冒用 alice 的 kid，验签用 alice 的登记公钥 → 拒绝。T3：一旦该绑定
  被替换（GM/配置层面被攻陷或误配），同一伪造包立即被接受——**身份保证完全来自这条
  凭据绑定，而非组材料**。
- pairwise 模式：ECDH 静态-静态共享秘密（需通信双方任一私钥）与双方凭据一起进入
  KDF。T9c：组内成员没有 alice 或 server 的私钥就无法推出 alice↔server 的 pairwise
  密钥；T10e：响应也绑定到指定对端，第三方组成员解不开。
- 响应路径：group 请求的响应按 RFC 8613 切到 pairwise 模式（T10a/b 实测
  `context_for_response()` 返回 `_PairwiseContextAspect`，OSCORE 选项无签名位），即
  **响应的身份保证来自 pairwise AEAD 密钥而非签名**；pairwise 请求的响应同理。

**重放状态与交付顺序**

- aiocoap 的 `unprotect` 顺序为：验签 → AEAD 解密 → 解密后检查 → `strike_out` 重放
  窗口 → 才构造明文消息返回。因此只有完整通过成员身份认证的包才会更新该成员的重放
  状态或到达应用层；T1–T9 的所有失败包对两个成员的窗口均零影响，且不消耗序列号
  （T6）、不干扰另一成员（T8）。

## 顺带发现的 aiocoap 缺陷（健壮性，非绕过）

`_GroupContextAspect` 与 `_PairwiseContextAspect` 未定义 `echo_recovery` 属性
（仅 `FilesystemSecurityContext` 与 deterministic aspect 有）。当 group/pairwise 包
命中重放检查时，`unprotect` 在访问 `self.echo_recovery` 处抛出 `AttributeError`，
而非预期的 `ReplayError`（aiocoap/oscore.py:1296）。`OscoreSiteWrapper` 只捕获
`ReplayError`/`DecodeError`/`ProtectionInvalid`，该异常会向上逃逸（可能表现为 5.02
或连接级错误而非 4.01 "Replay detected"）。**安全语义未被破坏**：包仍被拒绝、重放
状态不更新、不交付应用；但错误处理路径不符合预期，建议为两个 aspect 增加
`echo_recovery = None` 类属性。

## 环境限制

`tests/test_group_oscore.py` 的 30 个既有用例依赖 UDP 环回 socket，本沙箱禁止绑定
本地端口（`PermissionError: [Errno 1] Operation not permitted`），全部因此失败，与
本场景无关。本报告场景在 CoAP 线格式（wire bytes）层面直接驱动 aiocoap 的
protect/unprotect 真实代码路径，不依赖 socket。如需在本机跑通既有测试套件，需在
沙箱设置中允许 `sandbox.network.allowLocalBinding: true`。
