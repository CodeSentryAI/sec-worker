# HANDOFF — Chain Fox scan pipeline: sec-worker + slither-rs

状态快照: 2026-10-01。接手前先读本文件，再读两份 README（本目录与
`~/Projects/BW2/slither-rs/README.md`——后者含 oracle 契约与 R4.1 表）。
本文件是唯一权威的"现在在哪 / 为什么 / 下一步"。

## 0. 三个仓库各是什么

| 路径 | 角色 | git |
|---|---|---|
| `~/Projects/BW2/chain-fox-frontend-dao` | VPS 控制面（React + Express/TS + SQLite；x402/Stripe 收费、quote/job 生命周期）。**与本轮工作无关，勿动** | 有远程 |
| `~/Projects/BW2/sec-worker` | bwrap 沙箱 worker + 检测器（lockbud-stable、peCatch）+ **slither-oracle**（冻结语义快照）+ **bench**（A/B/C 成本测量） | git 已管理（initial commit 00edc85；大 corpus oracle 体 gitignored，字节可复现，见 .gitignore 注释） |
| `~/Projects/BW2/slither-rs` | Rust 语义核（R4.1：solc AST → arena 模型 → CFG → direct facts），differential 对抗 oracle | git 已管理（initial commit de0e922，/target ignored） |

## 1. 环境事实（踩过坑的）

- WSL2 Ubuntu 24.04。**github.com 被墙**；pypi / crates.io(index+static) / static.rust-lang.org / binaries.soliditylang.org / registry.npmjs.org 可达。
- 无免密 sudo。python3-venv/python3-dev 缺失 → venv 用 `virtualenv --user` 或 `venv --without-pip` + get-pip。
- 工具链（勿重复安装）：
  - `~/sec-toolchains/venv-pecatch` — slither **0.9.1** + peCatch 插件（worker 用）。装法见 `bootstrap/install-toolchains.sh`（setuptools<81、safe-pysha3 + pysha3 stub、peCatch 必须 editable）。
  - `~/sec-toolchains/venv-bench` — slither **0.11.6**（oracle/bench 用）。
  - solc 缓存 `~/.solc-select/artifacts/`：0.5.16 0.6.12 0.7.6 0.8.4 0.8.15 0.8.17 0.8.18 0.8.20 0.8.26 0.8.28。
  - node v20 via nvm（非交互 shell 需 `export PATH="$HOME/.nvm/versions/node/v20.19.5/bin:$PATH"`）；cargo nightly 默认。
- bwrap 0.9 已装；WSL 内核无 AppArmor userns 限制；usrmerge → bwrap 里要 `/usr/bin→/bin` 等别名绑（见 `sec-worker/src/sandbox/bwrap.ts`）。
- slither-as-library 两个关键 incantation：缓存 = pickle `CryticCompile`（`compile_force_framework="Solc-json"` + `solc_args="--allow-paths <root>"` + cwd=repo root）；库模式 detectors 为零，必须手动注册 `slither.detectors.all_detectors`。

## 2. 当前 gate 状态（诚实版）

### G0–G6 阶梯（sec-worker tests/，`npm test` 现状 10/10 PASS）

```
G0 manifest        PASS   bench/oracle/fixture-manifest.json（7 success + seadrop/seaport compile_failure）
G1 model.json      PASS   全部 7 个 fixture IDENTICAL
G2 cfg.json        OPEN   gas-toy 0/0/0 ✅；syntax-zoo 剩 ~5 个 detail-case；大 repo 未收
G3 analysis.json   BLOCKED（等 G2）
G4 effects         BLOCKED（等 G2）
G5 determinism+ids PASS   oracle/Rust 双跑 byte-identical；scoped ID 唯一性
G6 syntax-zoo      BLOCKED（13→9/14 IDENTICAL，见 tests/r41-syntax-zoo.test.ts 的 EXPECTED_OPEN）
```

### slither-rs vs oracle 实测差异（修复测量管道后的真实数字）

gas-toy **0/0/0**；zoo 9/14 函数全等；v2-core/v3-core/solmate/OZ 尚有
百~万级 cfg diffs —— 主因是 while/try/modifier 细节与 expression-detail，
不是模型结构错误。

### 性能基线（debug build，AST→model→CFG→emit）

v2-core 77ms/14MB · v3-core 499ms/66MB · solmate 1.1s/163MB · OZ 2.2s/198MB
（Python 对照 0.24s/61MB → 13.5s/729MB）。phase 边界不对称，
**speedup 结论等对称 benchmark 之后再下**（用户明确要求）。

## 3. 本轮刚落地的修复（接手者需要知道的上下文）

1. **跨函数变量污染**（大坑）：`var_index` 曾把所有函数的 params/returns/locals
   chain 进同一张 name 表 → continueCase 的命名返回 `acc`@2555 污染 breakCase。
   已改为 state-only + 每函数注册（main.rs "State variables only" 注释处）。
2. **新降级**：DoWhile（STARTLOOP→body→IFLOOP，true 回 body head）、
   Try/Catch（TRY 携带 external call，每 clause 一个 CATCH，clause.tail 全部
   流向 implicit RETURN）、tuple 声明展开（每组件一个 VARIABLE，span=组件 decl）、
   UncheckedBlock（AST 直接持 statements，无 body 包裹）、loop_stack 重构为
   (break=ENDLOOP, continue=IFLOOP)。
3. **implicit RETURN**（命名返回函数的隐式返回）：多 tail 汇入单节点，span =
   returnParameters 列表 src（不是首个参数）。
4. **Literal type**：solc `int_const N` → slither `uint256`（负数 int256）、
   bool/string 相应映射。
5. **bodyless 函数**（interface）：oracle 有 0-node 条目 → rust 也发空条目（不是跳过）。
6. **synthetic CFG**：`slitherConstructorVariables` / `...ConstantVariables` 无 AST
   定义，在 fnode 循环之外按 state var `value` 初值构建（每 var 一个
   OTHER_ENTRYPOINT，span=var decl src）。synthetic ctor（空构造）Oracle 侧
   **不存在**（早先"slither 会合成空 ctor"是误判，勿再引入）。
7. **diff.py**：两侧都缺文件不再静默跳过（曾造成整批假阳性 IDENTICAL——
   历史教训：**一切 green 结论必须来自根目录级 diff + 输出存在性断言**）。

## 4. 下一步任务清单（按序）

### G2 收口（zoo 驱动，EXPECTED_OPEN 就是工作队列）
1. loop 内 IFLOOP son 顺序 + back-edge 细节：breakCase/continueCase/doWhileCase
   的 `successors[1]` 差异 —— 与 oracle 逐节点对照（zoo diff 直接给出节点号）。
2. ifCase 的 else-branch son 顺序、whileCase 回边、namedReturnCase 的
   implicit-return tuple 细节、tryCase 的 callee 表达式细节。
3. `slitherConstructorVariables` 在 zoo 已 1 节点相等但全量 diff 仍有条目——
   跑 `npm run oracle -- diff` 看剩余字段。
4. 每关一个 case：从 tests/r41-syntax-zoo.test.ts 的 EXPECTED_OPEN 删除条目
   （测试会先 FAIL 提醒你删——这是设计）。
5. G2 全绿后跑大 repo：`diff.py fixtures /tmp/… --file cfg.json`（根目录级！）
   预期剩 while/try/modifier 组合场景，按 zoo 新增 case 逐个消。

### G3/G4（G2 绿后）
- analysis.json 的 call 分类：**CallTarget 与 CallKind 分轴**；
  internal 解析用 AST `referencedDeclaration`（id → 函数），不要 name+argc。
- 保持 direct/intraprocedural 边界：不做传播/依赖/taint/SSA（R4.3–R4.5）。

### 架构纪律（不可退让）
- core 只用 typed arena id（ContractId/FunctionId/VariableId/CfgNodeId/ExprId）；
  span-sort ordinal、`__str__` 格式、false-son-first 等**只存在于 compat
  emitter**；semantic equality/lookup 不得依赖字符串。
- slither 兼容怪癖（synthetic 函数、modifier 不内联、`++ i` 空格等）都是
  **compat artifact**，core 模型里不得变成"语言事实"。
- 任何 "green" 必须附带：根目录 diff 输出 + 输出存在性 + manifest 校验。
- oracle 冻结契约**不含** SSA 与 data-dependency（slither 自身跨进程不可复现，
  见 README "Slither stability findings"）；R4.3/R4.5 需要语义规范化对比而非
  raw dump。

## 5. 命令速查

```bash
# sec-worker（oracle + bench + gates）
cd ~/Projects/BW2/sec-worker && export PATH="$HOME/.nvm/versions/node/v20.19.5/bin:$PATH"
npm run oracle -- export bench/corpus.json bench/oracle/fixtures   # 重建 oracle（含 zoo）
npm run oracle -- diff bench/oracle/fixtures /tmp/oracle-check     # oracle 双跑确定性（期望 IDENTICAL）
npm run oracle -- mining bench/oracle/detector_apis.json           # detector API 覆盖表
python3 bench/oracle/make_inputs.py bench/corpus.json bench/oracle/fixtures  # 重建 solc 输入+provenance
npm run bench -- --modes cold,repo,bundle                          # A/B/C 成本
npm test                                                           # G0–G6 阶梯 + e2e

# slither-rs
cd ~/Projects/BW2/slither-rs && cargo build
./target/debug/slither-oracle-compat --repo syntax-zoo --solc 0.8.28 \
    --fixtures ../sec-worker/bench/oracle/fixtures --out /tmp/zoo
# 之后必须用根目录 diff（传 fixtures 根，不是 repo 目录）：
python3 ../sec-worker/bench/oracle/diff.py ../sec-worker/bench/oracle/fixtures /tmp/zoo --file cfg.json
npm test   # 在 sec-worker 里跑（会 cargo build + 差分 + 断言）

# zoo 单函数 CFG 对照（快速定位）
python3 - <<'PY'
import json
for side, p in [("ORACLE","bench/oracle/fixtures/syntax-zoo/cfg.json"),("RUST","/tmp/zoo/syntax-zoo/cfg.json")]:
    for fn in json.load(open(p))["functions"]:
        if "breakCase" in fn["function"]:
            for n in fn["nodes"]:
                print(side, n["id"].split("#n")[1], n["kind"], [s.split("#n")[1] for s in n["successors"]])
PY
```

## 6. 历史结论（已冻结，勿重复劳动）

- **bench 结论**：direct-solc 路径上 analysis(2–4×) > compile；bundle 缓存后
  边际成本 100% 是 analysis；OZ model 13.5s = expression/CFG 5.5s + SlithIR/SSA
  4.9s + dependency 2.4s；RSS 729MB 是并发上限。→ slither-rs 优先打
  expression/CFG 层（正在做），detector 最后移植。
- **detector mining**（98 源）：IR dispatch 39% / node.irs 38% / CFG nodes 35% /
  **SSA 仅 3%** → R4.2 做 non-SSA IR 即可解锁大批 detector，SSA 推迟到 R4.5。
- **slither 不可复现性**：SSA 版本号/phi 顺序、data-dependency 内容跨进程漂移
  （PYTHONHASHSEED 无效，object-id hash）→ 二者不在冻结契约内。
- **peCatch venv 坑**：slither 0.9.1 + py3.12 需要 setuptools<81、safe-pysha3
  + pysha3 stub、editable 安装（detectors/ 缺 __init__.py）。
- worker 侧（沙箱/检测器/收費面）均已 E2E green，见 sec-worker README 与
  tests/（npm test 含 13 项沙箱 containment probes + 两检测器 e2e）。
