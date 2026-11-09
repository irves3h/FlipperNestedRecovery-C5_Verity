# C5 “Verity” 引擎独立库 README

> 仓库：FlipperNestedRecovery-C5_Verity。无 GUI 的纯引擎库，供其他开发者在自己的项目里调用，与上游 FlipperNestedRecovery 同类。

## 优化是怎么来的

一开始的优化方案里是有 GPU 方案的：原计划把最耗时的部分搬到 GPU（Metal）上跑。但做到第 5 号实验（C5）时，提升已经够了——同一份 .nonces 在 M1 Pro 上从 3 分 30 秒降到 8–9 秒；这时候再上 GPU，反而要把整个事情复杂化（内核重写、数据来回搬、正确性重新验证），省下的只是几秒钟，所以 GPU 方案没做。

实验编号：C0 是原版基线；C1、C2、C3 是三个微优化（实测基本零收益，C3 多线程反而慢 73%，已否决）；C4 是 1.8 倍；C5 是第 5 号实验的组合版（combined），也是最终胜出的版本。

## 名字：C5 是什么意思

C5 不是产品名，是实验编号（实验经过见上面「优化是怎么来的」）。库里保留 C5 这个代号，是因为我们内部所有记录、测试和版本说明都这么叫；对外第一次出现时用一句话定义：**C5 = 单表 + 直接验证的 Nested 恢复引擎**。

英文代号：**Verity**。C5 的核心动作是直接验证（verify）而不是建表求交，Verity 就是“真实、真值”的意思——每个候选都直接验证真假，跑出来的密钥与原版逐字一致。名字由小克取。仓库名：FlipperNestedRecovery-C5_Verity。

## 库结构

```
FlipperNestedRecovery-C5_Verity/
├── NestedSolver/          # 从 c5-combined/NestedSolver/ 整体搬过来（C 扩展源，只换 C 文件）
│   ├── library.c          # 唯一改动的文件：C5 就在这里，其他 C 文件与上游 v2.3.5 一字不差
│   ├── crapto1.c / crapto1.h   # lfsr_recovery32（未动）
│   ├── crypto1.c               # Crypto1 状态机（未动）
│   └── bucketsort.c / parity.h / progress.c / python.c  # 均未动
├── HardNestedSolver/    # 上游 hardnested 模块原样搬运（bitsliced 暴力枚举，C5 不动它）
├── FlipperNested/         # Python 层不动，从主项目原样搬运（recover_keys、.keys 输出格式不变）
├── tests/                 # 已知答案夹具 + 同一份 .nonces 逐字节比对（.nonces 不提交）
└── README.md              # 本文件
```

要点：只拆引擎本身（C5 优化过的 NestedSolver，加原样搬运的 HardNestedSolver），不带 Swift 界面、不带并行驱动（驱动留在主项目）；Python 层接口不变，老调用方不用改。

## 技术细节

### 改了什么：只有一个文件

与上游 FlipperNestedRecovery v2.3.5（commit `ca7ad8529ebc26d3d86225b519569370d0bcbbf3`）逐文件比对，**只有 `NestedSolver/library.c` 不同**，其余 C 文件一字不差。C5 不是重写求解器，是把 `run_full_nested` 里的恢复循环换了一种组织方式；`lfsr_recovery32`、`prng_successor`、`valid_nonce`、`crypto1_word` 这些底层函数一个没动。

### 原版为什么慢

入口是 `run_full_nested(uid, nt0, ks0, par0, nt1, ks1, par1, from, to, progress)`，`[from, to]` 是深度窗口（默认 ±100）。原版对外层 `first`、内层 `second` 的每个候选对，只要两个 nonce 都通过 `valid_nonce` 检查，就调一次 `nested_calculate`：为 nonce-0 建一张 Crypto1 状态表（`lfsr_recovery32`），为 nonce-1 再建一张，两张表各排一次序，再求交集找共同状态，最后从交集提密钥。

单条记录实测：深度 ±100 时约 9 个有效 `first` × 25 个有效 `second` = **225 次 `nested_calculate` 调用，每次约 0.7 秒 CPU，其中只有 1 次命中，其余 224 次建的表、排的序、求的交全部作废**。这就是全部开销的来源。

### C5 怎么做（`library.c`，`run_full_nested`）

1. **外层只循环 `first`**：固定一个 `first` 时，`nt0' = prng_successor(nt0, first)` 是确定的，先把通过 `valid_nonce` 的 `second` 收集起来（一般 25 个）。
2. **一张表，建一次**：只为 nonce-0 建一张状态表 `list0 = lfsr_recovery32(ks0 ^ nt0', nt0' ^ uid)`，并把表里每个状态回滚一次（`lfsr_rollback_word`），得到 `rolled[]`。**同一 `first` 的 25 个候选共享这张表**，建表成本均摊到 25 次验证上。
3. **直接验证，不建第二张表**：对每个候选 `second`，把 `rolled[]` 里的状态逐个用 `verify_key_early` 直接验证 nonce-1（即检查 `crypto1_word(K, nt1' ^ uid, 0) == ks1'`）。取**最后一个**通过验证的 `second`（与原版的表求交顺序一致）。
4. **输出顺序与原版逐字一致**：对中选 `second` 下所有通过验证的回滚状态，按原始 uint64 值升序（原版的 `compare_uint64`）排好序再提密钥。**按密钥值排序是错的**——原版顺序是回滚后状态的原始值顺序，密钥是位交错提取的，两者顺序不同；这点在 CI 里暴露过一次，已修好，测试不许改期望值。

单条记录的调用结构从 225 次完整恢复变成：每 `first` 建 1 张表 + 直接验证。搜索空间、候选集合、密钥结果一概未变，砍掉的是重复建表、重复排序与无效求交。

### 没动什么

- `lfsr_recovery32`（`crapto1.c`）未动：R3c 把它的递归改成迭代工作队列的实验已验证正确（状态表逐字节一致），但单线程成本不变（-0.3%，噪声），所以**没进库**；它只是为以后上 GPU 准备的形状。
- 无多线程、无 SIMD、无 GPU：C5 是单线程的；C3 的 4 线程版反而慢 73%（内存 4.8 GB），已否决。
- Python 层未动：`FlipperNested/main.py` 的 `parse_file` / `recover_keys` / `.keys` 输出格式与上游一致；`run_nested`（单对恢复）走同一套直接验证逻辑。
- Hard Nested 不在 C5 的优化范围内：它是另一套 bitsliced 暴力枚举代码，没有双表求交结构，C5 那招套不上；库里原样带上它，不改。

## 性能对比

同一份 .nonces（12 条记录）、同一台 M1 Pro、同一深度设置：

| 深度 | 原版引擎 | C5 引擎 | 提升 |
|---|---|---|---|
| ±100（默认） | 3 分 30 秒 | 8–9 秒 | 约 25 倍 |
| ±150 | —（原版该深度未测） | 约 14–15 秒 | — |

补充（云端 Linux，1.4 有效核）：完整文件总 CPU 时间 2583.28 秒 → 58.05 秒，约 44.5 倍；墙钟 1770.67 秒 → 115.27 秒，约 15 倍；峰值内存 1.73 GB → 约 75 MB。
输出一致性：`.keys` 与原版逐字节一致（含密钥顺序）；密钥已在 Flipper 上经 Check found keys 验证通过。

## 原理

原版 `nested_calculate` 对每个 `(first, second)` 候选对都执行完整恢复流程：为两个 nonce 各建一张 Crypto1 状态表、排序、求交。单条记录 225 次调用中仅 1 次命中，其余 224 次的建表、排序与求交全部作废——这是全部开销的来源。

C5 的改进（搜索空间与候选集合不变，密钥结果不变）：

1. **单表 + 直接验证**：只为 nonce-0 建一张状态表；对每个候选状态做回滚（rollback）后，直接以 `crypto1_word(K, nt1'^uid, 0) == ks1'` 验证 nonce-1，省去第二张表、两次排序与表求交。
2. **表复用**：同一 `first` 的 25 个候选共享同一张表，建表成本均摊到 25 次验证上。
3. **输出等价**：对回滚后的状态按原始 uint64 值排序后再提取密钥，输出顺序与原版的表求交路径逐字一致。

一句话：候选一个没少试，密钥一个没少找；砍掉的是每试一次就重建、重排、重比两张大表的重复开销。

## 安装

从源码安装（本库未发布到 PyPI）：

```sh
git clone https://github.com/irves3h/FlipperNestedRecovery-C5_Verity.git
cd FlipperNestedRecovery-C5_Verity
pip install --upgrade pyserial protobuf wheel setuptools
python setup.py sdist bdist_wheel
pip install --user --upgrade --find-links=./dist FlipperNested
```

构建依赖：需要 C 编译器和 lzma（macOS 用 `brew install xz`，Ubuntu/Debian 用 `sudo apt-get install liblzma-dev`）。也可以直接在源码目录构建扩展后就地使用：`python setup.py build_ext --inplace`（Python 3.10 / 3.12，macOS / Linux）。

## 用法

```
$ FlipperNested --file card.nonces
Recovering key type A, sector 0
Found 1 key(s): ['ffffffffffff']
[+] Found potential 1 keys, use "Check found keys" in app
[?] Saved keys to card.nonces.keys
```

```
$ FlipperNested --help
usage: FlipperNested [-h] [--uid UID] [--port PORT] [--progress] [--save]
                     [--preserve] [--file FILE] [--per-record]

Recover keys after Nested attack

options:
  -h, --help    show this help message and exit
  --uid UID     Recover only for this UID
  --port PORT   Port to connect
  --progress    Show key recovery progress bar
  --save        Debug: Save nonces/keys from Flipper
  --preserve    Debug: Don't remove nonces after recovery
  --file FILE   Debug: Recover keys from local .nonces file
  --per-record  Print a per-record candidate report (which candidate each
                Nonces record produced and in how many records each candidate
                appears). The default .keys output format is unchanged.
```

本地文件模式：`FlipperNested --file card.nonces`，Hard Nested 单个数据文件同样这么跑。Python 层接口不变，老调用方不用改。

## 怎么测

- 已知答案夹具：跑完 `.keys` 与原版逐字节比对（含密钥顺序，顺序错了就是不合格）。
- 深度说明：±25 会漏密钥（实测 0 个），自动档最低只到 50；±150 能跑，内存约 1.85 GB（云端单条记录实测）。

## 支持 Hard Nested

库里带上游 hardnested 模块（bitsliced 暴力枚举，原样搬运，不改）；单个数据文件直接跑，Key A、Key B 各自独立；C5 的单表优化只针对 Nested 路径，Hard Nested 不套用。

## 致谢

感谢 AloneLiberty 开发了最初的 FlipperNestedRecovery 工具，本项目正是基于此工具开发的。
（ https://github.com/AloneLiberty/FlipperNestedRecovery ）

## 已定事项

- 仓库名：FlipperNestedRecovery-C5_Verity。
- 许可证：GPL-3.0。
- Python 包导入名：计划为 FlipperNestedVerity（暂不上传 PyPI；v0.1.0 代码里仍是 FlipperNested，改名另行处理）。
