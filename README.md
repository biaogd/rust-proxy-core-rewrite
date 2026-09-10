# Rust 学习笔记 · TinyRLE

在这个练习里实现了一个小型 **RLE（游程）压缩器**：

- **Rust**：对外 API、错误处理、CLI、参考实现与测试
- **纯汇编热路径**（`global_asm!`）：
  - `x86_64`（Linux/Intel Mac）→ `src/asm_x86_64.rs`
  - `aarch64`（**Apple Silicon / M 系列**、ARM64 Linux）→ `src/asm_aarch64.rs`

其他架构回退到 Rust 参考实现。macOS M1/M2/M3/M4 直接走 aarch64 汇编（同时导出 `_tinyrle_*` 以兼容 Mach-O 符号）。

## 格式（TinyRLE）

| 记录 | 控制字节 | 后继 |
|------|----------|------|
| 字面量 | `0..=127` = `len-1` | `len` 字节原文（1..=128） |
| 重复串 | `0x80..=0xFF` = `0x80 \| (count-3)` | 1 字节重复值（count 为 3..=130） |

## 运行

```sh
cargo run --bin rle-demo
cargo run --bin rle-demo -- bench
cargo test
```

在 Apple Silicon 上应显示：

```text
backend     : aarch64 assembly (Apple Silicon / ARM64)
```

压缩 / 解压文件：

```sh
cargo run --bin rle-demo -- compress  input.bin output.rle
cargo run --bin rle-demo -- decompress output.rle restored.bin
```

## 布局

- `src/lib.rs` — 公共 API（按架构选择汇编）
- `src/asm_x86_64.rs` — x86-64 纯汇编
- `src/asm_aarch64.rs` — AArch64 / Apple Silicon 纯汇编
- `src/rle_rust.rs` — Rust 参考实现（测试对照）
- `src/format.rs` — 格式常量
- `src/main.rs` — 演示 CLI
