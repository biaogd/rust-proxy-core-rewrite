# Rust 学习笔记 · TinyRLE

在这个练习里实现了一个小型 **RLE（游程）压缩器**：

- **Rust**：对外 API、错误处理、CLI、参考实现与测试
- **纯 x86-64 汇编**：`compress` / `decompress` 热路径（System V ABI，`global_asm!`）

非 `x86_64` 目标自动回退到 Rust 参考实现。

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

压缩 / 解压文件：

```sh
cargo run --bin rle-demo -- compress  input.bin output.rle
cargo run --bin rle-demo -- decompress output.rle restored.bin
```

## 布局

- `src/lib.rs` — 公共 API（x86_64 走汇编）
- `src/asm_x86_64.rs` — 纯汇编实现
- `src/rle_rust.rs` — Rust 参考实现（测试对照）
- `src/format.rs` — 格式常量
- `src/main.rs` — 演示 CLI
