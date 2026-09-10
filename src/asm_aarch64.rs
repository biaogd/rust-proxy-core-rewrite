//! AArch64 (Apple Silicon / Linux ARM64) TinyRLE compress / decompress.
//!
//! AAPCS64: x0=src, x1=src_len, x2=dst, x3=dst_cap → x0 = written bytes or -1.
//! Dual-exports `tinyrle_*` and `_tinyrle_*` so Linux ELF and macOS Mach-O both link.
//! Avoids x18 (reserved on Apple platforms).

use std::arch::global_asm;

global_asm!(
    r#"
    .text
    .align 2
    .globl tinyrle_compress
    .globl _tinyrle_compress
tinyrle_compress:
_tinyrle_compress:
    // Prologue: save FP/LR and callee-saved regs.
    stp  x29, x30, [sp, #-80]!
    mov  x29, sp
    stp  x19, x20, [sp, #16]
    stp  x21, x22, [sp, #32]
    stp  x23, x24, [sp, #48]
    stp  x25, x26, [sp, #64]

    mov  x19, x0              // src
    mov  x20, x1              // src_len
    mov  x21, x2              // dst
    mov  x22, x3              // dst_cap
    mov  x23, xzr             // si
    mov  x24, xzr             // di

.Lcomp_loop:
    cmp  x23, x20
    b.hs .Lcomp_ok

    ldrb w8, [x19, x23]       // current byte

    // Count run length, capped at 130.
    mov  w9, #1
.Lcomp_run_count:
    add  x10, x23, x9
    cmp  x10, x20
    b.hs .Lcomp_run_done
    cmp  w9, #130
    b.hs .Lcomp_run_done
    ldrb w11, [x19, x10]
    cmp  w11, w8
    b.ne .Lcomp_run_done
    add  w9, w9, #1
    b    .Lcomp_run_count
.Lcomp_run_done:

    cmp  w9, #3
    b.lo .Lcomp_literal

    // Emit run: need 2 bytes.
    add  x10, x24, #2
    cmp  x10, x22
    b.hi .Lcomp_err
    sub  w10, w9, #3
    orr  w10, w10, #0x80
    strb w10, [x21, x24]
    add  x24, x24, #1
    strb w8, [x21, x24]
    add  x24, x24, #1
    add  x23, x23, x9
    b    .Lcomp_loop

.Lcomp_literal:
    mov  x25, x23             // lit_start
    mov  x26, xzr             // lit_len

.Lcomp_lit_gather:
    cmp  x26, #128
    b.hs .Lcomp_lit_emit
    cmp  x23, x20
    b.hs .Lcomp_lit_emit

    ldrb w8, [x19, x23]
    mov  w9, #1
.Lcomp_lit_peek:
    add  x10, x23, x9
    cmp  x10, x20
    b.hs .Lcomp_lit_peek_done
    cmp  w9, #130
    b.hs .Lcomp_lit_peek_done
    ldrb w11, [x19, x10]
    cmp  w11, w8
    b.ne .Lcomp_lit_peek_done
    add  w9, w9, #1
    b    .Lcomp_lit_peek
.Lcomp_lit_peek_done:
    cmp  w9, #3
    b.hs .Lcomp_lit_emit
    add  x23, x23, #1
    add  x26, x26, #1
    b    .Lcomp_lit_gather

.Lcomp_lit_emit:
    cbnz x26, .Lcomp_lit_write
    add  x23, x23, #1
    mov  x26, #1
    sub  x25, x23, #1

.Lcomp_lit_write:
    add  x10, x24, #1
    add  x10, x10, x26
    cmp  x10, x22
    b.hi .Lcomp_err
    sub  x10, x26, #1
    strb w10, [x21, x24]
    add  x24, x24, #1
    // memcpy dst[di..] <- src[lit_start..] for lit_len bytes
    mov  x11, xzr
.Lcomp_memcpy:
    cmp  x11, x26
    b.hs .Lcomp_memcpy_done
    add  x12, x25, x11
    ldrb w8, [x19, x12]
    add  x12, x24, x11
    strb w8, [x21, x12]
    add  x11, x11, #1
    b    .Lcomp_memcpy
.Lcomp_memcpy_done:
    add  x24, x24, x26
    b    .Lcomp_loop

.Lcomp_ok:
    mov  x0, x24
    b    .Lcomp_epilogue
.Lcomp_err:
    mov  x0, #-1
.Lcomp_epilogue:
    ldp  x25, x26, [sp, #64]
    ldp  x23, x24, [sp, #48]
    ldp  x21, x22, [sp, #32]
    ldp  x19, x20, [sp, #16]
    ldp  x29, x30, [sp], #80
    ret


    .align 2
    .globl tinyrle_decompress
    .globl _tinyrle_decompress
tinyrle_decompress:
_tinyrle_decompress:
    stp  x29, x30, [sp, #-80]!
    mov  x29, sp
    stp  x19, x20, [sp, #16]
    stp  x21, x22, [sp, #32]
    stp  x23, x24, [sp, #48]
    stp  x25, x26, [sp, #64]

    mov  x19, x0
    mov  x20, x1
    mov  x21, x2
    mov  x22, x3
    mov  x23, xzr             // si
    mov  x24, xzr             // di

.Ldec_loop:
    cmp  x23, x20
    b.hs .Ldec_ok

    ldrb w8, [x19, x23]
    add  x23, x23, #1
    cmp  w8, #128
    b.hs .Ldec_run

    // Literal: n = ctrl + 1
    add  x25, x8, #1
    add  x10, x23, x25
    cmp  x10, x20
    b.hi .Ldec_err
    add  x10, x24, x25
    cmp  x10, x22
    b.hi .Ldec_err
    mov  x11, xzr
.Ldec_memcpy:
    cmp  x11, x25
    b.hs .Ldec_memcpy_done
    add  x12, x23, x11
    ldrb w8, [x19, x12]
    add  x12, x24, x11
    strb w8, [x21, x12]
    add  x11, x11, #1
    b    .Ldec_memcpy
.Ldec_memcpy_done:
    add  x23, x23, x25
    add  x24, x24, x25
    b    .Ldec_loop

.Ldec_run:
    // n = (ctrl - 0x80) + 3
    sub  w8, w8, #0x80
    add  x25, x8, #3
    cmp  x23, x20
    b.hs .Ldec_err
    add  x10, x24, x25
    cmp  x10, x22
    b.hi .Ldec_err
    ldrb w8, [x19, x23]
    add  x23, x23, #1
    mov  x11, xzr
.Ldec_fill:
    cmp  x11, x25
    b.hs .Ldec_fill_done
    add  x12, x24, x11
    strb w8, [x21, x12]
    add  x11, x11, #1
    b    .Ldec_fill
.Ldec_fill_done:
    add  x24, x24, x25
    b    .Ldec_loop

.Ldec_ok:
    mov  x0, x24
    b    .Ldec_epilogue
.Ldec_err:
    mov  x0, #-1
.Ldec_epilogue:
    ldp  x25, x26, [sp, #64]
    ldp  x23, x24, [sp, #48]
    ldp  x21, x22, [sp, #32]
    ldp  x19, x20, [sp, #16]
    ldp  x29, x30, [sp], #80
    ret
"#
);

unsafe extern "C" {
    pub fn tinyrle_compress(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_cap: usize,
    ) -> isize;

    pub fn tinyrle_decompress(
        src: *const u8,
        src_len: usize,
        dst: *mut u8,
        dst_cap: usize,
    ) -> isize;
}
