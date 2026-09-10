//! x86-64 System V ABI TinyRLE compress / decompress (pure Intel-syntax assembly).
//!
//! `tinyrle_compress(src, src_len, dst, dst_cap) -> isize`
//! `tinyrle_decompress(src, src_len, dst, dst_cap) -> isize`
//! Returns written byte count, or -1 on error.

use std::arch::global_asm;

global_asm!(
    r#"
    .text
    .globl tinyrle_compress
    .type  tinyrle_compress, @function
tinyrle_compress:
    // Args: rdi=src, rsi=src_len, rdx=dst, rcx=dst_cap
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  r12, rdi            // src base
    mov  r13, rsi            // src_len
    mov  r14, rdx            // dst base
    mov  r15, rcx            // dst_cap
    xor  rbx, rbx            // si
    xor  r8,  r8             // di

.Lcomp_loop:
    cmp  rbx, r13
    jae  .Lcomp_ok

    movzx eax, byte ptr [r12 + rbx]

    // Count run length, capped at 130.
    mov  ecx, 1
.Lcomp_run_count:
    mov  rdx, rbx
    add  rdx, rcx
    cmp  rdx, r13
    jae  .Lcomp_run_done
    cmp  ecx, 130
    jae  .Lcomp_run_done
    movzx edx, byte ptr [r12 + rdx]
    cmp  edx, eax
    jne  .Lcomp_run_done
    inc  ecx
    jmp  .Lcomp_run_count
.Lcomp_run_done:

    cmp  ecx, 3
    jb   .Lcomp_literal

    // Emit run record: ctrl + value (2 bytes).
    mov  rdx, r8
    add  rdx, 2
    cmp  rdx, r15
    ja   .Lcomp_err
    mov  edx, ecx
    sub  edx, 3
    or   edx, 0x80
    mov  byte ptr [r14 + r8], dl
    inc  r8
    mov  byte ptr [r14 + r8], al
    inc  r8
    add  rbx, rcx
    jmp  .Lcomp_loop

.Lcomp_literal:
    mov  r9, rbx             // lit_start
    xor  r10, r10            // lit_len

.Lcomp_lit_gather:
    cmp  r10, 128
    jae  .Lcomp_lit_emit
    cmp  rbx, r13
    jae  .Lcomp_lit_emit

    movzx eax, byte ptr [r12 + rbx]
    mov  ecx, 1
.Lcomp_lit_peek:
    mov  rdx, rbx
    add  rdx, rcx
    cmp  rdx, r13
    jae  .Lcomp_lit_peek_done
    cmp  ecx, 130
    jae  .Lcomp_lit_peek_done
    movzx edx, byte ptr [r12 + rdx]
    cmp  edx, eax
    jne  .Lcomp_lit_peek_done
    inc  ecx
    jmp  .Lcomp_lit_peek
.Lcomp_lit_peek_done:
    cmp  ecx, 3
    jae  .Lcomp_lit_emit
    inc  rbx
    inc  r10
    jmp  .Lcomp_lit_gather

.Lcomp_lit_emit:
    test r10, r10
    jnz  .Lcomp_lit_write
    // Unreachable in well-formed input; keep progress.
    inc  rbx
    mov  r10, 1
    mov  r9, rbx
    dec  r9

.Lcomp_lit_write:
    mov  rdx, r8
    add  rdx, 1
    add  rdx, r10
    cmp  rdx, r15
    ja   .Lcomp_err
    mov  rax, r10
    dec  rax
    mov  byte ptr [r14 + r8], al
    inc  r8
    lea  rsi, [r12 + r9]
    lea  rdi, [r14 + r8]
    mov  rcx, r10
    rep  movsb
    add  r8, r10
    jmp  .Lcomp_loop

.Lcomp_ok:
    mov  rax, r8
    jmp  .Lcomp_epilogue
.Lcomp_err:
    mov  rax, -1
.Lcomp_epilogue:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
    .size tinyrle_compress, .-tinyrle_compress


    .globl tinyrle_decompress
    .type  tinyrle_decompress, @function
tinyrle_decompress:
    // Args: rdi=src, rsi=src_len, rdx=dst, rcx=dst_cap
    push rbp
    mov  rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov  r12, rdi
    mov  r13, rsi
    mov  r14, rdx
    mov  r15, rcx
    xor  rbx, rbx            // si
    xor  r8,  r8             // di

.Ldec_loop:
    cmp  rbx, r13
    jae  .Ldec_ok

    movzx eax, byte ptr [r12 + rbx]
    inc  rbx
    cmp  eax, 128
    jae  .Ldec_run

    // Literal: n = ctrl + 1
    lea  r9, [rax + 1]
    mov  rdx, rbx
    add  rdx, r9
    cmp  rdx, r13
    ja   .Ldec_err
    mov  rdx, r8
    add  rdx, r9
    cmp  rdx, r15
    ja   .Ldec_err
    lea  rsi, [r12 + rbx]
    lea  rdi, [r14 + r8]
    mov  rcx, r9
    rep  movsb
    add  rbx, r9
    add  r8, r9
    jmp  .Ldec_loop

.Ldec_run:
    // n = (ctrl - 0x80) + 3
    lea  r9, [rax - 0x80 + 3]
    cmp  rbx, r13
    jae  .Ldec_err
    mov  rdx, r8
    add  rdx, r9
    cmp  rdx, r15
    ja   .Ldec_err
    movzx eax, byte ptr [r12 + rbx]
    inc  rbx
    lea  rdi, [r14 + r8]
    mov  rcx, r9
    rep  stosb
    add  r8, r9
    jmp  .Ldec_loop

.Ldec_ok:
    mov  rax, r8
    jmp  .Ldec_epilogue
.Ldec_err:
    mov  rax, -1
.Ldec_epilogue:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rbp
    ret
    .size tinyrle_decompress, .-tinyrle_decompress
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
