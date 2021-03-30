/*
 * Author: Daniel Lenski <dlenski@gmail.com>
 * Copyright © 2021 Daniel Lenski
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. *
 *
 */

/* This program demonstrates how to curry a 2-parameter function into
 * a 1-parameter function, in C, for the x86-64 architecture and
 * System V ABI.
 *
 * It is based on the "Trampoline Illustration" from
 * https://nullprogram.com/blog/2019/11/15, but with the trampoline
 * stored on the heap rather than the stack. This is much safer
 * because it means we don't have to disable the compiler's stack
 * execution protection (no 'gcc -Wl,-z,execstack').
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/mman.h>
#include <stdint.h>

#define PAGE_START(P) ((uintptr_t)(P) & ~(pagesize-1))
#define PAGE_END(P)   (((uintptr_t)(P) + pagesize - 1) & ~(pagesize-1))

/* x86-64 ABI passes parameters in rdi, rsi, rdx, rcx, r8, r9
 * (https://wiki.osdev.org/System_V_ABI), and return value
 * goes in %rax.
 *
 * Binary format of useful opcodes:
 *
 *       0xbf, [le32] = movl $imm32, %edi (1st param)
 *       0xbe, [le32] = movl $imm32, %esi (2nd param)
 *       0xba, [le32] = movl $imm32, %edx (3rd param)
 *       0xb9, [le32] = movl $imm32, %ecx (4rd param)
 *       0xb8, [le32] = movl $imm32, %eax
 * 0x48, 0x__, [le64] = movq $imm64, %r__
 *       0xff, 0xe0   = jmpq *%rax
 */

typedef uint32_t (*one_param_func_ptr)(uint32_t);
one_param_func_ptr curry_two_param_func(
    void *two_param_func,
    uint32_t second_param)
{
    /* This is a template for calling a "curried" version of
     * uint32_t (*two_param_func)(uint32_t a, uint32_t b),
     * using the Linux x86-64 ABI. The curried version can be
     * treated as uint32_t (*one_param_func)(uint32_t a).
     */
    uintptr_t fp = (uintptr_t)two_param_func;
    uint8_t template[] = {
        0xbe, 0, 0, 0, 0,                                   /* movl $imm32, %esi */
        0x48, 0xb8, fp >>  0, fp >>  8, fp >> 16, fp >> 24, /* movq fp, %rax */
                    fp >> 32, fp >> 40, fp >> 48, fp >> 56,
        0xff, 0xe0                                          /* jmpq *%rax */
    };

    /* Now we create a copy of this template on the HEAP, and
     * fill in the second param. */
    uint8_t *buf = malloc(sizeof(template));
    if (!buf)
        return NULL;

    memcpy(buf, template, sizeof(template));
    buf[1] = second_param >> 0;
    buf[2] = second_param >> 8;
    buf[3] = second_param >> 16;
    buf[4] = second_param >> 24;

    /* We do NOT want to make the stack executable,
     * but we NEED the heap-allocated buf to be executable.
     * Compiling with 'gcc -Wl,-z,execstack' would do BOTH.
     *
     * This appears to be the right way to only make a heap object executable:
     *   https://stackoverflow.com/questions/23276488/why-is-execstack-required-to-execute-code-on-the-heap
     */
    uintptr_t pagesize = sysconf(_SC_PAGE_SIZE);
    mprotect((void *)PAGE_START(buf),
             PAGE_END(buf + sizeof(template)) - PAGE_START(buf),
             PROT_READ|PROT_WRITE|PROT_EXEC);

    return (one_param_func_ptr)buf;
}

/********************************************/

int print_both_params(int a, int b)
{
    printf("Called with a=%d, b=%d\n", a, b);
    return a+b;
}

int main(int argc, char **argv)
{
    one_param_func_ptr print_both_params_b4 =
        curry_two_param_func(print_both_params, 4);
    one_param_func_ptr print_both_params_b256 =
        curry_two_param_func(print_both_params, 256);

    print_both_params_b4(3);    // "Called with a=3, b=4"
    print_both_params_b256(6);  // "Called with a=6, b=256"

    return 0;
}
