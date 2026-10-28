/*
 * Copyright 2026 Aurora Operations, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
 *
 * This work is dual licensed.
 * You may use it under Apache-2.0 or GPL-2.0 at your option.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * OR
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

/*
 * Bare-metal startup for the stack probe on QEMU's `virt` machine: entry,
 * exception vectors, semihosting, and the trampoline that runs a call on
 * the probe stack. ARM state; the C code is Thumb-2 like typical firmware.
 */

	.syntax unified
	.arm

	.section .text.start, "ax"
	.global _start
	.type	_start, %function
_start:
	ldr	sp, =__main_stack_top
	ldr	r0, =vectors
	mcr	p15, 0, r0, c12, c0, 0		@ VBAR
	ldr	r0, =__bss_start
	ldr	r1, =__bss_end
	mov	r2, #0
1:	cmp	r0, r1
	strlo	r2, [r0], #4
	blo	1b
	ldr	r0, =main
	blx	r0
	b	probe_exit

	.text
	.balign	32
vectors:
	b	.
	b	fault				@ undefined instruction
	b	fault				@ supervisor call
	b	fault				@ prefetch abort
	b	fault				@ data abort
	b	.
	b	fault				@ IRQ
	b	fault				@ FIQ

fault:
	ldr	sp, =__main_stack_top
	ldr	r1, =fault_msg
	mov	r0, #0x04			@ SYS_WRITE0
	svc	0x123456
	mov	r0, #1
	b	probe_exit

/* void probe_exit(int status): stops QEMU, exit code 0 or 1. */
	.global	probe_exit
	.type	probe_exit, %function
probe_exit:
	cmp	r0, #0
	ldreq	r1, =0x20026			@ ADP_Stopped_ApplicationExit
	ldrne	r1, =0x20023			@ ADP_Stopped_RunTimeErrorUnknown
	mov	r0, #0x18			@ SYS_EXIT
	svc	0x123456
	b	.

/* void probe_puts(char const *s) */
	.global	probe_puts
	.type	probe_puts, %function
probe_puts:
	mov	r1, r0
	mov	r0, #0x04			@ SYS_WRITE0
	svc	0x123456
	bx	lr

/*
 * int probe_call_on_stack(int (*fn)(void), void *stack_top): calls fn with
 * the stack pointer at stack_top, so everything fn and its callees write
 * to the stack lands in the probe stack and nowhere else.
 */
	.global	probe_call_on_stack
	.type	probe_call_on_stack, %function
probe_call_on_stack:
	push	{r4, lr}
	mov	r4, sp
	mov	sp, r1
	blx	r0
	mov	sp, r4
	pop	{r4, pc}

	.section .rodata
fault_msg:
	.asciz	"stack-probe: CPU exception\n"
