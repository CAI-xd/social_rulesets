/*
    Koodous Community Public Rule. Create your own rules to detect malware 
    for android at: https://koodous.com/
    
    Author: uF69F2A0VqGAGC32
    Rule name: CrackProof "BrawlStars" Packer
    Rule id: 5244
    Created at: 2019-01-31 19:22:19
    Updated at: 2019-03-23 17:23:47
    
    Rating: #0
    Total detections: 12
*/

import "androguard"
import "file"
import "cuckoo"


rule bs_packer : packer
{
	meta:
		description = "CrackProof packer"

	strings:

		/**
			int __fastcall j_do_asm_syscall(int svc_nr, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7)
			{
				int r; // r0

				r = do_asm_syscall(a2, a3, a4, a5, a6, a7, 0, svc_nr);
				return sub_4D78C(svc_nr, r);
			}
		*/
		$j_do_asm_syscall = {
			00 48 2D E9 //   PUSH {R11,LR}
			04 B0 8D E2 //   ADD  R11, SP, #4
			28 D0 4D E2 //   SUB  SP, SP, #0x28
			10 00 0B E5 //   STR  R0, [R11,#var_10]
			14 10 0B E5 //   STR  R1, [R11,#a1]
			18 20 0B E5 //   STR  R2, [R11,#a2]
			1C 30 0B E5 //   STR  R3, [R11,#a3]
			00 30 A0 E3 //   MOV  R3, #0
			08 30 0B E5 //   STR  R3, [R11,#r]
			08 30 9B E5 //   LDR  R3, [R11,#a6]
			00 30 8D E5 //   STR  R3, [SP,#0x2C+var_2C] ; a5
			0C 30 9B E5 //   LDR  R3, [R11,#a7]
			04 30 8D E5 //   STR  R3, [SP,#0x2C+var_28] ; a6
			00 30 A0 E3 //   MOV  R3, #0
			08 30 8D E5 //   STR  R3, [SP,#0x2C+var_24] ; a7
			10 30 1B E5 //   LDR  R3, [R11,#var_10]
			0C 30 8D E5 //   STR  R3, [SP,#0x2C+svc_nr] ; svc_nr
			14 00 1B E5 //   LDR  R0, [R11,#a1] ; a1
			18 10 1B E5 //   LDR  R1, [R11,#a2] ; a2
			1C 20 1B E5 //   LDR  R2, [R11,#a3] ; a3
			04 30 9B E5 //   LDR  R3, [R11,#a5] ; a4
			?? ?? ?? EB //   BL   do_asm_syscall
			00 30 A0 E1 //   MOV  R3, R0
			08 30 0B E5 //   STR  R3, [R11,#r]
			08 30 1B E5 //   LDR  R3, [R11,#r]
			10 00 1B E5 //   LDR  R0, [R11,#var_10] ; svc_nr
			03 10 A0 E1 //   MOV  R1, R3  ; r
			?? ?? ?? EB //   BL   sub_4D78C
			00 30 A0 E1 //   MOV  R3, R0
			08 30 0B E5 //   STR  R3, [R11,#r]
			08 30 1B E5 //   LDR  R3, [R11,#r]
			03 00 A0 E1 //   MOV  R0, R3
			04 D0 4B E2 //   SUB  SP, R11, #4
			00 88 BD E8 //   POP  {R11,PC}
		}


		/**
			int __fastcall do_asm_syscall(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7, int svc_nr)
			{
				return linux_eabi_syscall(svc_nr, a1, a2, a3, a4, a5, a6, a7);
			}
		*/
		$do_asm_syscall = {
			FE 4F 2D E9  //  PUSH  {R1-R11,LR}
			2C B0 8D E2  //  ADD   R11, SP, #0x2C
			04 40 9B E5  //  LDR   R4, [R11,#a5]
			08 50 9B E5  //  LDR   R5, [R11,#a6]
			0C 60 9B E5  //  LDR   R6, [R11,#a7]
			10 70 9B E5  //  LDR   R7, [R11,#svc_nr]
			00 00 00 EF  //  SVC   0
			FE 8F BD E8  //  POP   {R1-R11,PC}
		}

	condition:
		all of them
}
