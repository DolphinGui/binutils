#as: -march=rv64id
#name: D extension (64-bit)
#objdump: -dwrMnumeric

.*:[ 	]+file format .*


Disassembly of section .text:

0+ <D>:
[ 	]+[0-9a-f]+:[ 	]+22002fd3[ 	]+fabs\.d[ 	]+f31,f0
[ 	]+[0-9a-f]+:[ 	]+23ffa053[ 	]+fabs\.d[ 	]+f0,f31
[ 	]+[0-9a-f]+:[ 	]+02007fd3[ 	]+fadd\.d[ 	]+f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+020ff053[ 	]+fadd\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+03f07053[ 	]+fadd\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+02000053[ 	]+fadd\.d[ 	]+f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+02001053[ 	]+fadd\.d[ 	]+f0,f0,f0,rtz
[ 	]+[0-9a-f]+:[ 	]+02002053[ 	]+fadd\.d[ 	]+f0,f0,f0,rdn
[ 	]+[0-9a-f]+:[ 	]+02003053[ 	]+fadd\.d[ 	]+f0,f0,f0,rup
[ 	]+[0-9a-f]+:[ 	]+02004053[ 	]+fadd\.d[ 	]+f0,f0,f0,rmm
[ 	]+[0-9a-f]+:[ 	]+e2001fd3[ 	]+fclass\.d[ 	]+x31,f0
[ 	]+[0-9a-f]+:[ 	]+e20f9053[ 	]+fclass\.d[ 	]+x0,f31
[ 	]+[0-9a-f]+:[ 	]+d2207053[ 	]+fcvt\.d\.l[ 	]+f0,x0
[ 	]+[0-9a-f]+:[ 	]+d2200053[ 	]+fcvt\.d\.l[ 	]+f0,x0,rne
[ 	]+[0-9a-f]+:[ 	]+d2307053[ 	]+fcvt\.d\.lu[ 	]+f0,x0
[ 	]+[0-9a-f]+:[ 	]+42000fd3[ 	]+fcvt\.d\.s[ 	]+f31,f0
[ 	]+[0-9a-f]+:[ 	]+420f8053[ 	]+fcvt\.d\.s[ 	]+f0,f31
[ 	]+[0-9a-f]+:[ 	]+d2000053[ 	]+fcvt\.d\.w[ 	]+f0,x0
[ 	]+[0-9a-f]+:[ 	]+d2100053[ 	]+fcvt\.d\.wu[ 	]+f0,x0
[ 	]+[0-9a-f]+:[ 	]+c2207053[ 	]+fcvt\.l\.d[ 	]+x0,f0
[ 	]+[0-9a-f]+:[ 	]+c2307053[ 	]+fcvt\.lu\.d[ 	]+x0,f0
[ 	]+[0-9a-f]+:[ 	]+40107fd3[ 	]+fcvt\.s\.d[ 	]+f31,f0
[ 	]+[0-9a-f]+:[ 	]+401ff053[ 	]+fcvt\.s\.d[ 	]+f0,f31
[ 	]+[0-9a-f]+:[ 	]+40100053[ 	]+fcvt\.s\.d[ 	]+f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+c2007053[ 	]+fcvt\.w\.d[ 	]+x0,f0
[ 	]+[0-9a-f]+:[ 	]+c2107053[ 	]+fcvt\.wu\.d[ 	]+x0,f0
[ 	]+[0-9a-f]+:[ 	]+1a007fd3[ 	]+fdiv\.d[ 	]+f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+1a0ff053[ 	]+fdiv\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+1bf07053[ 	]+fdiv\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+1a000053[ 	]+fdiv\.d[ 	]+f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+a2002fd3[ 	]+feq\.d[ 	]+x31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+a20fa053[ 	]+feq\.d[ 	]+x0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+a3f02053[ 	]+feq\.d[ 	]+x0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+a2000fd3[ 	]+fle\.d[ 	]+x31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+a3f00053[ 	]+fle\.d[ 	]+x0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+a20f8053[ 	]+fle\.d[ 	]+x0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+a2001fd3[ 	]+flt\.d[ 	]+x31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+a3f01053[ 	]+flt\.d[ 	]+x0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+a20f9053[ 	]+flt\.d[ 	]+x0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+00003f87[ 	]+fld[ 	]+f31,0\(x0\) # 0( <.*>)?
[ 	]+[0-9a-f]+:[ 	]+7ff03007[ 	]+fld[ 	]+f0,2047\(x0\) # 7ff( <.*>)?
[ 	]+[0-9a-f]+:[ 	]+80003007[ 	]+fld[ 	]+f0,-2048\(x0\) # f+800( <.*>)?
[ 	]+[0-9a-f]+:[ 	]+000fb007[ 	]+fld[ 	]+f0,0\(x31\)
[ 	]+[0-9a-f]+:[ 	]+00000f97[ 	]+auipc[ 	]+x31,0x0[ 	]+[0-9a-f]+:[ 	]+R_RISCV_PCREL_HI20[ 	]+dval
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_RELAX.*
[ 	]+[0-9a-f]+:[ 	]+000fb007[ 	]+fld[ 	]+f0,0\(x31\) # [0-9a-f]+( <.*>)?[ 	]+[0-9a-f]+:[ 	]+R_RISCV_PCREL_LO12_I[ 	]+.*
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_RELAX.*
[ 	]+[0-9a-f]+:[ 	]+a2000fd3[ 	]+fle\.d[ 	]+x31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+a20f8053[ 	]+fle\.d[ 	]+x0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+a3f00053[ 	]+fle\.d[ 	]+x0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+a2001fd3[ 	]+flt\.d[ 	]+x31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+a20f9053[ 	]+flt\.d[ 	]+x0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+a3f01053[ 	]+flt\.d[ 	]+x0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+02007fc3[ 	]+fmadd\.d[ 	]+f31,f0,f0,f0
[ 	]+[0-9a-f]+:[ 	]+020ff043[ 	]+fmadd\.d[ 	]+f0,f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+03f07043[ 	]+fmadd\.d[ 	]+f0,f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+fa007043[ 	]+fmadd\.d[ 	]+f0,f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+02000043[ 	]+fmadd\.d[ 	]+f0,f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+2a001fd3[ 	]+fmax\.d[ 	]+f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+2a0f9053[ 	]+fmax\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+2bf01053[ 	]+fmax\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+2a000fd3[ 	]+fmin\.d[ 	]+f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+2a0f8053[ 	]+fmin\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+2bf00053[ 	]+fmin\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+02007fc7[ 	]+fmsub\.d[ 	]+f31,f0,f0,f0
[ 	]+[0-9a-f]+:[ 	]+020ff047[ 	]+fmsub\.d[ 	]+f0,f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+03f07047[ 	]+fmsub\.d[ 	]+f0,f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+fa007047[ 	]+fmsub\.d[ 	]+f0,f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+02000047[ 	]+fmsub\.d[ 	]+f0,f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+12007fd3[ 	]+fmul\.d[ 	]+f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+120ff053[ 	]+fmul\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+13f07053[ 	]+fmul\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+12000053[ 	]+fmul\.d[ 	]+f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+22000fd3[ 	]+fmv\.d[ 	]+f31,f0
[ 	]+[0-9a-f]+:[ 	]+23ff8053[ 	]+fmv\.d[ 	]+f0,f31
[ 	]+[0-9a-f]+:[ 	]+f2000053[ 	]+fmv\.d\.x[ 	]+f0,x0
[ 	]+[0-9a-f]+:[ 	]+e2000053[ 	]+fmv\.x\.d[ 	]+x0,f0
[ 	]+[0-9a-f]+:[ 	]+22001fd3[ 	]+fneg\.d[ 	]+f31,f0
[ 	]+[0-9a-f]+:[ 	]+23ff9053[ 	]+fneg\.d[ 	]+f0,f31
[ 	]+[0-9a-f]+:[ 	]+02007fcf[ 	]+fnmadd\.d[ 	]+f31,f0,f0,f0
[ 	]+[0-9a-f]+:[ 	]+020ff04f[ 	]+fnmadd\.d[ 	]+f0,f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+03f0704f[ 	]+fnmadd\.d[ 	]+f0,f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+fa00704f[ 	]+fnmadd\.d[ 	]+f0,f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+0200004f[ 	]+fnmadd\.d[ 	]+f0,f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+02007fcb[ 	]+fnmsub\.d[ 	]+f31,f0,f0,f0
[ 	]+[0-9a-f]+:[ 	]+020ff04b[ 	]+fnmsub\.d[ 	]+f0,f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+03f0704b[ 	]+fnmsub\.d[ 	]+f0,f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+fa00704b[ 	]+fnmsub\.d[ 	]+f0,f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+0200004b[ 	]+fnmsub\.d[ 	]+f0,f0,f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+01f03027[ 	]+fsd[ 	]+f31,0\(x0\) # 0( <.*>)?
[ 	]+[0-9a-f]+:[ 	]+00003fa7[ 	]+fsd[ 	]+f0,31\(x0\) # 1f( <.*>)?
[ 	]+[0-9a-f]+:[ 	]+fe003027[ 	]+fsd[ 	]+f0,-32\(x0\) # f+e0( <.*>)?
[ 	]+[0-9a-f]+:[ 	]+000fb027[ 	]+fsd[ 	]+f0,0\(x31\)
[ 	]+[0-9a-f]+:[ 	]+00000f97[ 	]+auipc[ 	]+x31,0x0[ 	]+[0-9a-f]+:[ 	]+R_RISCV_PCREL_HI20[ 	]+dval
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_RELAX.*
[ 	]+[0-9a-f]+:[ 	]+000fb027[ 	]+fsd[ 	]+f0,0\(x31\) # [0-9a-f]+( <.*>)?[ 	]+[0-9a-f]+:[ 	]+R_RISCV_PCREL_LO12_S[ 	]+.*
[ 	]+[0-9a-f]+:[ 	]+R_RISCV_RELAX.*
[ 	]+[0-9a-f]+:[ 	]+22100fd3[ 	]+fsgnj\.d[ 	]+f31,f0,f1
[ 	]+[0-9a-f]+:[ 	]+220f8053[ 	]+fsgnj\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+23f00053[ 	]+fsgnj\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+22009053[ 	]+fsgnjn\.d[ 	]+f0,f1,f0
[ 	]+[0-9a-f]+:[ 	]+2200a053[ 	]+fsgnjx\.d[ 	]+f0,f1,f0
[ 	]+[0-9a-f]+:[ 	]+5a007fd3[ 	]+fsqrt\.d[ 	]+f31,f0
[ 	]+[0-9a-f]+:[ 	]+5a0ff053[ 	]+fsqrt\.d[ 	]+f0,f31
[ 	]+[0-9a-f]+:[ 	]+5a000053[ 	]+fsqrt\.d[ 	]+f0,f0,rne
[ 	]+[0-9a-f]+:[ 	]+0a007fd3[ 	]+fsub\.d[ 	]+f31,f0,f0
[ 	]+[0-9a-f]+:[ 	]+0a0ff053[ 	]+fsub\.d[ 	]+f0,f31,f0
[ 	]+[0-9a-f]+:[ 	]+0bf07053[ 	]+fsub\.d[ 	]+f0,f0,f31
[ 	]+[0-9a-f]+:[ 	]+0a000053[ 	]+fsub\.d[ 	]+f0,f0,f0,rne