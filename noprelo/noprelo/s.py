from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.arch.x86 import regs
from miasm2.core.utils import *
from miasm2.expression.expression import *
from miasm2.analysis.dse import DSEPathConstraint
from miasm2.jitter.csts import PAGE_READ,PAGE_WRITE
from miasm2.os_dep.linux_stdlib import *
from miasm2.core import asmblock
from argparse import ArgumentParser
import sys

machine = Machine("x86_64")
dse = DSEPathConstraint(machine,produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)
def xxx___libc_start_main_symb(dse):
	regs = dse.ir_arch.arch.regs
	top_stack = dse.eval_expr(regs.RSP)
	main_addr = dse.eval_expr(regs.RDI)
	argc = dse.eval_expr(regs.RSI)
	argv = dse.eval_expr(regs.RDX)
	hlt_addr = ExprInt(0x13371acc,64)
	dse.update_state({
		ExprMem(top_stack,64):hlt_addr,
		regs.RDI: argc,
		regs.RSI: argv,
		dse.ir_arch.IRDst: main_addr,
		dse.ir_arch.pc: main_addr,
		regs.RIP: main_addr
	})
def xxx_ptrace(jitter):
	ret_addr, args = jitter.func_args_systemv(["request","pid","addr","data"])
	ret_value = 1337 
	jitter.func_ret_systemv(ret_addr,ret_value)
def xxx_ptrace_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	ret_value = ExprId('ptrace_return_value',64)
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8, regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		regs.RIP: ret_addr,
		regs.RAX: ret_value,
	})
def xxx_puts_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		dse.ir_arch.pc: ret_addr,
		
	})
	pass
def xxx_exit(jitter):
	return False
	pass
def xxx_exit_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		dse.ir_arch.pc: ret_addr,
	})
def xxx_strncmp_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	s1 = dse.jitter.get_str_ansi(dse.jitter.cpu.RDI,dse.jitter.cpu.RDX)
        s2 = dse.jitter.get_str_ansi(dse.jitter.cpu.RSI,dse.jitter.cpu.RDX)
	print cmp(s1,s2)
	if cmp(s1,s2) == 0:
		regs.zf = ExprInt(0,regs.zf.size)
	else:
		regs.zf = ExprInt(1,regs.zf.size)	
	dse.update_state({
		regs.pf: regs.zf,
		regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		dse.ir_arch.pc: ret_addr,
		regs.RAX: ExprInt(cmp(s1,s2),64),
	})	
def attach_dse(jitter):
	global dse
	jitter.cpu.RIP = 0x1076
	dse.attach(jitter)
	dse.update_state_from_concrete()
	#dse.jitter.jit.log_mn=True	
	return True
def fix_rdx(jitter):
	global dse
	dse.update_state({
		ExprMem(ExprInt(0x13ff98,64),64):ExprInt(2580338280,64),
	})
	return True
def fix_rax(jitter):
	global dse
	print "Check:%s"%jitter.cpu.RAX
	print "Check:%s"%struct.unpack("<Q",jitter.vm.get_mem(jitter.cpu.RBP - 52,8))
	regs = dse.ir_arch.arch.regs
	jitter.cpu.EAX = 0x13371acc 
	dse.update_state({
		regs.EAX: ExprInt(jitter.cpu.EAX,32),
		regs.zf: ExprInt(1,regs.zf.size),
		
	})
	return True
def xxx_strncmp(jitter):
	ret_addr, args = jitter.func_args_systemv(["ptr1","ptr2","size"])
	s1 = jitter.get_str_ansi(args.ptr1,args.size)
	s2 = jitter.get_str_ansi(args.ptr2,args.size)
	ret_value = cmp(s1,s2)
	if ret_value == 0:
		jitter.cpu.zf = 0
	jitter.func_ret_systemv(ret_addr,ret_value)
def main():
	global dse
	parser = Sandbox_Linux_x86_64.parser(description="Sandbox")
	parser.add_argument('filename',help='filename')
	args = parser.parse_args()
	sb = Sandbox_Linux_x86_64(args.filename,args,globals())
	sb.jitter.vm.add_memory_page(0x140008,PAGE_READ|PAGE_WRITE,"\x04\x20\x00\x00\x00\x00\x00\x00","stuff")
        #dse.attach(sb.jitter)
        #dse.update_state_from_concrete()
        dse.add_lib_handler(sb.libs,globals())
	#dse.jitter.jit.log_mn=True	
	sb.jitter.add_breakpoint(0x1074,attach_dse)
	sb.jitter.add_breakpoint(0x1286,fix_rax)
	sb.jitter.add_breakpoint(0x11f5,fix_rdx)
	sb.run(0x1074)		
	#print dse
	#print dse.new_solutions
        #print dse.symb.dump_mem()
        #print dse.symb.dump_id()
	
	pass
main()
