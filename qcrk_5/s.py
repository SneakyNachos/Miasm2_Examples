from miasm2.analysis.machine import Machine
from miasm2.core.utils import *
from miasm2.analysis.binary import Container
from miasm2.core import asmblock
from miasm2.expression.expression import *
from argparse import ArgumentParser
from miasm2.analysis.sandbox import Sandbox_Linux_x86_32
from miasm2.analysis.dse import DSEPathConstraint
from miasm2.jitter.csts import PAGE_READ,PAGE_WRITE
from miasm2.os_dep.linux_stdlib import *
import struct

#Machine, Dynamic Sym Engine
machine = Machine("x86_32")
dse = DSEPathConstraint(machine,produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)

def ptrace_bp(jitter):
	#Force ptrace to return 0, always
	ret_addr = jitter.get_stack_arg(0)
	jitter.func_ret_systemv(ret_addr,0)
	return True

def toint_bp(jitter):
	"""toInt handler, change input to a 32-bit integer"""
	ret_addr,args = jitter.func_args_systemv(["input"])	
	jitter.func_ret_systemv(ret_addr,args.input)
	dse.attach(jitter)
	dse.update_state_from_concrete()
	regs = dse.ir_arch.arch.regs
	dse.update_state({
		regs.EAX: ExprId("input",32)
	})
	return True

def printf_bp(jitter):
	global dse
	"""Printf handler, print the args"""
	print "printf(%s,%s)"%(jitter.get_str_ansi(jitter.get_stack_arg(1)),jitter.get_stack_arg(2))
	jitter.vm.set_mem(0x13ffb4,struct.pack("<L",0))
	jitter.cpu.EIP = jitter.get_stack_arg(0)
	jitter.pc = jitter.get_stack_arg(0)
	regs = dse.ir_arch.arch.regs
	return True
def jumpover_bp(jitter):
	"""Jump past 0x80482d1, modify the Dyn Sym Engine to patch the drift exception"""
	jitter.pc = 0x80482eb
	jitter.cpu.EIP = 0x80482eb
	regs = dse.ir_arch.arch.regs
	dse.update_state({
		regs.EDX: ExprInt(1335,32),	
		dse.ir_arch.IRDst: ExprInt(0x80482eb,32),
		regs.EIP: ExprInt(0x80482eb,32),
	})
	return True
	pass	
def finish_bp(jitter):
	#Dump Solutions
	global dse
	#The answer to the crackme will now pop out with the path taken to get to it
	"""
	{(ExprLoc(<LocKey 0>, 32), ExprLoc(<LocKey 1>, 32), ExprLoc(<LocKey 2>, 32), ExprLoc(<LocKey 3>, 32), ExprLoc(<LocKey 4>, 32), ExprLoc(<LocKey 5>, 32), ExprLoc(<LocKey 6>, 32), ExprLoc(<LocKey 7>, 32), ExprLoc(<LocKey 8>, 32), ExprLoc(<LocKey 9>, 32), ExprLoc(<LocKey 10>, 32), ExprLoc(<LocKey 11>, 32), ExprLoc(<LocKey 12>, 32), ExprLoc(<LocKey 13>, 32), ExprLoc(<LocKey 14>, 32), ExprLoc(<LocKey 15>, 32), ExprLoc(<LocKey 16>, 32), ExprLoc(<LocKey 18>, 32), ExprLoc(<LocKey 19>, 32), ExprLoc(<LocKey 20>, 32), ExprLoc(<LocKey 22>, 32)): [input = 91867153]}
	"""
	print dse.new_solutions
	jitter.run =False
def main():
	global dse
	"""Example of a heavy patchwork rework to force the key out of the program

	python s.py qcrk5
	"""
	parser = Sandbox_Linux_x86_32.parser(description="Sandbox")
        parser.add_argument('filename',help="filename")
        args = parser.parse_args()
        sb = Sandbox_Linux_x86_32(args.filename,args,globals())
	sb.jitter.jit.log_mn=True
	sb.jitter.add_breakpoint(0x804ea50,ptrace_bp)
	sb.jitter.add_breakpoint(0x8048be0,toint_bp)
	sb.jitter.add_breakpoint(0x8049530,printf_bp)
	sb.jitter.add_breakpoint(0x80482d1,jumpover_bp)	
	sb.jitter.add_breakpoint(0x8048314,finish_bp)
	sb.jitter.vm.add_memory_page(0x140000,PAGE_READ|PAGE_WRITE,struct.pack("<L",2))
	sb.jitter.vm.add_memory_page(0x140004,PAGE_READ|PAGE_WRITE,struct.pack("<L",0x41414141))
	sb.jitter.vm.add_memory_page(0x41414145,PAGE_READ,struct.pack("<L",1234))
	sb.run(addr=0x8048208)
	pass
main()
