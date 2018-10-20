
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

machine = Machine("x86_32")
dse = DSEPathConstraint(machine,produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)

def ptrace_bp(jitter):
	ret_addr, args = jitter.func_args_systemv(["s1","s2","s3","s4"])
	print "ptrace(%s,%s,%s,%s)"%(args.s1,args.s2,args.s3,args.s4)
	jitter.func_ret_systemv(ret_addr,0)
	return True

def atoi_bp(jitter):
	ret_addr,args = jitter.func_args_systemv(["input"])
	jitter.func_ret_systemv(ret_addr,args.input)
	dse.attach(jitter)
	dse.update_state_from_concrete()
	regs = dse.ir_arch.arch.regs
	dse.update_state({
		regs.EAX: ExprId("input",32)
	})	
	return True
	pass	

def stop_bp(jitter):
	print dse.new_solutions
	return False

def main():
	parser = Sandbox_Linux_x86_32.parser(description="Sandbox")
        parser.add_argument('filename',help="filename")
        args = parser.parse_args()
        sb = Sandbox_Linux_x86_32(args.filename,args,globals())
	sb.jitter.jit.log_mn=True
	sb.jitter.vm.add_memory_page(0x140004,PAGE_READ|PAGE_WRITE,struct.pack("<L",0x41414141))
	sb.jitter.vm.add_memory_page(0x41414145,PAGE_READ|PAGE_WRITE,struct.pack("<L",1234))
	sb.jitter.add_breakpoint(0x8048334,ptrace_bp)
	sb.jitter.add_breakpoint(0x8048354,atoi_bp)
	sb.jitter.add_breakpoint(0x80484fe,stop_bp)
	sb.run(0x8048438)
	pass
main()
