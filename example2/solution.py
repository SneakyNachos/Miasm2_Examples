from miasm2.core import asmblock
from miasm2.expression.expression import *
from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.analysis.machine import Machine
from miasm2.analysis.dse import DSEPathConstraint
from miasm2.jitter.csts import PAGE_READ,PAGE_WRITE
from miasm2.os_dep.linux_stdlib import *
import sys
import os
def xxx___libc_start_main_symb(dse):
	regs = dse.ir_arch.arch.regs
	top_stack = dse.eval_expr(regs.RSP)
	main_addr = dse.eval_expr(regs.RDI)
	argc = dse.eval_expr(regs.RSI)
	argv = dse.eval_expr(regs.RDX)
	hlt_addr = ExprInt(0x1337beef,64)
	dse.update_state({
		ExprMem(top_stack,64):hlt_addr,
		regs.RDI:argc,
		regs.RSI:argv,
		dse.ir_arch.IRDst:main_addr,
		dse.ir_arch.pc:main_addr,
		regs.RIP:main_addr,
	})
def xxx_read(jitter):
	ret_addr,args = jitter.func_args_systemv(["fd","buf","count"])
	if args.fd == 0 or args.fd == 1:
		user_input = raw_input("")
		jitter.vm.set_mem(args.buf,user_input+"\x00")
	else:
		print "Unable to handle other inputs"
		sys.exit(-1)
	jitter.func_ret_systemv(ret_addr,min(args.count,len(user_input)))
	
def xxx_read_symb(dse):
	global user_input_index
	regs = dse.ir_arch.arch.regs
	update = {}
	ret_addr= ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	lst = [x for x in xrange(dse.jitter.cpu.RSI,dse.jitter.cpu.RSI+dse.jitter.cpu.RDX)]
	dse.symbolize_memory(lst)
	ret_value = ExprId('user_input_%s_size'%user_input_index,regs.RSP.size)
	update.update({
		regs.RSP:dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst:ret_addr,
		dse.ir_arch.pc:ret_addr,
		regs.RAX:ret_value,
	})
	user_input_index+=1
	dse.update_state(update)	

def xxx_write(jitter):
	ret_addr,args = jitter.func_args_systemv(["fd","buf","count"])
	s = jitter.get_str_ansi(args.buf)
	os.write(args.fd,s[:args.count])
	jitter.func_ret_systemv(ret_addr,args.count)
def xxx_write_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	ret_value = dse.eval_expr(regs.RDX)
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst:ret_addr,
		regs.RIP:ret_addr,
		regs.RAX:ret_value,
	})

addr = None
user_input_index = 0

def xxx_malloc(jitter):
	global addr
	ret_addr,args = jitter.func_args_systemv(["msize"])
	jitter.func_ret_systemv(ret_addr,addr)
def xxx_malloc_symb(dse):
	global addr
	update = {}
	regs = dse.ir_arch.arch.regs
	addr = linobjs.heap.alloc(dse.jitter,int(dse.eval_expr(regs.RDI)))
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	lst = [x for x in xrange(addr,dse.jitter.cpu.RDI+addr)]
	dse.symbolize_memory(lst)
	ret_value = ExprInt(addr,64)
	update.update({
		regs.RSP:dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst:ret_addr,
		dse.ir_arch.pc:ret_addr,
		regs.RAX: ret_value,
	})
	dse.update_state(update)

def xxx_strlen_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	string = dse.jitter.get_str_ansi(dse.jitter.cpu.RDI)
	ret_value = len(string)
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst:ret_addr,
		regs.RIP: ret_addr,
		regs.RAX: ExprInt(len(string),64),
	})

def xxx_strncmp(jitter):
	ret_addr, args = jitter.func_args_systemv(["s1","s2","count"])
	s1 = jitter.vm.get_mem(args.s1,args.count)
	s2 = jitter.vm.get_mem(args.s2,args.count)
	if s1 == s2:
		ret_value = 0
	else:
		ret_value = 1
	jitter.func_ret_systemv(ret_addr,ret_value)

def xxx_strncmp_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	s1 = int(dse.jitter.cpu.RDI)
	s2 = int(dse.jitter.cpu.RSI)
	count = int(dse.jitter.cpu.RDX)
	index = 0
	string1 = dse.jitter.vm.get_mem(s1,32)
	string2 = dse.jitter.get_str_ansi(dse.jitter.cpu.RSI)
	ret_value = 0
	while(count != index):
		print index,ord(string1[index]),ord(string2[index])
		s1_e = dse.eval_expr(ExprMem(ExprInt(s1+index,64),8))
		s2_e = dse.eval_expr(ExprMem(ExprInt(s2+index,64),8))
		eaff = ExprAff(s2_e,s1_e)
		dse.cur_solver.add(dse.z3_trans.from_expr(eaff))
		if ord(string1[index]) != ord(string2[index]):
			ret_value = 1
			break
		index+=1
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		regs.RIP: ret_addr,
		regs.RAX: ExprInt(ret_value,64),

	})

def main():
	parser = Sandbox_Linux_x86_64.parser(description="Sandbox")
	parser.add_argument('filename',help='filename')
	args = parser.parse_args()
	
	sb = Sandbox_Linux_x86_64(args.filename,args,globals())
	sb.jitter.init_run(sb.entry_point)
	sb.jitter.vm.add_memory_page(0x28,PAGE_READ|PAGE_WRITE,"B"*100,"stack cookies")
	machine = Machine("x86_64")
	dse = DSEPathConstraint(machine,produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)
	dse.attach(sb.jitter)
	dse.update_state_from_concrete()
	dse.add_lib_handler(sb.libs,globals())
	#dse.jitter.jit.log_mn=True
	sb.run()

	dse.cur_solver.check()
	model = dse.cur_solver.model()
	print model
main()
