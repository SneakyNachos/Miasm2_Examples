from miasm2.analysis.machine import Machine
from miasm2.core import asmblock
from miasm2.expression.expression import *
from miasm2.analysis.dse import DSEPathConstraint
from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.jitter.csts import PAGE_READ,PAGE_WRITE
import sys

dse = None

def xxx_exit(jitter):
	#When jit engine hits exit, die
	jitter.run=False
	return True

def xxx_exit_symb(dse):
	#Nothing, program dies after this
	pass

def xxx_read(jitter):

	#Get return address, arguments
	ret_addr,args = jitter.func_args_systemv(["fd","buf","count"])

	#Handle only file descriptor 0
	if args.fd == 0:
		user_input = raw_input("")
		jitter.vm.set_mem(args.buf,user_input[:args.count-1]+"\x00")

	else:
		#Fail
		print "Unable to handle other inputs"
		sys.exit(-1)
	#Set return address,return value

	jitter.func_ret_systemv(ret_addr,min(args.count,len(user_input)))
	
user_input_count = 0
def xxx_read_symb(dse):

	global user_input_count

	#Get registers and arguments
	regs = dse.ir_arch.arch.regs
	fd = dse.eval_expr(regs.RDI)
	buf = dse.eval_expr(regs.RSI)
	count = dse.eval_expr(regs.RDX)
	update = {}

	#Create symbolic memory map of the input buffer, one byte at a time
	lst = [x for x in xrange(dse.jitter.cpu.RSI,dse.jitter.cpu.RSI+dse.jitter.cpu.RDX)]

	#Force the sym engine to create expressions for each byte
	dse.symbolize_memory(lst)
	
	#symbolize return address and return value
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RIP.size)
	ret_value = ExprId('user_input_%s_size'%user_input_count,regs.RAX.size)
	user_input_count+=1
	
	#Update state
	update.update({
		regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		dse.ir_arch.pc: ret_addr,
		regs.RAX: ret_value
	})
	dse.update_state(update)

def xxx___libc_start_main_symb(dse):
	'''Libc start main return to main's address when done'''
	
	#Grab constants
	regs = dse.ir_arch.arch.regs
	top_stack = dse.eval_expr(regs.RSP)
	main_addr = dse.eval_expr(regs.RDI)
	argc = dse.eval_expr(regs.RSI)
	argv = dse.eval_expr(regs.RDX)
	hlt_addr = ExprInt(0x1337beef,64)
	
	#Update state with main address as next spot
	dse.update_state({
		ExprMem(top_stack,64):hlt_addr,
		regs.RDI:argc,
		regs.RSI:argv,
		dse.ir_arch.IRDst:main_addr,
		dse.ir_arch.pc:main_addr,
	})

def xxx_puts_symb(dse):

	#Get registers,return address
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)

	#Update state
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP + ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		regs.RIP: ret_addr,
	})

def xxx_printf_symb(dse):

	#Get registers,return address
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)

	#Get string
	string = dse.jitter.get_str_ansi(dse.jitter.cpu.RDI)

	#Update state with return value as len(string)
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		regs.RIP: ret_addr,
		regs.RAX: ExprInt(len(string),64)
	})	

def main():
	global dse

	#Argparse wrapper is within Sandbox_Linux_x86_64, but it also return a jitter object so w/e	
	parser = Sandbox_Linux_x86_64.parser(description="Sandbox")
	parser.add_argument('filename',help="filename")
	args = parser.parse_args()

	#start sandbox
	sb = Sandbox_Linux_x86_64(args.filename,args,globals())
	sb.jitter.init_run(sb.entry_point)
	
	#Stack cookies
	sb.jitter.vm.add_memory_page(0x28,PAGE_READ|PAGE_WRITE,"B"*100,"stack cookies")
	
	#Setup Dynamic Sym Engine and the machine
	machine = Machine("x86_64")
	dse = DSEPathConstraint(machine,produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)
	dse.attach(sb.jitter)
	dse.update_state_from_concrete()
	#dse.jitter.jit.log_mn = True	

	#DSE stubs are handled by functions in the globals, aka you the programmer
	dse.add_lib_handler(sb.libs,globals())

	#Run, print solutions
	sb.run()
	print dse.new_solutions

	pass
main()
