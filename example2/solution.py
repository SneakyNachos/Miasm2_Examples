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
	'''	
	Dynamic Stub for libc_start_main
	proto:libc_start_main(main_addr,argc,argv)
	Desc: Sets up main
	Return Value: main
	
	'''
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
	'''
	Jitter replacement for libc_read
	proto:read(fd,buf,count)
	Return Value: length of read input
	'''
	
	#Get return address, arguments
	ret_addr,args = jitter.func_args_systemv(["fd","buf","count"])
		
	#Only handle fd of 0 or 1
	if args.fd == 0 or args.fd == 1:
		#Grab input, put in memory
		user_input = raw_input("")
		jitter.vm.set_mem(args.buf,user_input+"\x00")
	else:
		#Can't handle other fd's 
		print "Unable to handle other inputs"
		sys.exit(-1)
	#Set return address and return value
	jitter.func_ret_systemv(ret_addr,min(args.count,len(user_input)))
	
def xxx_read_symb(dse):
	'''
	Dynamic Stub for read
	proto: read(fd,buf,count)
	Return Value: length of read input
	'''
	global user_input_index
	#Get registers
	regs = dse.ir_arch.arch.regs
	update = {}

	#Return address is on the stack
	ret_addr= ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)

	#Setup list of memory index's as integers
	lst = [x for x in xrange(dse.jitter.cpu.RSI,dse.jitter.cpu.RSI+dse.jitter.cpu.RDX)]
	
	#Tell sym engine to symbolize all those memory indexes
	dse.symbolize_memory(lst)
	
	#Return Value is an expression of size
	ret_value = ExprId('user_input_%s_size'%user_input_index,regs.RSP.size)
	
	#Update the state
	update.update({
		regs.RSP:dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst:ret_addr,
		dse.ir_arch.pc:ret_addr,
		regs.RAX:ret_value,
	})
	user_input_index+=1
	dse.update_state(update)	

def xxx_write(jitter):
	'''
	Jitter replace for write
	proto:write(fd,buf,count)
	return value: count
	'''
	#Get return address, arguments
	ret_addr,args = jitter.func_args_systemv(["fd","buf","count"])

	#Get string from memory
	s = jitter.get_str_ansi(args.buf)

	#Print string
	os.write(args.fd,s[:args.count])

	#Set return address,return value
	jitter.func_ret_systemv(ret_addr,args.count)

def xxx_write_symb(dse):
	'''
	DSE stub
	This one was somewhat ignored
	'''
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
	'''
	Jitter stub
	malloc(size)
	'''
	global addr
	#Get return address,arguments
	ret_addr,args = jitter.func_args_systemv(["msize"])

	#Set return address,return value
	jitter.func_ret_systemv(ret_addr,addr)

def xxx_malloc_symb(dse):
	global addr
	update = {}
	regs = dse.ir_arch.arch.regs

	#Malloc address
	addr = linobjs.heap.alloc(dse.jitter,int(dse.eval_expr(regs.RDI)))

	#Setup return address
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)
	
	#Symbolize the mallocs memory
	lst = [x for x in xrange(addr,dse.jitter.cpu.RDI+addr)]
	dse.symbolize_memory(lst)
	ret_value = ExprInt(addr,64)
	
	#Update DSE
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
	
	#Get string from memeory
	string = dse.jitter.get_str_ansi(dse.jitter.cpu.RDI)

	#Return value of strlen is the length of string
	ret_value = len(string)
	
	#Update DSE
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst:ret_addr,
		regs.RIP: ret_addr,
		regs.RAX: ExprInt(len(string),64),
	})

def xxx_strncmp(jitter):
	#Get return address,arguments
	ret_addr, args = jitter.func_args_systemv(["s1","s2","count"])
	#Get string 1 and 2
	s1 = jitter.vm.get_mem(args.s1,args.count)
	s2 = jitter.vm.get_mem(args.s2,args.count)
	#Cheating the check
	if s1 == s2:
		ret_value = 0
	else:
		ret_value = 1
	#Set return address,value
	jitter.func_ret_systemv(ret_addr,ret_value)

def xxx_strncmp_symb(dse):
	regs = dse.ir_arch.arch.regs
	ret_addr = ExprInt(dse.jitter.get_stack_arg(0),regs.RSP.size)

	#Get string 1 and 2 ptrs
	s1 = int(dse.jitter.cpu.RDI)
	s2 = int(dse.jitter.cpu.RSI)

	#Get count
	count = int(dse.jitter.cpu.RDX)

	index = 0

	#Get strings from memory
	string1 = dse.jitter.vm.get_mem(s1,32)
	string2 = dse.jitter.get_str_ansi(dse.jitter.cpu.RSI)
	ret_value = 0

	#Hard part
	while(count != index):
		print index,ord(string1[index]),ord(string2[index])
		#Create the expression for each byte in the strings
		s1_e = dse.eval_expr(ExprMem(ExprInt(s1+index,64),8))
		s2_e = dse.eval_expr(ExprMem(ExprInt(s2+index,64),8))

		#s2_e = s1_e, expression
		eaff = ExprAff(s2_e,s1_e)

		#Add to z3 engine in dse
		dse.cur_solver.add(dse.z3_trans.from_expr(eaff))
	
		#If they don't match bail out
		if ord(string1[index]) != ord(string2[index]):
			ret_value = 1
			break
		index+=1

		#Update dse
	dse.update_state({
		regs.RSP: dse.symb.eval_expr(regs.RSP+ExprInt(8,regs.RSP.size)),
		dse.ir_arch.IRDst: ret_addr,
		regs.RIP: ret_addr,
		regs.RAX: ExprInt(ret_value,64),

	})

def main():
	#Grab Filename
	parser = Sandbox_Linux_x86_64.parser(description="Sandbox")
	parser.add_argument('filename',help='filename')
	args = parser.parse_args()
	
	#Create Sandbox at entry of binary
	sb = Sandbox_Linux_x86_64(args.filename,args,globals())
	sb.jitter.init_run(sb.entry_point)

	#Stack cookies
	sb.jitter.vm.add_memory_page(0x28,PAGE_READ|PAGE_WRITE,"B"*100,"stack cookies")
	
	#Create dynamic symbolic engine
	machine = Machine("x86_64")
	dse = DSEPathConstraint(machine,produce_solution=DSEPathConstraint.PRODUCE_SOLUTION_PATH_COV)
	dse.attach(sb.jitter)

	#Setup dse, all libraries are now handled by names in the globals
	dse.update_state_from_concrete()
	dse.add_lib_handler(sb.libs,globals())
	#dse.jitter.jit.log_mn=True

	#Run
	sb.run()

	#Print answers
	dse.cur_solver.check()
	model = dse.cur_solver.model()
	print model
main()
