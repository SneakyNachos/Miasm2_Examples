from miasm2.analysis.machine import Machine
from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.jitter.csts import PAGE_READ, PAGE_WRITE
from miasm2.expression.expression import *

read_ptr = 0
def jumpPipe(jitter):
	#Skip the Pipe instruction, modify to our needs
	global read_ptr
	print "Hit jumppipe"
	jitter.cpu.RIP = 0x400c1d
	jitter.pc = 0x400c1d
	print hex(jitter.cpu.RAX)
	
	jitter.vm.set_mem(jitter.cpu.RAX,"hax0rz!~")
	jitter.cpu.RAX = 9

	return True

def saveVersionName(jitter):
	#Skip version name, modify to our needs
	jitter.cpu.RIP = 0x400d55
	jitter.pc = 0x400d55
	jitter.vm.set_mem(jitter.cpu.RAX,"2.4.31\x00")
	return True

def saveCpuId(jitter):
	#Skip cpuid, modify to our needs
	jitter.vm.set_mem(jitter.cpu.RAX,"AMDisbetter!")
	return True

def main():
	
	#Get filename
	parser = Sandbox_Linux_x86_64.parser(description="Sandbox")
	parser.add_argument("filename",help="filename")
	options = parser.parse_args()
	
	#Setup sandbox
	sb = Sandbox_Linux_x86_64(options.filename,options,globals())
	sb.jitter.ir_arch.do_all_segm=True

	#Stack cookies and what not
	sb.jitter.vm.add_memory_page(0,PAGE_READ,"B"*100,"fs")
	
	#Add Breakpoints,Run
	sb.jitter.add_breakpoint(0x400b6f,jumpPipe)
	sb.jitter.add_breakpoint(0x400c6c,saveVersionName)
	sb.jitter.add_breakpoint(0x400b2f,saveCpuId)
	sb.run()
main()
