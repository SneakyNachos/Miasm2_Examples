from miasm2.analysis.binary import Container
from miasm2.analysis.machine import Machine
from miasm2.analysis.sandbox import Sandbox_Linux_x86_64
from miasm2.core.asmbloc import *
from miasm2.expression.expression import *
cfg = AsmCFG()
block = None
data = []
index = 0

def stop(jitter):
	global data
	jitter.run = False

	#Grab the Bytecode from the binary
	data = [c for c in jitter.vm.get_mem(0x6022a0,0x6024a7-0x6022a0)]

	return True

def sub_template(label_name,size,line):
	global index
	global data	

	#Check if there is data to append
	if line == None:
		#No Data
		label = AsmLabel("%s"%label_name,offset=index)
	else:
		#Data to append
		label = AsmLabel("%s %s"%(label_name,line),offset=index)

	#Create new block
	blk = AsmBlock(AsmLabel("loc_%s"%index))

	#Add instruction
	blk.lines.append(label)

	#Update program counter
	index+=size
	return blk

def interpret():
	global data
	global block
	global index
	global cfg

	#Functions for grabbing data next to the instruction
	one_byte = lambda i: map(hex,map(ord,data[i+1]))
	four_byte = lambda i: map(hex,map(ord,data[i+1:i+5]))
	multi_byte = lambda i: map(hex,map(ord,data[i+1:i+16]))

	#The virtual machines instructions 
	func_lst = {
		'f':("END",1,None),
		'g':("ADD",2,one_byte),
		'h':("SUB",2,one_byte),
		'i':("MUL",2,one_byte),
		'k':("INC",2,one_byte),
		'l':("DEC",2,one_byte),
		'm':("XOR",2,one_byte),
		'p':("PUSHD",5,four_byte),
		'q':("POP",2,one_byte),
		's':("MOVD",2,one_byte),
		'u':("LOOP",2,one_byte),
		'v':("CMP",2,one_byte),
		'w':("JL",2,one_byte),
		'x':("JG",2,one_byte),
		'y':("JZ",2,one_byte),
		'z':("INCD",1,None),
		'|':("FUN",16,multi_byte),
		'{':("DECD",1,None),
		'\xde':("NOP",1,None),
		'\xad':("NOP",1,None),
		'\xc0':("NOP",1,None),
		'\xde':("NOP",1,None),
	}

	#The new blocks of the virtual machine cfg
	blocks = {}

	#Keep Walking the bytecode
	while(index < len(data)):
		#Grab bytecode, check if in func_lst
		bcode = data[index]
		lst = func_lst.get(bcode,("",None))
		name = lst[0]
		size = lst[1]
		func = lst[2]

		#Get the block
		if func == None:
			blk = sub_template(name,size,None)
		else:
			line = func(index)
			blk = sub_template(name,size,line)

		#Add Block to the cfg one at a time
		if block == None:
			block = blk
			cfg.add_node(block)
		else:
			n_block = blk
			cfg.add_node(n_block)
			cfg.add_edge(block,n_block,AsmConstraint.c_next)
			block = n_block
		blocks.update({block.lines[0].offset:block})

	#Walk the cfg and point the jumps and loops to the jump locations
	for node in cfg._nodes:
		#Is a LOOP instruction
		if "LOOP" in node.lines[0].name:

			offset = int(node.lines[-1].name.split(" ")[1].replace("[","").replace("]","").replace("'",""),16)

			#Loops jumps backwards
			offset = node.lines[-1].offset-offset
			cfg.add_edge(node,blocks[offset],AsmConstraint.c_to)

		#Is a JUMP instruction
		if "J" in node.lines[0].name:
			offset = int(node.lines[-1].name.split(" ")[1].replace("[","").replace("]","").replace("'",""),16)

			#Jumps in the vm are forward jumps
			offset= node.lines[-1].offset+offset+2
			cfg.add_edge(node,blocks[offset],AsmConstraint.c_to)
	
	i = 0
	#Sort the blocks in order
	s_blks = sorted(blocks)
	while(True):
		
		blk = blocks[s_blks[i]]
		#Check if the block has only one edge to and from the block
		if len(cfg.successors(blk)) == 1 and len(cfg.predecessors(blk)) == 1:
			try:
				#Double checks for weird situations
				pred = cfg.predecessors(blk)[0]
				if (len(cfg.successors(pred)) == 1 and len(cfg.predecessors(pred)) == 1) or (len(cfg.predecessors(pred)) == 0):
					#Combine the node to the previous block
					succ = cfg.successors(blk)[0]
					pred.lines.append(blk.lines[0])
					if "END" not in blk.lines[0].name:
						cfg.add_edge(pred,succ,AsmConstraint.c_to)
					cfg.del_node(blk)
			except AssertionError:
				pass

		if i == s_blks.index(s_blks[-1]):
			#Hit the bottom, Bail
			break
		i+=1
def main():
	global cfg
	global block
	global data
	
	#Paint the cfg_before image from disassembly
	cont = Container.from_stream(open('300.bin'))
	bin_stream = cont.bin_stream
	adr = 0x401550
	machine = Machine(cont.arch)
	mdis = machine.dis_engine(bin_stream)
	blocks = mdis.dis_multibloc(adr)
	open("cfg_before.dot","w").write(blocks.dot())
	
	#Get filename
	parser = Sandbox_Linux_x86_64.parser(description="300.bin")
	parser.add_argument("filename",help="filename")
	options = parser.parse_args()
	options.mimic_env = True
	
	#Start Sandbox
	sb = Sandbox_Linux_x86_64(options.filename,options,globals())
	sb.jitter.init_run(sb.entry_point)
	sb.jitter.add_breakpoint(sb.entry_point,stop)
	machine = Machine("x86_64")
	sb.run()

	#Get bytecode
	interpret()

	#Paint cfg
	open("vm_graph.dot","w").write(cfg.dot())

main()
