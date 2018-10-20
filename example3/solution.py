from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.core.utils import *
from miasm2.expression.expression import *
from miasm2.core import asmblock
from miasm2.core.graph import MatchGraphJoker
from argparse import ArgumentParser
def main():
	#Setup Machine for arm, get filename
	machine = Machine('armtl')
	parser = ArgumentParser("Description")
	parser.add_argument('filename',help='filename')
	args = parser.parse_args()
	
	#Setup disassembly stream in container, get blocks and draw the graph
	cont = Container.from_stream(open(args.filename))
	bin_stream = cont.bin_stream
	mdis = machine.dis_engine(bin_stream)
	blocks = mdis.dis_multibloc(0x614)
	open("cfg.dot","w").write(blocks.dot())

	#Create a template for matching blocks in the control flow graph
	#Requirement 1) Don't get block 0xdf8, it can't disassemble
	#Requirement 2) Get ones that start with LDR 
	#Requirement 3) Get ones where the second to last instruction is CMP
	#No restructions for in going and out going edges
	mblock = MatchGraphJoker(name='mblock', restrict_in=False,restrict_out=False,filt=lambda block: block.label.offset != 0xdf8 and "LDR" in block.lines[0].name and "CMP" in block.lines[-2].name)

	#Basic block matcher 
	nblock = MatchGraphJoker(name="next",restrict_in=False,restrict_out=False)

	#Now it should match the blocks we want with the checks
	matcher = nblock >> mblock


	flag_storage = {}
	#Loop through matching template blocks
	for sol in matcher.match(blocks):
		try:
			#Grab position line
			pline = sol[mblock].lines[3]
			#Grab character check line
			cline = sol[mblock].lines[-2]
			#Transform character and position to integer
			pos = int(pline.arg2str(pline.args[1]),16)
			c = int(cline.arg2str(cline.args[1]),16)
			#If its NULL, ignore
			if c != 0:
				flag_storage.update({pos:c})
		except ValueError:
			#The F at the beginning is a NULL check
			pass
	#Print Flag
	flag = "".join(map(lambda x: chr(flag_storage[x]),sorted(flag_storage))).replace("F","I")
	print "F"+flag
	
	
	pass
main()
