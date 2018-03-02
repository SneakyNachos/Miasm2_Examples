from miasm2.analysis.machine import Machine
from miasm2.analysis.binary import Container
from miasm2.core.utils import *
from miasm2.expression.expression import *
from miasm2.core import asmblock
from miasm2.core.graph import MatchGraphJoker
from argparse import ArgumentParser
def main():
	machine = Machine('armtl')
	parser = ArgumentParser("Description")
	parser.add_argument('filename',help='filename')
	args = parser.parse_args()
	
	cont = Container.from_stream(open(args.filename))
	bin_stream = cont.bin_stream
	mdis = machine.dis_engine(bin_stream)
	
	blocks = mdis.dis_multibloc(0x614)
	open("cfg.dot","w").write(blocks.dot())
	mblock = MatchGraphJoker(name='mblock', restrict_in=False,restrict_out=False,filt=lambda block: block.label.offset != 0xdf8 and "LDR" in block.lines[0].name and "CMP" in block.lines[-2].name)

	nblock = MatchGraphJoker(name="next",restrict_in=False,restrict_out=False)
	matcher = nblock >> mblock


	flag_storage = {}
	for sol in matcher.match(blocks):
		try:
			pline = sol[mblock].lines[3]
			cline = sol[mblock].lines[-2]
			pos = int(pline.arg2str(pline.args[1]),16)
			c = int(cline.arg2str(cline.args[1]),16)
			if c != 0:
				flag_storage.update({pos:c})
		except ValueError:
			pass
		
	flag = "".join(map(lambda x: chr(flag_storage[x]),sorted(flag_storage))).replace("F","I")
	print "F"+flag
	
	
	pass
main()
