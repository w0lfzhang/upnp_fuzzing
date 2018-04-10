'''
Some structures for fuzzing
'''

#A fuzz case's changeable part, it's just a description.
class Fuzz_case:
	def __init__(self, service_fullName, ctlurl, action, args):
		self.service_fullName = service_fullName
		self.ctlurl  = ctlurl
		self.action  = action
		#for args, it's a dictionary
		self.args    = args

#Types of fuzzing data, actually, it's real data~
class Fuzz_data:
	def __init__(self, int_fuzz, string_fuzz, delim_fuzz, fsb_fuzz):
		self.int_fuzz    = int_fuzz
		self.string_fuzz = string_fuzz
		self.delim_fuzz  = delim_fuzz
		self.fsb_fuzz    = fsb_fuzz

