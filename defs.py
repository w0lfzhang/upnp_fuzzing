'''
Some initial functions
'''
import random

def init():
	with open('crash/data_crash', 'w+') as f:
		f.seek(0)
		f.truncate()

def get_random_str(fuzz):
	if len(fuzz) > 0:
		n = random.randint(0, len(fuzz) - 1)

	return fuzz[n]