#!/usr/bin/env python

from capstone import *
from capstone.arm  import *
from PIL import Image, ImageDraw

import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from matplotlib import colors


def setPic(img, file, color, lenDict):
	"""
	Set pixels in a figure
	"""
	draw = ImageDraw.Draw(img)
	pixels = img.load()
	for line in file:
		x = int(line, 16) % 0xA0
		y = int(line, 16) // 0xA0
		if line == "0x00001f38\n" or line == "0x000006b4\n" or line == "0x000006fc\n":
			pixels[x, y] = (0, 0, 0)
			pixels[x+1, y] = (0, 0, 0)
			continue
		pixels[x, y] = color
		pixels[x+1, y] = color
		if lenDict[line] == 4 and x+2>0xA0-1:
			pixels[0, y+1] = color
			pixels[1, y+1] = color
		elif lenDict[line] == 4 and x+2<0xA0-1:
			pixels[x+2, y] = color
			pixels[x+3, y] = color

	file.seek(0)



def insLength(romByte, file):
	"""
	Get a dictionary, which records each instructions length
	"""
	insLenDict = {}
	md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
	md.detail = True

	for line in file:
		code = romByte[int(line.strip(), 16):]
		for insn in md.disasm(code, int(line.strip(), 16), 4):
			# print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
			insLenDict[line] = insn.size
			break;
	file.seek(0)
	return insLenDict


def insFreq(romByte, file, red):
	"""
	Get a dictionary, which records each instructions length
	"""
	insFreqDict = {}

	for line in file:
		if line in insFreqDict:
			insFreqDict[line] += 1
		else:
			insFreqDict[line] = 1
	file.seek(0)

	df = []
	for i in range(0, 80):
		tmp = []
		for j in range(0, 80):
			tmp.append(1)
		df.append(tmp)

	for key, value in insFreqDict.items():
		x = int(key, 16) % 0xA0
		y = int(key, 16) // 0xA0

		df[y//2][x//2] += 1
	
	trans2blue = colors.LinearSegmentedColormap.from_list(name='Trans2Blue', colors=[(0., 0., 1., 0.), (0., 0., 1., 1.)])
	trans2red = colors.LinearSegmentedColormap.from_list(name='Trans2Red', colors=[(1., 0., 0., 0.), (1., 0., 0., 1.)])
	sns.set(color_codes=True)
	fig, ax = plt.subplots( nrows=1, ncols=1 )
	ax.set_axis_off()
	if red:
		ax = sns.heatmap(df, cmap=trans2red, cbar=False)
		fig.savefig('/tmp/1.png')
	else:
		ax = sns.heatmap(df, cmap=trans2blue, cbar=False)
		fig.savefig('/tmp/2.png')
	plt.close(fig)




if __name__ == "__main__":

	with open('./ins.bin', 'rb') as f:
		ROM = f.read()

	img1 = Image.new('RGB', (0xA0, 0xA0), "white")
	img2 = Image.new('RGB', (0xA0, 0xA0), "white")

	color = (0, 0, 255)
	with open('./boardInsTrace', 'r') as f:
		# insFreq(ROM, f, False)
		setPic(img1, f, color, insLength(ROM, f))

	color = (255, 0, 0)
	with open('./qemuInsTrace', 'r') as f:
		# insFreq(ROM, f, True)
		setPic(img2, f, color, insLength(ROM, f))

	img1 = img1.resize((0x280, 0x280))
	img2 = img2.resize((0x280, 0x280))

	img = Image.blend(img1, img2, 0.6)
	img.show()





