#!/usr/bin/python
###############################################################################
#MIT License
#
#Copyright (c) 2018 Israel Araoz Severiche
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.
###############################################################################
# Macphish (https://github.com/iaraoz/binsecurity)
# Version: 1.0 Beta
# Author: Israel Araoz <israel.araoz@gmail.com>
#
# binsecurity - Python script to check if Windows Binary (EXE/DLL) has ASLR,DEP,SafeSEH
#
# Usage: ./binsecurity -h
# ./binsecurity -b putty.exe --check
# ./binsecurity -dir C:\Windows\System32
# ./binsecurity -b putt.exe 
# ./binsecurity --single C:\Windows\System32\kernel32.dll

import sys
import core
import argparse



def main():
	core.get_banner()
	parser = argparse.ArgumentParser()
	parser.add_argument("-b","--bin",required=False,dest="bin",help="Name of binary")
	parser.add_argument("-s","--single",dest="dll",default=False,help="Name of dll")
	parser.add_argument("-d","--dir",dest="dir",default=False, help="Directory")
	parser.add_argument("-c","--check",dest="sc",default=False,action="store_true",help="Check security : ASLR,DEP,SafeSEH")
	parser.add_argument("-g","--get-section",dest="section",default=False,action="store_true",help="Section of Binary")
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	
	args = parser.parse_args()
	if args.bin and args.sc:
		core.get_dll(args.bin,True)
	else:
		if args.bin:
			core.get_dll(args.bin)
	if args.section:
		core.get_section(args.bin)
	if args.dir:
		core.get_path(args.dir)
	if args.dll:
		core.get_dll(args.dll)

if __name__=="__main__":
	main()
