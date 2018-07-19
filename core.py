"""
https://docs.microsoft.com/en-us/windows/desktop/secbp/control-flow-guard
https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
# IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
# IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
# IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
# IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000 

"""
import os
import pefile
import fnmatch

#set PATH=%PATH%;c:\python27\

colors={		'HEADER':'\033[95m',
				'LINE' :'\033[90m',
    			'SUBTITLE':'\033[92m',
				'TITLE' :'\033[93m',
				'FAIL':'\033[91m',
				'ENDC':'\033[0m',
				'BOLD':'\033[1m',
				'UNDERLINE':'\033[4m'
		}

def get_banner():
	print_log("FAIL","""
  _     _                                _ _         
 | |   (_)                              (_) |        
 | |__  _ _ __  ___  ___  ___ _   _ _ __ _| |_ _   _ 
 | '_ \| | '_ \/ __|/ _ \/ __| | | | '__| | __| | | |
 | |_) | | | | \__ \  __/ (__| |_| | |  | | |_| |_| |
 |_.__/|_|_| |_|___/\___|\___|\__,_|_|  |_|\__|\__, |
                                                __/ |
                                               |___/ """)
	print_log("SUBTITLE","Version\t: v1.0 (Beta)")
 	print_log("SUBTITLE","Autor\t: Israel Araoz S.")
	print_log("SUBTITLE","Twitter\t: @yaritu_")
	print_log("SUBTITLE","Github\t: https://github.com/iaraoz/binsecurity\n")

def print_log(options, message):
	if	options in colors:
		if options == "SUBTITLE":
			print (colors[options] + "\t-> "+ message + colors['ENDC'])
		elif options == "TITLE":
			print(colors[options] +"[*] " + message + colors['ENDC'])
		elif options == "FAIL":
			print (colors[options] +"\t\n"+ message + colors['ENDC'])
		elif options == "LINE":
			print(colors[options] + "\t\t[!] "+ message + colors['ENDC'])


def get_section(binary):
	pe = pefile.PE(binary)
	print_log("TITLE","Analyzing header")
	print_log("SUBTITLE","AddressOfEntryPoint\t:\t" + hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
	print_log("SUBTITLE","ImageBase\t\t:\t"+hex(pe.OPTIONAL_HEADER.ImageBase))
	print_log("SUBTITLE","NumberoFSections\t:\t"+str(pe.FILE_HEADER.NumberOfSections))
	print_log("TITLE","Extracting sections....")
	for section in pe.sections:
		print_log("SUBTITLE","Section : "+section.Name.decode('utf-8'))
		print_log("LINE","Virtual Addres\t: "+ hex(section.VirtualAddress))
		print_log("LINE","Virtual Size\t: "+ hex(section.Misc_VirtualSize))
		print_log("LINE","Raw Size\t\t: "+ hex(section.SizeOfRawData))
	
def get_dll(binary,dependencie = False):
	if os.path.isfile(binary):
		pe = pefile.PE(binary)
		if pe.is_exe() and dependencie == False:
			print_log("TITLE","Check if binary has security check : "+ binary)
			check_security(binary)
		else:
			if not (pe.is_dll()):
				print_log("TITLE","Extracting dll from binary : "+ binary)
				for entry in pe.DIRECTORY_ENTRY_IMPORT:
					print_log("SUBTITLE","Analyzing : " + entry.dll.lower())
					check_security((entry.dll).lower())
			else:
				print_log("TITLE","Check if dll has security check")
				print_log("SUBTITLE","Analyzing : " + binary)
				check_security(binary)
		
	else:
		print_log("FAIL","File does not exist")


def find_path_dll(dll,path):
	for root, dirs,files in os.walk(path):
		if dll in files:
			return os.path.join(root,dll)


def check_security(dll,path = os.environ['WINDIR']):
	if os.path.isfile(dll):
		dll = pefile.PE(dll)
	else:
		dll = pefile.PE(find_path_dll(dll,path))	
	
	print_log("LINE","ASLR\t\t: " + str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE))
	print_log("LINE","DEP\t\t\t: " +str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NX_COMPAT))
	print_log("LINE","SafeSEH\t\t: "+str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_NO_SEH))
	print_log("LINE","ControlFlowGuard\t: "+str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_GUARD_CF))
	print_log("LINE","HighentropyVA\t: "+str(dll.OPTIONAL_HEADER.IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA))

def get_path(path):
	print_log("TITLE","Searching :"+path)
	if os.path.exists(path):
		dlls = os.listdir(path)
		for dll in dlls:
			if fnmatch.fnmatch(dll,"*.dll"):
				print_log("SUBTITLE","Analyzing : " + dll)
				check_security(dll,path)
	else:
		print_log("FAIL","ERROR: Directory does not exist")
