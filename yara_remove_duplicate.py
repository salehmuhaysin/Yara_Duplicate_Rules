


import argparse


# ======================= Arguments =========================# 
a_parser = argparse.ArgumentParser('Python script tool remove duplicate rules from Yara file')


requiredargs = a_parser.add_argument_group('required arguments')
requiredargs.add_argument('-i', dest='in_file', help='Input Yara file', required=True)
requiredargs.add_argument('-o' , dest='out_file' , help='output Yara file with no duplication', required=True)
a_parser.add_argument('-v' , dest='verbose' , help='print more details (default disabled)' , action='store_true')
a_parser.add_argument('-nh' , dest='no_header' , help='Dont print the header (default enabled)' , action='store_true')


args = a_parser.parse_args()

file_path = args.in_file
output_file = args.out_file

if not args.no_header:
	print """                           
	                        *
	                    _:*///:_                     
	                _+*///////////+_                
	    ____----*////////////////////**----____    
	   *//////////////////////////////////********    
	   */////////////////       ////**************    
	   *////////////////          /***************    
	   *///////////////   /////   ****************    
	   *//////////////   /////**   ***************    
	   *//////////////   ////***   ***************    
	   *//////////////   ///****   ***************    
	   *////////////                 *************    
	   *////////////    Saleh Bin    *************    
	   *////////////     Muhaysin    *************    
	   *////////////                 *************    
	    *////////********************************     
	     */////  github.com/salehmuhaysin  *****      
	      *///*********************************             
	=========================================================="""


# ======================= Global Functions =========================# 
def print_logs(msg , verbose=False):
	if (verbose and args.verbose) or (not verbose):
		print msg
# ======================= Global Parameters =========================# 

# read the input file content 
file_yara = open(file_path , 'r')
file_content = file_yara.read()
file_yara.close()

yara_rule_names 	= [] 	# contain rule names
yara_rule_content 	= []	# contain rule content
yara_imports_content= []	# contain import content

duplicate_rules 	= 0		# number of duplicate rules
rule_addr 			= 0		# iteratable starting address of the input file (rules)
import_addr			= 0		# iteratable starting address of the input file (imports)

output_yara = open(output_file , 'w+') # objcet of output file

# ======================= Get All Imports =========================# 
while True:
	import_addr = file_content.find("\nimport " , import_addr+1)
	
	# if there are not more rules exit the loop
	if import_addr == -1:
		break 

	end_import = file_content.find("\n" , import_addr+1)
	import_content = file_content[import_addr+1:end_import]
	if import_content in yara_imports_content:
		print_logs("[/] Import ["+import_content+"] is Duplicate" , verbose=True)
		continue
	print_logs("[+] Imports: " + import_content)

	yara_imports_content.append(import_content)

	output_yara.write(import_content + "\n")


# ======================= Remove Duplicate Rules =========================# 
while True:

	rule_addr = file_content.find("\nrule " , rule_addr+1)
	
	# if there are not more rules exit the loop
	if rule_addr == -1:
		break 

	print_logs("[+] Rule pos: " + str(rule_addr) , verbose=True)
	# get rule name
	rule_name_end = rule_addr
	while file_content[rule_name_end] not in [":" , "{"]:
		rule_name_end +=1 
	rule_name = file_content[rule_addr+6:rule_name_end].strip()

	if rule_name in yara_rule_names:
		duplicate_rules += 1
		print_logs("[/] Rule ["+rule_name+"] is Duplicate" , verbose=True)
		continue

	print_logs("[+] Rule Name: " + rule_name)
	yara_rule_names.append(rule_name)

	# get the rule content
	is_opened = False
	opening_addr = rule_addr
	closing_addr = file_content.find('\n}' , opening_addr)+2


	rule_content = file_content[opening_addr:closing_addr].strip()
	print_logs( "[+] Rule Content: \n" + rule_content  , verbose=True)
	yara_rule_content.append(rule_content)

	output_yara.write( "\n\n\n" + rule_content)


output_yara.close()

print_logs( "\n\n[+] Done! \n[+] Imports: "+str(len(yara_imports_content))+" \n[+] Unique Rules: " + str(len(yara_rule_names)) + "\n[+] Duplicate Rules: " + str(duplicate_rules) + "\n[+] Output written to ["+output_file+"]" )

# rules = yara.compile(filepath=file_path)

