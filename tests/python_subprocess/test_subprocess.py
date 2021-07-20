import subprocess
# Define command as string and then split() into list format
cmd = '/bin/ls -ltr'.split()

# Check the list value of cmd
print('command in list format:',cmd,'\n')

# Use shell=False to execute the command
sp = subprocess.Popen(cmd,shell=False,stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
print('Popen returned\n')
# Store the return code in rc variable
rc=sp.wait()
print('Return Code:',rc,'\n')
# Separate the output and error.
# This is similar to Tuple where we store two values to two different variables
out,err=sp.communicate()


print('output is: \n', out)
print('error is: \n', err)