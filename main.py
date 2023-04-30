import os

path = os.environ['PATH']  # get current PATH value
new_path = r'C:\Program Files\Python311\Scripts'  # directory to add to PATH
if new_path not in path:  # check if directory is already in PATH
    os.environ['PATH'] = new_path + ';' + path  # append directory to PATH

# now you can run any executables in the added directory from Python
os.system('django-admin --version')  # example of running django-admin from the added directory
