import sys
import glob
import os
from subprocess import call

if len(sys.argv) != 2 or not os.path.isdir(sys.argv[1]):
    print "Usage: analyze_all.py <module folder>"
    quit()
	
binfiles = glob.glob(sys.argv[1] + "/*.bin")

for b in binfiles:
    k = b[:-3] + "key"
	
    print "Running analysis on module %s..." % b[:-3]

    call([sys.argv[1] + "/../x64/Release/WardenSigning.exe",
          "--binary", b, "--key", k, "--analyze"])