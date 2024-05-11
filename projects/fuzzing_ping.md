
# Fuzzing the ping command line utilities command line parameters.

Hi! Inspired by this: https://sha256.net/fuzzing-ping.html I decided to fuzz the ping utility myself, however instead of fuzzing the packet handling system, I decided to fuzz the command line parameters to see if there are some bugs which I could shake out.

# Creating some testcases

Ok, so I did my usual setup and forgot to document it here, so I will just skip it for now. For fuzzing I need to generate testcases and for that I created this quick little python script:







