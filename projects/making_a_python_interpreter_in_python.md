
# Making a python interpreter in python

As the title suggest, this is my attempt at making a python interpreter in python. This is in large part inspired by this project: https://aosabook.org/en/500L/a-python-interpreter-written-in-python.html 

Note that this is a python bytecode interpreter, not a python compiler. This program is only supposed to execute .pyc files. Execution of a python program is split into two parts: compilation and interpretation. The compilation process first compiles the python source into python bytecode and then the interpreter actually runs this compiled bytecode inside a thing which is called a stack machine. https://en.wikipedia.org/wiki/Stack_machine 


