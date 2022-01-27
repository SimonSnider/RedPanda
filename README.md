<t> PANDA Taint Modeling </t>

# Quick Start Guide
The PANDA Instruction Taint Analysis System (PANDA-RED) can be installed and run under default settings by following the instructions below.

## Installation
#Requirements
* Ubuntu 20.04
* Python 3.7 or above

Close the git repository and navigate to the parent folder of the project. Then run:
```
pip install .
```
This installs the current version of RED to your python3 environment.


## Running
### Default Mode
To run RED in the default mode use the following command:
<b>
```
python3 modules/PANDARED.py
```
</b>
All arguments and system settings will be prompted after running the command.
<br><br/>

### Config Mode
Sometimes it is useful to leverage the same settings over the course of multiple runs of RED without needing to input the same settings on command line each time. When this functionality is desired, you can use the RED configurable mode to accomplish it. Said mode is initialized as follows:
<b>
```
python3 modules/PANDARED.py -c 
```
</b>
To use config mode simply open <a>modules/debug.cfg</a> and edit the interior settings to match your desired settings.
<br></br>

### System Arguments
There are a variety of arguments to pass into RED. Below is a full list of what they mean and the types are input they expect. For argument field that specify a list of options, specify the list number as input during runtime.

#### Output File Name
This specifies the name of the output file. This argument does not take in file type as that is generated based on the desired output format. 

#### Architecture
This specifies which architecture to generate and run instructions in. Currently MIPS is the only supported instruction set.

#### Instructions Mode
This specifies the input format of instructions to the system. The default of zero randomly generates instructions in the chosen architecture. Byte-specified mode takes a list of pre-assembled bytes corresponding to chosen instructions to run the current architecture. Text-specified mode takes a list of chosen unassembled instructions. By default these optional modes are given parameters in <a>modules/byte_specifications.txt</a> and <a>modules/instruction_specifications.txt</a> respectively.

#### Instruction Iterations
This specifies the number of times each instructions is run through panda with random inputs.

#### Analysis Model
This specifies which type of analysis the system will perform. Currently reg-correlational and mem-reg-correlational perform the same analysis without or with memory tracking.

#### Output Format
This specifies the output format of the system. By default the system produces a square matrix mapping the correlation between input and output.

#### Verbose?
The specifies if you wish the system to output debug and progress messages.

# Package Import Implementation
To import the modules into the test files or scripts, run pip install . at the head of the tree (panda-taint-models folder)
Then the you can import from the module folder by using "from module."module_folder_name"."module_file" import *"
