<t> PANDA Taint Modeling </t>

# Quick Start Guide
The PANDA Instruction Taint Analysis System (PANDA-RED) can be installed and run under default settings by following the instructions below.
* <a href="#installationSection">Installation</a>
* <a href="#runningSection">Running the System</a>
* <a href="#exampleSection">Examples</a>

<h2 id="installationSection">Installation</h2>
### Running with Dockerfile
* Ubuntu 20.04 or above
* docker

Additionally, the latest docker image for both pandare and python. Use the following commands to get them:
```
docker pull pandare/panda
docker pull python
```

In the repository, there is a Dockerfile that uses these images to build the dependencies needed for Red PANDA. Building and running a shell in the Dockerfile may require root privledges but will allow you to run Red PANDA:

```
docker build -t image .
docker run -it image bash
```

Then you should be able to successfully run:
```
python3 panda_red/PANDARED.py <arguments>
```

### Non-Dockerfile Requirements (Note: This method is currently not recommended and is missing complete installation instructions)
* Ubuntu 20.04
* Python 3.7 or above

Close the git repository and navigate to the parent folder of the project. Then run:
```
pip install .
```
This installs the current version of RED to your python3 environment.

<h2 id="runningSection">Running</h2>
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
python3 modules/PANDARED.py -f
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

<h2 id=exampleSection>Examples</h2>

### Creating a Configuration File From Scratch
Argument configuration files can be a useful tool for storing complex sets of system arguments. Red Panda provides functionality to store whole configurations and partial configurations in files. Below is an example of creating one of these files from scratch and using it to execute a Red Panda instance.
<ol>
  <li>
  Begin by creating a new text file to store the custom configuration. Then open the file in a text editor.
    
    
    touch my_config.txt
  </li>
  <li>
  Once open specify the arguments desired for the configuration. This configuration is going to use the MIPS architecture with a focus on high instruction iteration counts. To do so we construct each line to be a single argument defined using the same syntax as on the command line. The value given for the argument is found on the following line.
    
    
  ```
  -architecture
  mips32
  -iterations
  100
  -analysis_model
  1
  -output_model
  threshold
  -threshold
  .5
  ```
  Notice that this argument list does not contain all the required arguments for a system run. Arguments not specified in the configuration file are specified during program execution, allowing for greater flexibility in configuration file uses.
  </li>
  <li>
  Now that the file is complete we can execute it using the following command:
  

    python3 /panda_red/PANDARED.py -random_instructions=10 -name=my_config_run @my_config.txt
  Notice that the two required arguments of instruction source and execution name are still specified. If we wanted to keep either of these consistent between runs we could move them to the configurable file much like the others.
  </li>
</ol>

### Using Non-random Instructions
<ol>
  <li>
  Using instructions from a source other than random can be useful for getting models for a subset of an assembly language. Red Panda supports this using non-random instruction lists. In order to do so first begin by creating a file for the desired instructions to be stored.
    
    touch my_instructions.txt
  </li>
  <li>
  Open the file and enter the instructions which you desire to run. The entered instructions must all be in the same instruction set architecture and be viable assembly for the keystone assembler. Here the add and sub instructions are entered for the mips ISA. Save and close the file afterwards.
    
  ```
  add $t0, $t1, $t2
  sub $t4, $t2, $t6
  ```
  </li>
  <li>
  Once the instructions are written it is time to run Red Panda. In order to run the system using the instruction list you must use the -instructions_file argument in place of the -random_instructions argument. The usage of which can be found as follows:
    
  ```
  python3 /panda_red/PANDARED.py -random_instructions=10 -name=my_instructions_run ...
    
  # Becomes
    
  python3 /panda_red/PANDARED.py -instructions_file=my_instructions.txt -name=my_instructions_run ...
  ```
  </li>
</ol>

### Using Non-random Byte Strings
<ol>
  <li>
  text
    
    touch my_bytes.txt
  </li>
  <li>
  text
    
  ```
  
  ```
  </li>
  <li>
  text
    
    python3 /panda_red/PANDARED.py -random_instructions=10 -name=my_config_run @my_config.txt
  </li>
</ol>

### Understanding Matrix Output
Text

### Understanding Threshold Output


# Package Import Implementation
To import the modules into the test files or scripts, run pip install . at the head of the tree (panda-taint-models folder)
Then the you can import from the module folder by using "from module."module_folder_name"."module_file" import *"
