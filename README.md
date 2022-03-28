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
python3 red_panda/REDPANDA.py <arguments>
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
To run RED PANDA in the default mode use the following command:
<b>
  
```
python3 red_panda/REDPANDA.py <arguments>
```
  
</b>
The following arguments must be specified on the command line:
  
* Name
* Architecture
* Instruction Source
* Instruction Iterations
* Analysis Model
* Output Model

### Config Mode
Sometimes it is useful to leverage the same settings over the course of multiple runs of RED without needing to input the same settings on command line each time. When this functionality is desired, you can use the RED configurable mode to accomplish it. Said mode is initialized as follows:
<b>
```
python3 modules/REDPANDA.py -f
```
</b>
To use config mode simply open <a>modules/debug.cfg</a> and edit the interior settings to match your desired settings.
<br></br>

### System Arguments
There are a variety of arguments to pass into RED. Below is a full list of what they mean and the types are input they expect. For argument fields that specify a list of options, specify the list number as input during runtime.

#### Name (-name)
Specifies the name of the system run. Used to generate output files.

Valid Options
* Any valid string

Usage Example: ``-name=default``

#### Architecture (-architecture)
Specifies the instructions set architecture RED PANDA is to run in. This also determines the ISA instructions are generated in during run time.

Valid Options
* mips32 - The MIPS instruction set
* x86-64 - The x86-64 or AMD64 instruction set

Usage Example: ``-architecture=mips32``

#### Instruction Source (-random_instructions, -bytes_file, -instructions_file)
Determines the source of instructions during the RED PANDA run. Instructions have three different supported sources. The -random_instructions option uses RED PANDA's internal instruction generator to randomly generate valid instructions in the system. The -bytes_file option allows you to specify a new line delimited file of assembled instructions in byte format. The -instructions_file option does the same using unassembled instructions in a chosen ISA.

##### Random Instructions
Valid Options
* Any positive 32-bit integer

Usage Example: ``-random_instructions=186``

##### Bytes File
Valid Options
* the path to a file holding instruction bytes

Usage Example: ``-bytes_file=bytes.txt``

##### Instructions File
Valid Options
* the path to a file holding unassembled instructions

Usage Example: ``-instructions_file=instructions.txt``

#### Instruction Iterations (-iterations)
Specifies the number of times an instruction is run to collect correlation data for a particular register. Note that this means that an architecture with 32 registers will run 32 times the entered number.

Valid Options
* Any positive 32-bit integer

Usage Example: ``-iterations=12``

#### Analysis Model (-analysis_model)
This specifies which type of analysis the system will perform. Currently reg-correlational and mem-reg-correlational perform the same analysis without or with memory tracking.

Valid Options
* 0 - generate correlations between registers only (currently only supported for basic mips functionality)
* 1 - generate correlations between registers and memory

Usage Example: ``-analysis_model=1``

#### Output Format (-output_model)
This specifies the output format of the system.

Valid Options
* 0 - matrix output (generates a matrix where ones in the matrix represent correlations between inputs in the row and outputs in the column)
* 1 - threshold output (generates a human readable message of unexpected correlations based on a p-value threshold)

Usage Example: ``-output_model=1``

#### Verbose? (-v/--verbose)
The specifies if you wish the system to output debug and progress messages.

Usage Example: ``-v``

#### Intermediate Output (-i/--intermediate)
Generates another json file of the full output of the randomly run instructions.

Usage Example: ``-i``

#### Output Threshold (-threshold)
The p-value threshold required for threshold output to recognize and output a correlation.

Valid Options
* Any decimal value between 0 and 1

Usage Example: ``-threshold=0.55``

#### Random Generation Seed (-seed)
A seed used by the random instruction generator. Used to ensure randomly generated instruction lists are consistent between runs.

Valid Options
* Any 32-bit integer

Usage Example: ``-seed=1352389``

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
  

    python3 /red_panda/REDPANDA.py -random_instructions=10 -name=my_config_run @my_config.txt
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
    
  Random Instructions: `` python3 /red_panda/REDPANDA.py -random_instructions=10 -name=my_instructions_run ... `` Becomes
    
  ```
  python3 /red_panda/REDPANDA.py -instructions_file=my_instructions.txt -name=my_instructions_run ...
  ```
  </li>
</ol>

# Package Import Implementation
To import the modules into the test files or scripts, run pip install . at the head of the tree (panda-taint-models folder)
Then the you can import from the module folder by using "from module."module_folder_name"."module_file" import *"
