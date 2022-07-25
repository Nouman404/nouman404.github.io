---
title: Notes | Bash Scripting
author: Zeropio
date: 2022-07-25
categories: [Notes, Languages]
tags: [bash, scripts]
permalink: /notes/languages/bash-scripting
---

Bash is the scripting language we use to communicate with Unix-based OS and give commands to the system. The main difference between scripting and programming languages is that we don't need to compile the code to execute the scripting language, as opposed to programming languages. 

To run a bash script:
```console
zero@pio$ bash script.sh <optional arguments>
zero@pio$ sh script.sh <optional arguments>
zero@pio$ ./script.sh <optional arguments>
```

Remember to give execution privileges to the file:
```console
zero@pio$ chmod +x script.sh
```

---

# Components 

## Shebang

The shebang line is always at the top of each script and always starts with "#!". This line contains the path to the specified interpreter (/bin/bash) with which the script is executed. The shebang can be different:
```python
#!/usr/bin/env python
```

```perl
#!/usr/bin/env perl
```

## Conditional Execution 

Conditional execution allows us to control the flow of our script by reaching different conditions. This function is one of the essential components. Otherwise, we could only execute one command after another. One of the most fundamental programming tasks is to check different conditions to deal with these. Checking of conditions usually has two different forms in programming and scripting languages, the **if-else condition** and **case statements**.

By default, an **If-Else** condition can contain only a single `if`. For example:
```bash
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
        echo "Given argument is greater than 10."
fi
```

The execution would be:
```console
zero@pio$ bash if-only.sh 5

zero@pio$ bash if-only.sh 10 

Given argument is greater than 10.
```

When adding `Elif` or `Else`:
```bash
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
	echo "Given argument is greater than 10."
elif [ $value -lt "10" ]
then
	echo "Given argument is less than 10."
else
	echo "Given argument is not a number."
fi
```

The execution would be:
```console
zero@pio$ bash if-elif-else.sh 5

Given argument is less than 10.

zero@pio$ bash if-elif-else.sh 12

Given argument is greater than 10.

zero@pio$ bash if-elif-else.sh ZERO 

if-elif-else.sh: line 5: [: ZERO: integer expression expected
if-elif-else.sh: line 8: [: ZERO: integer expression expected
Given argument is not a number.
```

We could extend our script and specify *several conditions*:
```bash
#!/bin/bash

# Check for given argument
if [ $# -eq 0 ]
then
	echo -e "You need to specify the target domain.\n"
	echo -e "Usage:"
	echo -e "\t$0 <domain>"
	exit 1
elif [ $# -eq 1 ]
then
	domain=$1
else
	echo -e "Too many arguments given."
	exit 1
fi
```

Here we define another condition (`elif [<condition>];then`) that prints a line telling us (`echo -e "..."`) that we have given more than one argument and exits the program with an error (`exit 1`).

## Arguments 

The advantage of bash scripts is that we can always pass up to 9 arguments (**$0-$9**) to the script without assigning them to variables or setting the corresponding requirements for these. Nine arguments because the first argument `$0` is reserved for the script. As we can see here, we need the dollar sign `$` before the name of the variable to use it at the specified position. The assignment would look like this in comparison:
```console
zero@pio$ ./script.sh ARG1 ARG2 ARG3 ... ARG9
       ASSIGNMENTS:       $0      $1   $2   $3 ...   $9
```

## Variables 

There are some special variables:

| **IFS**   | **Description**    |
|--------------- | --------------- |
| `$#` | holds the number of arguments passed to the script   |
| `$@` | can be used to retrieve the list of command-line arguments |
| `$n` | Each command-line argument can be selectively retrieved using its position (for example, the first argument is found at `$1`) |
| `$$` | the process ID of the currently executing process |
| `$?` | exit status of the script, `0` -> successful execution, `1` -> failure |

The assignment of variables takes place without the dollar sign `$`. The dollar sign is only intended to allow this variable's corresponding value to be used in other code sections. When assigning variables, there must be *no spaces between the names and values*. There is no direct differentiation and recognition between the types of variables in Bash like **strings**, **integers**, and **boolean**. All contents of the variables are treated as string characters.

## Arrays 

There is also the possibility of assigning several values to a single variable in Bash. For example:
```bash
#!/bin/bash

domains=(www.zeropio.com ftp.zeropio.com vpn.zeropio.com www2.zeropio.com)

echo ${domains[0]}
```

The `' '` and `" "` create different objects:
```bash
#!/bin/bash

domains=("www.zeropio.com ftp.zeropio.com vpn.zeropio.com" www2.zeropio.com)

echo ${domains[0]}
```

This script output will be:
```console
zero@pio$ ./script.sh 

www.zeropio.com ftp.zeropio.com vpn.zeropio.com
```

## Comparison Operators

The **comparison operators** are used to determine how the defined values will be compared. We must differentiate between:
- **string** operators
- **integer** operators
- **file** operators
- **boolean** operators

### String Operators 

In order to compare strings:

| **Operator**   | **Description**    |
|--------------- | --------------- |
| `==` | is equal to   |
| `!=` | is not equal to |
| `<` | is less than in ASCII alphabetical order |
| `>` | is greater than in ASCII alphabetical order |
| `-z` | if the string is empty (null) |
| `-n` | if the string is not null |

If we put a variable name between `" "` (for example `"$1"`) bash handled it as a string.

We can get the ASCII table by:
```console
zero@pio$ man ascii
```

### Integer Operators 

In order to compare numbers:

| **Operator**   | **Description**    |
|--------------- | --------------- |
| `-eq` | is equal to |
| `-ne` | is not equal to |
| `-lt` | is less than |
| `-le` | is less than or equal to |
| `-gt` | is greater than |
| `-ge` | is greater than or equal to |

### File Operators 

To compare files:

| **Operator**   | **Description**    |
|--------------- | --------------- |
| `-e` | if the file exist |
| `-f` | tests if it is a file |
| `-d` | tests if it is a directory |
| `-L` | tests if it is if a symbolic link |
| `-N` | checks if the file was modified after it was last read |
| `-O` | if the current user owns the file |
| `-G` | if the file’s group id matches the current user’s |
| `-s` | tests if the file has a size greater than 0 |
| `-r` | tests if the file has read permission |
| `-w` | tests if the file has write permission |
| `-x` | tests if the file has execute permission |

### Logical Operators 

| **Operator**   | **Description**    |
|--------------- | --------------- |
| `!` |	logical negotation NOT |
| `&&` | logical AND |
| `||` | logical OR |

## Arithmetic 

### Arithmetic Operators 

| **Operator**   | **Description**    |
|--------------- | --------------- |
| `+` | Addition |
| `-` | Substraction |
| `*` | Multiplication | 
| `/` | Division |
| `%` | Modulus |
| `variable++` | Increase the value of the variable by 1 |
| `variable--` | Decrease the value of the variable by 1 |

We can also calculate the length of the variable: `${#variable}`

---

# Script Control 

## Input Control 

Some functions, like `read`, stop the program waiting for a user input. If we add `-p` the input will remain on the same line, for example:
```bash
read -p "Select your option: " opt
```

The variable `opt` can be used later in the `case` function:
```bash
case $opt in
	"1") case_1 ;;
	"2") case_2 ;;
	"3") case_3_1 && case_3_2 ;;
	"*") exit 0 ;;
esac
```

## Output Control 

We can use the command `tee` to write all our output into a file:
```bash
echo "Hi" | tee hi.txt
echo "Hi" | tee -a hi.txt
```

The flag `-a`/`--append` doesn't overwrite the file, just add new lines. At the same time, it show us the results.

## Flow Control

Each flow control can be a **branch** or a **loop**:
- Branch 
  - **If-Else** Conditions
  - **Case** Statements 
- Loops
  - **For** Loops
  - **While** Loops 
  - **Until** Loops

### For Loops 

An example could be an automatic ping:
```bash
for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
do
	ping -c 1 $ip
done
```

### While Loops 

The **While** Loops keep working until a statement stop being **True**. This script only works **while** `counter` is smaller than 10:
```bash
#!/bin/bash

counter=0

while [ $counter -lt 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"

  if [ $counter == 2 ]
  then
    continue
  elif [ $counter == 4 ]
  then
    break
  fi
done
```

### Until Loops 

The **Until** Loops is the reverse of the while. The code inside a until loop is executed as long as the particular condition is **false**. This script do the same as the last one:
```bash
#!/bin/bash

counter=0

until [ $counter -eq 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"
done
```

### Branches 

We can use the **Case** statements. 
```bash
case <expression> in
	pattern_1 ) statements ;;
	pattern_2 ) statements ;;
	pattern_3 ) statements ;;
esac
```

---

# Execution Flow 

## Functions 

Once the script is bigger and bigger it's get more chaotic. Adding function can be a resolve to this problem:
```bash
function name {
	<commands>
}
```

We can pass parameters within the functions:
```bash

#!/bin/bash

function print_pars {
	echo $1 $2 $3
}

one="First parameter"
two="Second parameter"
three="Third parameter"

print_pars "$one" "$two" "$three"
```

Once we create a new process, each **child process** send a **return code** to his **parent function**. This are the **return code**:

| **Return Code**   | **Description**    |
|--------------- | --------------- |
| `1` | General errors |
| `2` | Misuse of shell builtins |
| `126` | Command invoked cannot execute |
| `127` | Command not found |
| `128` | Invalid argument to exit |
| `128+n` | Fatal error signal `n` |
| `130` | Script terminated by `Ctrl + c` | 
| `255\*` | Exit status out of range |

## Debugging

The command `bash` allow us debugging using the option `-x` (**xtrace**) and `-v`. Bash shows us precisely which function or command was executed with which values. If we want to see all the code for a particular function, we can set the "-v" option that displays the output in more detail.
```console
zero@pio$ bash -x script.sh 
zero@pio$ bash -x -v script .sh 
```





