# Paranoid Pipes Bash Logics

## Internal `bash` commands used within this project's scripts

### `touch`

> Make an empty file or modify the last edit time on preexisting file.
> Within this script `touch` is used within the function `Func_rotate_log`
> To make a new empty log file that `chmod` & `chown` commands can be run
> against for setting correct permissions up again. Functions that make
> use of this command within the `Paranoid_Pipes.sh` script include
> `Func_messages`, `Func_rotate_log`, `Func_mkpipe_reader`,
> `Rotate_output_file` & `Pipe_parser_loop`.

### `trap`

> Traps exit signals and runs a command prior to giving control back to parent.
> Within this script `trap` is used within a few `case` statements but mainly
> provides *clean-up* of named pipe files and script generated log files via
> calling function `Func_trap_cleanup` at the proper time.

### `read`

> Read user input (from keyboard) and save string received as a variable
> Within this script `read` is used for reading user input for simple `yes` or
> `no` questions via function `Func_prompt_continue`, and usually results in
> either continuing or exiting with an error code greater than `0`

### `mapfile`

> Map a file or input to an array that may contain multiple addresses or lines.
> Within this script `mapfile` is used by first calling the function
> `Func_mkpipe_reader` which within it's `while` loop calls the function
> `Map_read_array_to_output` that then intern calls `mapfile` command in order
> to read multiple write actions on a named pipe file at one time. The authors
> admit that this one section of the main script is a little *funky* to wrap
> ones brain around, however, it works wonderfully and without padding does
> slim down considerably. So make an effort to understand these two functions
> and how they preform their *magic* with `mapfile` and output redirection.

### `set`

> Set bash environment setting.
> Within this script `set` is used to turn off logging of command line actions
> to your `~/.bash_history` file within the same terminal window that it is
> actively running in. Logging is automatically turned back on again when this
> script exits.

### `let`

> Let a numerical value equal a new value.
> Within this script `let` is used to set variables that only contain numerical
> values; `0`, `1`,... and is used for it's built in arithmetic. Often you'll
> find that `let` will be used in combination with arrays to iterate though
> their address or index value.

### `disown`

> Disown a process by `pid` or previous process found in stack if unspecified.
> Within this script `disown` is used to *background* specific looping functions
> so that the terminal maybe freed-up for further user input.

### `break`

> Break from loop or other bash logic expression
> Within this script `break` is used

## Internal `bash` logic operators used within this project's scripts

### `case`

> Within other languages also known as a `switch` statement, `case` matches
> against various conditions and then switches control to another process.
> Within this script `case` is used to match against `yes` or `no` like
> statements read from user input as well as in instances where the script
> could take more than one action on input but should only take one. Used
> within loops `case` is used to set user input variables based upon command
> line option matching.

### `for`

> For each in list do something with each listed.
> Within this script `for` loops are used for iterating over lists of options
> and then *feeding* them one by one to another process or command.

### `if`

> If condition is true then do something else do something else.
> Within this script `if` is used much like `case` statements for matching
> various conditions equality or falseness.

### `until`

> Until true do something.
> Within this script `until` is used to loop through array indexes until the
> total number of indexes are equal to the number of processed indexes.

### `while`

> While true do something.
> Within this script `while` is used to loop though commands while a condition
> is true, such as a file existing.

### `&&` and `||`

> If command exits true (`&&`) then do next listed operation. Or if command
> exits false (`||`) do next listed operation.
> Within this script these above `operator` commands are used to test if two
> or more listed conditions are true/false and take actions based upon the
> summed truthfulness or falseness of listed conditions.

### `[`, `=`, `!=`, `]`

> If string is equal (`=`) to another or if string is not equal (`!=`) to
> another string then do something.
> Within this script the above `operator` commands are used within `if`, `until`
> and `while` loops with other special operator command line options to test
> whether or not some condition is true.

### `|`

> Pipe anonymously the output of one process into the input of another process.
> Within this script `|` (pipes) are used for transmitting data from one command
> to another (nearly the same as named pipes) and much like `mapfile` provides
> this script with much of it's *magical* capabilities.

### Getting help

> Documentation specific to each command above can be found with
> `help <command>` and/or `man <command>` for most, however those that are
> marked with `operator` should be searched as `man operator` or `help operator`

## Internal `bash` variables & arrays used within this project's scripts

### Variables

> Variables are used within this script to hold values from both user input as
> well as results of commands saved as a value to variables. Below are some
> examples of syntax used within bash scripts.

- Assigning variable `foo` with `bar` value

```
foo="bar"
```

- Calling variable `foo` to display `bar` value

```
echo "${foo}"
## Or using redirection and cat
cat <<<"${foo}"
## Above should print: bar
```

- Printing charicter count/length of `foo` variable

```
echo "${#foo}"
## Above shoule print: 0
```

- Adding value `,second` to variable `foo`

```
## Using '+=' syntax
foo+=",second"
## And using variable within value assignment
foo="${foo},third"
```

- Outputting only first or second values from `foo` variable

```
awk '{print $2}' <<<"${foo//,/ }"
## Or using pipes
echo "${foo//,/ }" | awk '{print $2}'
## Above will print "second" value
```

> Note in above two examples how the comas (`,`) where added within variable
> assignments and then *stripped* out again before presenting the string to
> `awk`, this syntax of removing/replacing characters will be seen often
> within the scripts of this project when array indexing is unnecessary for
> holding complex strings or lists of values. Furthermore this type of complex
> variable string assignments is not uncommon; try the following to output your
> path's varaible values each on their own lines.

```
for _path in ${PATH//:/ }; do
    echo "${_path}"
done
```

> Or for a more on topic example, try the following after assigning above.

```
for _word in ${foo//,/ }; do
    echo "${_word}"
done
```

### Arrays

> Arrays are like *supper powered* variables and come with some nifty bult in
> options when used within the Bash scripting language.

- Assigning an array `foo_bar` with `fubarz` value

```
foo_bar=( "fobarz" )
```

- Printing first value of `foo_bar` array

```
echo "${foo_bar[0]}"
## Above should print: fobarz
```

> Note with arrays the index/address will start with `0` and add one for
> every index/address after.

- Adding values `cheese` & `cheesy` to `foo_bar` array

```
## Using '+=' syntax
foo_bar+=( "cheese" )
## And using the array within value assignment syntax
foo_bar=( "${foo_bar[*]}" "cheesy" )
```

- Printing all values within `foo_bar` array

```
echo "${foo_bar[@]}"
## Or using '*' instead
echo "${foo_bar[*]}"
```

> Now to get into some of the fancier things that arrays can do for us.

- Assign indexes after `1` to new `bars_foo` array

```
bars_foo=( "${foo_bar[@]:1}" )
```

- Assign indexes befor `2` to new `fobarz_cheese` array

```
fobarz_cheese=( "${foo_bar[@]::2}" )
```

- Print new & old arrays

```
echo "${foo_bar[*]}"
## Above should print: fobarz cheese cheesy
echo "${bars_foo[*]}"
## Above should print: cheese cheesy
echo "${fobarz_cheese[*]}"
## Above shoule print: fobarz cheese
```

- Looping though `foo_bar` array with `until` and `let` itteration

```
let counter=0
until [ "${#foo_bar[*]}" = "${counter}" ]; do
    echo "${foo_bar[${counter}]}"
    let counter++
done
unset counter
```

> Above should print out as shown bellow.

```
fobarz
cheese
cheesy
```

## Internal `bash` built-in variables used within this project's scripts

> Note unlike the previous examples the following are available to any
> bash script.

### Capturing exit status of previous command

- Testing for failure codes by intentionaly running a failing command

```
cat /tmp/some_non_exsistant.file
exit_variable_one=$?
if [ "${exit_variable_one}" != '0' ]; then
    echo "Proccess ID errored: $!"
fi
```

- Testing for sucess code by running a command that will succeed

```
cat /etc/hosts
exit_variable_two=$?
if [ "${exit_variable_two}" = '0' ]; then
    echo "Proccess ID succeeded: $!"
fi
```

> Note above will only capture the last command's exit status, so
> if using piped commands try `${PIPESTATUS[@]}` built in array to
> capture the exit statuses of all commands that where piped

## Bash function assignment and calling syntax

- Assign a function named `func`

```
func(){
    var="${1:-value}"
    echo "${var}"
}
```

- Call above function named `func`

```
func "yo"
```

### manipulating via assigning function `func` with argument `yo` to variable `func_var`

```
func_var=$(func "yo")
```

## Bash write file method

### Write to `/tmp/file.name` text until `EOF` is found on it's own line

```
cat > "/tmp/file.name" <<EOF
some text with "EOF" on a new line to end statement
some variables with "\" and some without depending
upon if they should be expanded on write or on re-read/execution
EOF
```

## Bash examples of string *scrubbing*

> alpha numeric only

```
var_test="${var_test//[^a-zA-Z0-9]/}"
```

> alpha numeric with comments, spaces, and underscores allowed only

```
var_test="${var_test//[^a-zA-Z0-9# _]/}"
```

> Note one *gotcha* for allowing double quotes as well as other special
> characters; use `\` (backslash) to escape them.
> allow double quotes

```
var_test="${var_test//[^a-zA-Z0-9# _\"]/}"
```

> Other special characters that require '\' backslash in order to allow

```
\/ \^ \( \) \\ \{ \} \- \' \"
```

### Example of all above substitution tricks

```
var_test="${var_test//[^a-zA-Z0-9 #&:;$&\/\^\-\"\'\(\)\{\}]/}"
```

## Bash example of case matching

> This example is going to combine some of the previously covered subjects in
> order to show how more than one of the scripts in this project handle user
> input from the command line.

```
#!/usr/bin/env bash
Var_foo="some string"
Var_bar="another string"
Func_help(){
    echo "Script: ${0##*/} undersands the following"
    echo "--option-foo    Var_foo=${Var_foo}"
    echo "--option-bar    Var_bar=${Var_bar}"
}
Arg_assigner(){
    _option="$1"
    _variable="$2"
    _value="$3"
    declare -g "${_variable}=${_value}"
    unset _option
    unset _variable
    unset _value
}
Arg_checker(){
    _option="$1"
    _input="$2"
    case "${_option}" in
        --option-foo)
            Arg_assigner 'Var_foo' "${_option}" "${_input}"
        ;;
        --option-bar)
            Arg_assigner 'Var_bar' "${_option}" "${_input}"
        ;;
        --help)
            Func_help
        ;;
        *)
            Func_help
        ;;
    esac
    unset _option
    unset _intput
}
Arg_splitter(){
    _raw_input=( "$@" )
    let _counter=0
    until [ "${#_raw_input[@]}" = "${_counter}" ]; do
        _string_from_array="${_raw_input[${_counter}]}"
        _option="${_string_from_array%=*}"
        _value="${_string_from_array#*=}"
        Arg_checker "${_option}" "${_value}"
        unset _string_from_array
        unset _option
        unset _value
        let _counter++
    done
    unset _counter
    unset _raw_input	
}
Arg_splitter "${@:---help}"
```

> The above group of functions are a *set* that work togeather to parse user
> input for scripts that should have user modifide variables. Those that do
> read this project's scripts will find similar logic under slightly differant
> function names and with slightly modified syntax.

## Licensing notice for this file

```
    Copyright (C) 2016 S0AndS0.
    Permission is granted to copy, distribute and/or modify this document under
    the terms of the GNU Free Documentation License, Version 1.3 published by
    the Free Software Foundation; with the Invariant Sections being
    "Title page". A copy of the license is included in the directory entitled
    "License".
```

[Link to title page](Contributing_Financially.md)

[Link to related license](../Licenses/GNU_FDLv1.3_Documentation.md)
