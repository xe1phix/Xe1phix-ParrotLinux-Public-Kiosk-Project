xargs: A brief primer
---------------------

If you’ve spent any amount of time at a Unix command line you’ve probably used xargs. In case you haven’t, [xargs](https://linux.die.net/man/1/xargs) is a command used to execute commands based on arguments from standard input.

**Common use cases:**

These who use xargs often use it in combination with find in order to do something with the list of files returned by find.

On its' own, find is a very powerful command and it has built in flags such as `-exec` and `-delete` that you can often use instead of piping to xargs. With it's simplicity, xargs tends to find more usage than find on its' own.

**Examples:**

Recursively find all Python files and count the number of lines:

    find . -name '*.py' | xargs wc -l

Recursively find all Emacs backup files and remove them

    find . -name '*~' | xargs rm

Recursively find all Python files and search them for the word ‘import’

    find . -name '*.py' | xargs grep 'import'

**Special note on handling files or folders with spaces in the name:**

`xargs` by default will split on any white-space character. A quick solution to this is to tell find to delimit results with `NUL (\0)` characters (by supplying `-print0` to `find`), and to tell `xargs` to split the input on NUL characters as well (`-0`).

**Remove backup files recursively even if they contain spaces:**

    find . -name '*~' -print0 | xargs -0 rm

**Security note:** Filenames can often contain more than just spaces.

**Argument syntax in xargs:**

In the examples above xargs reads all non-white-space elements from standard input and concatenates them into the given command line before executing it. This is very useful in many circumstances. Sometimes however you might want to insert the arguments in the middle of a command. The `-I` flag to xargs takes a string that will be replaced with the supplied input before the command is executed. A common choice is `%`. , as used in the example below to move all backup files elsewhere on a user's system.

**Move all backup files somewhere else;**

    find . -name '*~' -print 0 | xargs -0 -I % cp % ~/backups

**Maximum command length:**

Sometimes the list of arguments piped to `xargs` would cause the resulting command line to exceed the maximum length allowed by the system. You can find this limit with:

    getconf ARG_MAX

In order to avoid hitting the system limit, `xargs` has its own limit to the maximum length of the resulting command. If the supplied arguments would cause the invoked command to exceed this built in limit, xargs will split the input and invoke the command repeatedly. This limit defaults to 4096, which can be significantly lower than ARG_MAX on modern systems. You can override xargs’s limit with the `-s` flag. This will be particularly important when you are dealing with a large source tree.

**Operating on a subset of arguments at a time:**

You may be dealing with commands that can only accept 1 or maybe 2 arguments at a time. For example the `diff` command operates on two files at a time. The `-n` flag to xargs specifies how many arguments at a time to supply to the given command. The command will be invoked repeatedly until all input is exhausted. Note that on the last invocation you might get less than the desired number of arguments if there is insufficient input. Let’s simply use xargs to break up the input into 2 arguments per line, as illustrated below:

    $ echo {0..9} | xargs -n 2
    
    0 1
    2 3
    4 5
    6 7
    8 9

In addition to running based on a specified number of arguments at time you can also invoke a command for each line of input at a time with `-L 1`. You can of course use an arbitrary number of lines a time, but 1 is most common. Here is how you might diff every git commit against its parent.

    git log --format="%H %P" | xargs -L 1 git diff

**Executing commands in parallel:**

You might be using xargs to invoke a compute intensive command for every line of input. That’s what `-P` is for. It allows xargs to invoke the specified command multiple times in parallel. You might use this to run [multiple ffmpeg encodes in parallel](https://gist.github.com/Brainiarc7/2afac8aea75f4e01d7670bc2ff1afad1). See another example below:

Parallel sleep:

    $ time echo {1..5} | xargs -n 1 -P 5 sleep
    
    real    0m5.013s
    user    0m0.003s
    sys     0m0.014s

Sequential sleep:

    $ time echo {1..5} | xargs -n 1 sleep
    
    real    0m15.022s
    user    0m0.004s
    sys     0m0.015s

If you are interested in using xargs for parallel computation, you may also consider [GNU parallel](https://www.gnu.org/software/parallel/). xargs has the advantage of being installed by default on most systems, and is easily deployed on BSD and OS X, but parallel has some [really nice features](https://www.gnu.org/software/parallel/parallel_tutorial.html).

