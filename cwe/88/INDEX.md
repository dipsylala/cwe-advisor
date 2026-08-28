# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')

## LLM Guidance

Argument Injection occurs when untrusted user input is used to construct command-line arguments, function parameters, or system calls, allowing attackers to inject malicious arguments and alter program behavior. Innocuous installed executables (LOLBins) can be subverted through command-line arguments to perform code execution or filesystem manipulation. This is the weakness that survives the CWE-78 fix: an argument array delivers `--use-compress-program=touch` faithfully, and the invoked program's own option parser is what reinterprets it.

## Key Principles

- Never allow untrusted input to be parsed as command options or flags
- Remove the argument vector where possible - a native library (an archive or HTTP library instead of `tar` or `curl`) leaves no downstream option parser to reinterpret the value
- Constrain the first character: require the value to start with something that cannot introduce an option (`[A-Za-z0-9]`), which holds even for programs that do not support a flag terminator
- Use flag terminators (`--`) to separate options from user-controlled arguments where the invoked program honours them - not all do, so treat `--` as a second layer rather than the control
- Never let untrusted input choose the program being executed (the first element of the argument list); constrain execution to a fixed command or a map of approved ones
- Know the dangerous options of the specific program invoked: `tar --use-compress-program=`/`--to-command=`/`--checkpoint-action=exec=`, `curl -K`/`-o`, `git --upload-pack=`, `rsync -e`, `ssh -oProxyCommand=`, `find -exec`
- Prefer parameterized APIs and safe libraries over string concatenation
- Validate input rigorously using allowlists of permitted values
- Avoid invoking system commands when safer alternatives exist

## Remediation Steps

- Trace the data path: identify where untrusted data enters (source), how it's used in argument construction, and where it reaches command execution (sink)
- Review scan results for string concatenation or direct use of user input in command arguments
- Locate all command execution functions (`system()`, `exec()`, `subprocess`, `Runtime.exec()`)
- Implement input validation with strict allowlists for permitted characters and values
- Use parameterized command execution methods that separate arguments from the command
- Place user input after `--` flag terminator to prevent interpretation as options
- Do not assume a space in the value defuses it - one array element is not one command line: GNU `getopt` reads the remainder of the same element as the option's value, so `-o /etc/cron.d/x` passed as a single argument is still an option and its argument
- Test with a value beginning with `-` and with a program-specific dangerous option, and confirm legitimate values (filenames that legitimately contain dots or dashes mid-string) still work
