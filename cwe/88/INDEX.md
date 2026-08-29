# CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')

## LLM Guidance

Argument Injection occurs when untrusted user input is used to construct command-line arguments, function parameters, or system calls, allowing attackers to inject malicious arguments and alter program behavior. Innocuous installed executables (LOLBins) can be subverted through command-line arguments to perform code execution or filesystem manipulation. This is the weakness that survives the CWE-78 fix: an argument array delivers `--use-compress-program=touch` faithfully, and the invoked program's own option parser is what reinterprets it.

## Key Principles

- Remove the argument vector where possible - a native library (an archive or HTTP library instead of `tar` or `curl`) leaves no downstream option parser to reinterpret the value
- Constrain the first character: require the value to start with something that cannot introduce an option (`[A-Za-z0-9]`), which holds even for programs that do not support a flag terminator. An allowlist works here because it is closed; a denylist would have to enumerate every option form of every program you might invoke
- Never let untrusted input choose the program being executed (the first element of the argument list); constrain execution to a fixed command or a map of approved ones
- Treat `--` as a second layer, not the control - support is thinner than it looks. curl documents it; git needs `--end-of-options` (2.24+) because `--` is its revision/path separator; tar's manual documents no terminator at all; rsync and ssh document none. GNU `find` documents that `--` *does not work* for it, because it decides where starting points end by reading until an argument begins with `-`, and names its own remedies instead: prefix the value with `./`, pass an absolute path, or use `-files0-from`
- Know the dangerous options of the program invoked and what each actually does, since the mechanisms differ: `tar --use-compress-program=`/`--to-command=`/`--checkpoint-action=exec=` splits the value into words itself and execs the first (so an argument works, but shell syntax does not); `ssh -oProxyCommand=` is run by the user's shell; `git --upload-pack=` is documented as the command run on the *remote* end; `curl -K` executes nothing itself, it reads further arguments from a file, and the damage is whatever those then do. `rsync -e`, `rsync --rsync-path=` and `find -exec` round out the set. Consult a per-binary reference such as GTFOBins rather than assuming from the name

## Remediation Steps

- Trace the data path: identify where untrusted data enters, how it is used in argument construction, and where it reaches command execution
- Locate all command execution functions (`system()`, `exec()`, `subprocess`, `Runtime.exec()`) and determine which argument position the value occupies - a bare positional is the exploitable case, an option's value slot usually is not
- Use parameterized command execution that separates arguments from the command, then validate with an allowlist anchored on the first character
- Place user input after `--` where the invoked program honours it
- Do not assume a space in the value defuses it - one array element is not one command line: GNU `getopt` reads the remainder of the same element as the option's value, so `-o /etc/cron.d/x` passed as a single argument is still an option and its argument. The space is kept, so that payload writes to a path beginning with a space; the attacker's working form is the attached one, `-o/etc/cron.d/x`
- Choose the test payload for whether it actually fires: `tar --checkpoint-action=exec=...` does nothing without a companion `--checkpoint=N`, so it passes against a broken fix and a working one alike. Send `--help` too - most tools exit 0 for it, so a leak arrives looking like a successful response rather than an error
- Confirm legitimate values still work: filenames that legitimately contain dots or dashes mid-string, and URLs with query parameters
