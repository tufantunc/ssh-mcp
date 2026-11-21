---
"ssh-mcp": minor
---

The classifier now finds the program an interpreter is handed when options stand between the interpreter and the program. A shell's `-c` is a switch, so its program is the first operand wherever `-c` stands: `sh -c -- CMD`, `sh -c -e CMD`, `sh -o errexit -c CMD` and `bash --rcfile FILE -c CMD` are classified, and checked against the never-allowed list, as `CMD`. For the other interpreters the classifier knows the options that take no value and takes every other option to have one, so an option's value no longer hides the program flag behind it (`python3 -W ignore -c CODE`, `perl -I lib -e CODE`, `node -r ./x -e CODE`, `ruby -r json -e CODE`, `php -d a=b -r CODE`, `lua -l os -e CODE`, `osascript -l JavaScript -e CODE`), nor does a cluster of flags (`perl -lane CODE`) or a program attached to its flag (`perl -e'CODE'`). `vim`, `vi`, `ex`, `view`, `nvim` and `gdb` are read with their options after operands too (`vim FILE -c CMD`, `gdb PROG -ex CMD`), and vim's `+CMD` is read as `-c CMD`. This reading applies behind a command the classifier has no table entry for as well (`unshare -m sh -c -- CMD`, `docker exec NAME python3 -W ignore -c CODE`). Before, each of these was `safe`.

More names are read as interpreters: a version after the name (`python3.11`, `perl5.36`, `php8.2`, `lua5.4`, `ksh93`), `mksh`, `pdksh`, `oksh`, `yash`, `rbash`, `posh`, `fish`, `csh`, `tcsh`, `nodejs`, `pypy`, `pypy3`, `jruby`, `luajit`, `nvim`, `rvim`, `rview`, `gview` and `gdb-multiarch`. More program flags are read: `php -B`, `-R`, `-E` and `--run`, `bun --eval`, `-p` and `--print`, and gdb's `-eval-command`, `-iex`, `-eiex` and their abbreviations with one dash or two.

Upgrade notes:

- The invocations above that ran without a prompt now follow the policy for a program handed to an interpreter: `destructive` for code the classifier does not read, and the class of the command itself for a shell's `-c`.
- An interpreter option the classifier does not know is taken to have a value. `python3 --some-new-flag run.py -c config.yml` is then read as `-c` handing `config.yml` to python and is `destructive`; with an option it knows (`python3 -u run.py -c config.yml`) the line keeps its class. Report such an option and it is added.
- `vim +q FILE`, `ex -s +'%s/a/b/' +wq FILE` and any other `+COMMAND` are `destructive`, and so is a `+/PATTERN` that holds a `|`. `vim +10 FILE`, `vim + FILE` and `vim +/pattern FILE` keep their class.
- `fish -c CMD`, `csh -c CMD` and `tcsh -c CMD` are `destructive` at least: their program is not read as POSIX shell text.
- A script's own arguments are not read: `python3 -u train.py -c config.yml`, `python3 -m gunicorn -c conf.py app` and `node server.js -p 3000` keep their class.
