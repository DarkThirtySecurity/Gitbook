---
description: >-
  We can view the contents of a given environment variable with the echo command
  followed by the $ character and an environment variable name. Take a look at
  the contents of the PATH environment.
---

# ECHO

```text
austin@songer:-$ echo $PATH
/usr/local/sbi n:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

```text
austin@songer:-$ echo $USER
```

```text
austin@songer:-$ echo $PWD
```

```text
austin@songer:-$ echo $HOME
```

```text
austin@songer:-$ export b=le.11.1.220
```

## Export

> The export command makes the variable accessible to any subprocesses we might spawn from our current Bash instance. If we set an environment variable without export it will only be available in the current shell. `$$` variable to display the process ID of the current shell instance to make sure that we are indeed issuing commands in two different shells:

```text
austin@songer:-$ echo"$$"
1827
```

```text
austin@songer:-$ var="My Var"
```

```text
austin@songer:-$ echo $var
My Var
```

```text
austin@songer:-$ bash
austin@songer:-$ echo"$$"
1908
```

```text
austin@songer:-$ echo $var
```

```text
austin@songer:-$ exit
exit
```

```text
austin@songer:-$ echo $var
My Var
```

```text
austin@songer:-$ export othervar="Global Var"
```

```text
austin@songer:-$ echo $othervar
Global Var
```

```text
austin@songer:-$ bash
```

```text
austin@songer:-$ echo $othervar
Global Var
```

```text
austin@songer:-$ exit
exit
austin@songer:-$
```

## Env

> env at the command line:

```text
austin@songer:-$ env
SHELL=/bin/bash
...
PWD=/home/songer
XDG_SESSION_DESKTOP=lightdm-xsession
LOGNAME=songer
XDG_SESSION_TYPE=xll
XAUTHORITY=/home/songer/.Xauthority
XDG_GREETER_DATA_DIR=/var/lib/lightdm/data/songer
HOME= /home/songer
...
TERM=xte rm-256color
USER=kali
```

