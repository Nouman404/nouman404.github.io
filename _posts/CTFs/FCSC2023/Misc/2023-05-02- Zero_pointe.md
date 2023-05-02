---
title: CTFs | FCSC2023 | Misc | Zéro pointé 
author: BatBato
date: 2023-05-02
categories: [CTFs, FCSC2023, Misc]
tags: [CTF, FCSC, Misc]
permalink: /CTFs/FCSC2023/Misc/Zero_pointe
---

#  Zéro pointé 

![image](https://user-images.githubusercontent.com/73934639/235791083-ce6ea12c-7391-4c5d-9e4a-a1f0c582e9bd.png)


This chall is a bit of a reverse one. We had two files, one containing the following C code and the other with the compiled version of it:

```c

static void flag(int sig){
    (void) sig;
    char flag[128];

    int fd = open("flag.txt", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    int n = read(fd, flag, sizeof(flag));
    if (n == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }

    flag[n] = 0;
    flag[strstr(flag, "\n") - flag] = 0;

    if (close(fd) == -1) {
        perror("close");
        exit(EXIT_FAILURE);
    }

    printf("%s\n", flag);

    exit(EXIT_SUCCESS);
}

long read_long(){
    long val;
    scanf("%ld", &val);
    return val;
}

int main(){
    long a;
    long b;
    long c;

    if (signal(SIGFPE, flag) == SIG_ERR) {
        perror("signal");
        exit(EXIT_FAILURE);
    }

    a = read_long();
    b = read_long();
    c = b ? a / b : 0;

    printf("%ld\n", c);
    exit(EXIT_SUCCESS);
}

```

As we can see, the flag function is called if the `SIGFPE` signal is raised. To do so we would need to have a division by  `0` for exemple.
We have 2 input, `a` and `b` and then, the result of `a/b` is put in the `c` variable. But before doing the division, the program check if `b` is different of `0`. If so, then the division is done if not, `c=0`. For that we needed to overwrite the values in `a` and `b`. Reading the [man](https://www.tutorialspoint.com/c_standard_library/limits_h.htm) we see that `LONG_MIN = -9223372036854775808` and `LONG_MAX = +9223372036854775807`.

To get to `0` in `b`, we then need to put `LONG_MIN - 1` in `a` and `-1` in `b`. The input value for "a" is outside the range that can be represented by a long data type, and therefore leads to an overflow. As a result, the value of "a" becomes a very large positive number, and the value of "b" remains as -1, which causes a division by zero and triggers the flag() function.

![image](https://user-images.githubusercontent.com/73934639/235792417-d86b3f4f-59f3-4782-893e-567e7a09bd8a.png)


