---
title: CTFs | 404CTF_2023 | Web3 | Descente aux enfers
author: BatBato
date: 2023-06-05
categories: [CTFs, 404CTF_2023, Web3]
tags: [Web3,BlockChain, Contract, Solidity]
permalink: /CTFs/404CTF_2023/Web3/Descente_aux_enfers
---

#  La Folie du jeu : descente aux enfers 

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/106df26e-3c6c-4ab4-b686-5772ba8f8770)

In this challenge, we are given a Solidity code (available [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Web3/Jeu.sol)).

In this code, we first initialise the contract using the constructor and by giving it the `_start` value:

```java
constructor(uint _start) {
        currentState = _start;
}
```

This value is not known but can be found. Then when the contract is initialized, we can use the `guess` function to try guessing the correct value and get the flag. As we can see in the bellow code, we need to give a calculation of the `_start` value `a`, `c` and `m`:

```java
function guess(uint _next) public returns (bool) {
        currentState = (a * currentState + c) % m;
        isSolved = (_next == currentState) || isSolved;
        return isSolved;
}
```

To find the `_start` value, I found the website [Try Ethernal](https://app.tryethernal.com/blocks). This allows us to see all the newly created blocks and to get the one with the `_start` value given to the constructor.

Now that we are all set, we can connect to the `nc` server to deploy the game. We get the `JSON-RPC` URL and the `chain-id`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/8560bddc-d280-49ab-bba2-33f2e0759b48)

Now, we can deploy the `Jeu` contract and head back to `Try Ethernal`. We will see the newly created block. When we click on it, we can see the `Contract Creation Data`:

![image](https://github.com/Nouman404/nouman404.github.io/assets/73934639/e74ce1f1-b22b-4751-9800-4cbaa048d250)

As we can see, at the bottom, the last line looks like `000000000000000000000000000000000000000000000000000000000c39b211`. What comes after the `0`s is the value given to the constructor. We now just have to send `(a*0xc39b211+c)%m` and we are done. To do so, I used a python code available [here](https://github.com/Nouman404/nouman404.github.io/blob/main/_posts/CTFs/404CTF_2023/Web3/exploit_sol.py)

> Note that you could also have done a JS code to do that ore used the website [Remix Ethereum](https://remix.ethereum.org/)
{: .prompt-tip}

The flag we get by asking the `nc` server is `404CTF{r4Nd0Mn3ss_1S_NOt_s0_345y}`
