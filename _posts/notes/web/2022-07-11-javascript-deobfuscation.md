---
title: Notes | JavaScript Deobfuscation
author: Zeropio
date: 2022-07-11
categories: [Notes, Web]
tags: [javascript]
permalink: /notes/web/javascript-deobfuscation
---

JavaScript is one of the most used language in webpages. It operate at the client-side.
The first thing we should look is the source code, easily access with **CTRL + u**. There the JavaScript code can be inside **<script>** or in other files.

---

# Meaning

Obfuscation is the technique to make the code hard to read by humans, without losing function. An example of obfuscation is taking the code and changing the words by a dictionary that JavaScript understand.
Due to the fact that JavaScript operates in the client-side (PHP or Python operate in the server-side) users can read the code. This is why obfuscation is pretty popular in this language.

# Obfuscation

Let's take a simple code as the example:
```javascript
console.log('coding!')
```

This are some examples of obfuscation:
- **Minifying**: convert the code in a whole line
- **Packing**: convert all the words into a list or dictionary
- **Obfuscator**: in the web [obfuscator.io](https://obfuscator.io/) we have some types for obfuscation
- **JSfuck**: replaces all the character by **[]()!+**

---

# Deobfuscation

There are many techniques to deobfuscated code:
- **Beautify**: simple as making order in the code. The **Browser Dev Tools** has this option, or use the page of Prettier
- **[JSnice](http://www.jsnice.org/)**: this online tool can deobfuscated code

