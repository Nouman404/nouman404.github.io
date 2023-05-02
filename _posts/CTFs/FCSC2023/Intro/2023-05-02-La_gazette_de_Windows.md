---
title: CTFs | FCSC2023 | La_gazette_de_Windows
author: BatBato
date: 2023-05-02
categories: [CTFs, FCSC2023, Intro]
tags: [CTF, FCSC, Windows]
permalink: /CTFs/FCSC2023/Intro/La_gazette_de_Windows 
---

# La_gazette_de_Windows

![image](https://user-images.githubusercontent.com/73934639/235746934-bd1b360a-3fd0-4af6-991c-2e77fc9502ce.png)

For this chall, we had a `.evtx` file. The .evtx file extension is used for files that contain event logs on Windows operating systems. These logs are recorded by the Event Viewer application and contain information about system events, including security, application, and system-related events. You can read a .evtx file using the Windows Event Viewer.

You can read a .evtx file using the Windows Event Viewer. The Event Viewer is a built-in Windows tool that allows you to view, manage, and analyze events that are recorded in event logs. To open the Event Viewer:

Press the `Windows key + R` to open the Run dialog box.
1. Type `eventvwr.msc` and press Enter.
2. In the `Event Viewer` window, select `Action` from the menu bar and choose `Open Saved Log`.
3. Browse to the location of the `.evtx` file and select it.

![image](https://user-images.githubusercontent.com/73934639/235749060-c09bc377-f37a-48df-b739-09932ebf6805.png)


The one with the event ID of `4104` is the more interesting, we can find some powershell script in it:

![image](https://user-images.githubusercontent.com/73934639/235749213-0adc1267-022e-4328-9295-dab47a227a5d.png)

The interesting part is:

```ps1
$l = 0x46, 0x42, 0x51, 0x40, 0x7F, 0x3C, 0x3E, 0x64, 0x31, 0x31, 0x6E, 0x32, 0x34, 0x68, 0x3B, 0x6E, 0x25, 0x25, 0x24, 0x77, 0x77, 0x73, 0x20, 0x75, 0x29, 0x7C, 0x7B, 0x2D, 0x79, 0x29, 0x29, 0x29, 0x10, 0x13, 0x1B, 0x14, 0x16, 0x40, 0x47, 0x16, 0x4B, 0x4C, 0x13, 0x4A, 0x48, 0x1A, 0x1C, 0x19, 0x2, 0x5, 0x4, 0x7, 0x2, 0x5, 0x2, 0x0, 0xD, 0xA, 0x59, 0xF, 0x5A, 0xA, 0x7, 0x5D, 0x73, 0x20, 0x20, 0x27, 0x77, 0x38, 0x4B, 0x4D
$s = ""
for ($i = 0; $i -lt 72; $i++) {
    $s += [char]([int]$l[$i] -bxor $i)
}
```

Writing it in a `.ps1` file, we print the `s` string and find the flag:

![image](https://user-images.githubusercontent.com/73934639/235749868-72e6d09e-12a6-43e1-9a47-75a556c34943.png)
