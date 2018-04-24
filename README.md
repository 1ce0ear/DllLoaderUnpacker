[WIP] DLL Loader Unpacker
===============================================

Intro
---------------------

This tool is designed to unpack dll loader malware. It hooks ZwAllocateVirtualMemory and ZwProtectVirtualMemory. When malware requests executable memory, hook engine changes memory permission to be non-executable.

Therefore when malware executes a non-executable memory, VEH handler will be triggered and the tool searches process memory in order to find and dump the new malware image.

Compilation
---------------------

Visual Studio 2017 with configuration Debug | x86.

Testing
---------------------

```
DllInjector.exe -d DllLoaderUnpacker.dll -e 2017-02-06-Terdot.A-Zloader-from-Hancitor-malspam.exe 
```

Windows XP x86 is tested.
Windows 7 x86 [WIP]

Example
---------------------

Dll loader unpacker can unpack Vawtrak. 
Unpacked dll info: https://www.virustotal.com/#/file/0e34064a9e44c097392b8f58361821801fbc73ae45decbdf80a087359c25fd6e/detection
