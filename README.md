# windows-drivers
 *user/kernel mode drivers*

This project's motivation is to test development of User-mode/Kernel-mode drivers in Windows (11). It has been useful to me for enlightenment on windows device driver development, coming from an embedded software engineering background for mobile chipsets (Qualcomm Snapdragon Android).

The code is adapted from [cazz's guide](https://www.youtube.com/watch?v=n463QJ4cjsU) which is focused on using kernel drivers for game cheat (for educational purposes). Along the way, he sets up a modern approach to windows driver development.


Topics covered include:
- Kernel-mode development (DriverEntry, Irp handlers + processing requests, driver codes, basic process attach/read/write)
  - Uses kdmapper tool to register the driver
- User-mode development - create/acquire driver handle, attach to process and executing requests
  - usage of TlHelp32 to scan through process id's and .dll modules of a process
- Setup & testing through Windows Driver Kit, Windows VM (Virtual Machine), WinDbg, & kdmapper
  
## Next steps
- Refactoring for common driver codes/request structure to a header w/ namespace
- more functionality (for game client explotation, load in client.dll offset headers, get client.dll modules and modify contents on keypress callbacks)