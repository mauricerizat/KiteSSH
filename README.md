# KiteSSH
## KiteSSH an An SSH, SFTP, SCP and P2P client for Windows
## README
### FYP-20-S3-10 PROTOTYPE_01
### KITESSH
### VERSION 1.0
### NOVEMBER 2020
***
### PROJECT META
KiteSSH - An SSH, SFTP, SCP and P2P client for Windows

UNIVERSITY OF WOLLONGONG - CSIT321 [Project]

GROUP: FYP-20-S3-10 - EFFICIENT SSH TUNNELING

MEMBERS:

+ Fratini Luca Project Manager 
+ Maurice Rizat Kasomwung Backend Programmer mauricerizat@gmail.com
+ Lim Wei Zhi Maximillian Frontend Programmer 
+ Chua Man Fu UI/UX Designer 
+ Pang Chun Weng Software Tester 


SUPERVISOR:
ASSESSOR:

VERSION: 1.0
DATE: November 2020

_Some personal information on the individuals involved in this project is not displayed due to privacy reasons._
***
### REQUIREMENTS
This KiteSSH Application is meant for Microsoft Windows operating systems. Windows 10 1089 or above is recommended.

Java Runtime Environment (Minimum Version 1.8.0) is required to run the application.

KiteSSH uses JCraft's JSch library [http://www.jcraft.com/jsch/] to handle its SSH, SCP and SFTP functinalities. This is bundled with the application and can be found in the **lib** subfolder.
***
### USE
Download executable folder and run **KiteSSH.exe** located within the sub-folder **KiteSSH**. It is important that the contents of the directory KiteSSH remain unchanged relative to each other to ensure the program runs as intended.

Below is a brief instructional video outlining the basic uses of KiteSSH.

[![IMAGE ALT TEXT HERE](http://img.youtube.com/vi/cqihqAPsWJg/0.jpg)](http://www.youtube.com/watch?v=cqihqAPsWJg)

***
### P2P Encryption
KiteSSH offers multiple P2P encryption methods. They are (in descending order of speed):
1. Blowfish
2. AES128
3. AES256

Instructions for file transfer and the use of these encryption methods are available in the applications P2PClient terminal. Enter `help_local` in the terminal for details.
***
### DISCLAIMER
For the P2P features of KiteSSH, certificate checks are ignored. As such, it is essential to be aware of the connecting client when setting up a listening server with the application's P2P feature. Passwords are not required to set up a P2P server but it is highly recommended that you do so.

When setting up a P2P Server with KiteSSH, if the "host address" field is left blank, the application will attempt to automatically detect the machine's IP address. Manual address specification may, however, be require in the case of multiple network interfaces.
***
### Future Features
The P2P transfer speed could be significantly faster with this optimization of the `sendFile()` and `recieveFile()`methods in both `P2PClient` and `P2PServer` classes. I hope to implement this improvement soon.  

