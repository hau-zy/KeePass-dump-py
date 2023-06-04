# KeePass-dump-py

My attempt to re-write the original KeePass 2.X Master Password Dumper (CVE-2023-32784) POC in python. 

Please head over to [Original POC](https://github.com/vdohney/keepass-password-dumper) for more details about the vulnerability and exploitation process.

What this script does:
1. Checks if KeePass process is running, otherwise it spawns the KeePass
2. Dumps KeePass process using WerFault (code snippet adapted from LSASSY)
3. Search process dump for password
