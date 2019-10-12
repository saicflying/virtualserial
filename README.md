# VirtualSerial

1. this is to setup a system which can have serials mapped from other systems. 
2. this system can play the role as the console server/serial server. 
3. some codes are reused from sheepdog project, thanks.

the design is like the below

tty ---> kernel driver ---> user space mapping ---> target system ---> server program ---> kernel driver ---> physical serial


any problem, please post an issue or directly contace me: saicflying@163.com
