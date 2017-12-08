# eel5718-project
Class Project for EEL5718: encryption and authentication of messages transmitted over TCP socket

Team:  
Khaled Hassan  
Samuel Lichtenheld  

## How to run
0. Optionally, set up a virtualenv for the project and activate it. This helps reduce the chance of conflicting packages now or in the future. However, you'd have to activate the virtualenv any time you wanted to run the programs.
```
$ virtualenv venv
$ source venv/bin/activate
```
1. Install required packages
```
$ pip install -r requirements.txt
```
2. In a separate terminal, start the server. 
```
$ cd server
$ ./server.py -h # (-h flag displays usage information)
```
3. In a(nother) separate terminal, use the client to send messages or files to the server.
```
$ cd client
$ ./client.py -h # (again, -h flag displays usage)
```

You should be able to run the client and server on different hosts, on different ports, in Docker containers, across the internet, etc.
