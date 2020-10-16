# Remote-Password-Manager 
A Remote Password Manager written in Python 2.7. This project was developed for the "Cybersecurity" course at University of Pisa.

Required modules:

- cryptography
- MySQLdb
- Tkinter

In order to run the system you have to do the following:

**Server side:**

Create the configuration file to login with the database (see [DB_config_example](https://github.com/linofex/Remote-Password-Manager/blob/master/DB_config_example) as example)

Create a database like [this](https://github.com/linofex/Remote-Password-Manager/blob/master/PWD_manager_2.sql) one

Create couple of public and private key and link the public one with a certifate.

run `python PWD_manager_sever_1T.py -i server_address -p server_port`

**Client side:**

run `python clientGui.py -i localhost -p 8288`


Read [Relazione.pdf](https://github.com/linofex/Remote-Password-Manager/blob/master/relazione.pdf) for the implementation choices.

