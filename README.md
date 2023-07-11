# Encrypted-File-Transfer
Project that allows file transfer between C++ based client and Python based server which use encryption to communicate securely.<br>
This was created as a final project for the course "Defensive System-Programming".
# Usual protocol flow
![image](https://github.com/FlameyBoi/Encrypted-File-Transfer/assets/48094669/c830b9e7-e1a2-4106-8e12-deaa6cce1baa)
# Reconnect attempt by user
![image](https://github.com/FlameyBoi/Encrypted-File-Transfer/assets/48094669/2412c512-bb9f-445e-bc28-8172e66acb32)
# Technical specification
WIP
# Implementation details
Client uses the CryptoPP library for encryption while the server uses PyCryptodome<br>
Actual file transfer uses AES-CBC with 128 bit key while key exchange uses RSA-1024<br>
Client uses boost for all connection related functionality<br>
Server uses a Selector to handle connections - file transfer is chunked to minimize client starvation<br>

