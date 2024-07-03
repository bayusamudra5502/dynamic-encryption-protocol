# Implementation of AES Encryption Algorithm with Chaos-Based Dynamic Block Key on TLS Protocol

This repository consists implementation of AES Encryption Algorithm with Chaos-Based Dynamic Block Key on TLS Protocol.

## Requirements

To run this repository, you need preserve requirements below:

- Python 3.11.9
- Linux kernel 6.9.5.

## How to run server

To run peer server, you need to install the requirements first:

```sh
pip install -r requirements.txt
```

Next, you need to run server:

```sh
cd src
python main.py --mode server -a localhost -p 8888 --cert ../certs/cert.pem --key ../certs/ec_key.pem --folder $PWD/../server
```

Next, to run client, you need to run below command:

```sh
python main.py --mode client -a localhost -p 8888 -c ../certs/cert.pem --folder $PWD/../client
```
