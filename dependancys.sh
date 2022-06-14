#!/bin/bash

# install python 3.9
sudo apt update
sudo apt install software-properties-common
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.9

# install pip3
sudo apt-get -y install python3-pip

# install libraries for code
sudo pip3 install -r requirements.txt
