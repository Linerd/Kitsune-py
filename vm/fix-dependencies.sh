#!/usr/bin/env bash

#make sure user has created an SSH key
read -p "About to install SDNator from Github, have you created and added an SSH key to Github yet? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]
then
    exit 1
fi

cd ~

#sdnator-due
ssh-keyscan github.com >> ~/.ssh/known_hosts
git clone git@github.com:Linerd/SDNator.git
cd SDNator/src/due
git checkout due-py2
sudo pip install -r requirements.txt
sudo python setup.py install

cd ~

#java
sudo apt-get -y install default-jre

#mysql for python2
pip install mysql-connector-python

#other pip
pip install scapy
pip install numpy==1.14.6 scipy==1.0.1
pip install cython

#mongodb on VM
wget -qO - https://www.mongodb.org/static/pgp/server-4.0.asc | sudo apt-key add -
echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/ubuntu trusty/mongodb-org/4.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-4.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org
echo "mongodb-org hold" | sudo dpkg --set-selections
echo "mongodb-org-server hold" | sudo dpkg --set-selections
echo "mongodb-org-shell hold" | sudo dpkg --set-selections
echo "mongodb-org-mongos hold" | sudo dpkg --set-selections
echo "mongodb-org-tools hold" | sudo dpkg --set-selections
sudo service mongod start
sudo service mongod status

#redis
sudo apt-get -y install redis-server
sudo service redis-server restart
sudo service redis-server status
