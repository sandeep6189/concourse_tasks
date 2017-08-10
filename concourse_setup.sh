#!/usr/bin/bash

# UPDATE Kernel version before installing postgres
apt-get install --install-recommends linux-generic-lts-wily
reboot
apt-get update

# POSTGRES CONFIG STARTS
apt-get install -y postgresql postgresql-contrib
sudo -u postgres createuser concourse
sudo -u postgres createdb --owner=concourse atc

# Download concourse binaries
cd /tmp
apt-get install curl
cuhttps://github.com/concourse/concourse/releases/download/v3.3.4/concourse_linux_amd64rl -L0 
wget https://github.com/concourse/concourse/releases/download/v3.3.4/fly_linux_amd64

# create keys
sudo mkdir /etc/concourse
sudo ssh-keygen -t rsa -q -N '' -f /etc/concourse/tsa_host_key
sudo ssh-keygen -t rsa -q -N '' -f /etc/concourse/worker_key
sudo ssh-keygen -t rsa -q -N '' -f /etc/concourse/session_signing_key

# copy to get a worker key
sudo cp /etc/concourse/worker_key.pub /etc/concourse/authorized_worker_keys

# set env variables
# file - /etc/concourse/web_environment
# put it in .bashrc as well

# Concourse web
export CONCOURSE_SESSION_SIGNING_KEY=/etc/concourse/session_signing_key
export CONCOURSE_TSA_HOST_KEY=/etc/concourse/tsa_host_key
export CONCOURSE_TSA_AUTHORIZED_KEYS=/etc/concourse/authorized_worker_keys
export CONCOURSE_POSTGRES_SOCKET=/var/run/postgresql

export CONCOURSE_BASIC_AUTH_USERNAME=root
export CONCOURSE_BASIC_AUTH_PASSWORD=vmware
export CONCOURSE_EXTERNAL_URL=http://10.160.29.4:8080

# Concourse worker
export CONCOURSE_WORK_DIR=/var/lib/concourse
export CONCOURSE_TSA_WORKER_PRIVATE_KEY=/etc/concourse/worker_key
export CONCOURSE_TSA_PUBLIC_KEY=/etc/concourse/tsa_host_key.pub
export CONCOURSE_TSA_HOST=127.0.0.1


# change password of concourse postgres user
sudo -u concourse psql postgres
# type \password and give new password

# Changing peer authentication to md5, open following file and change peer to md5
vim /etc/postgresql/9.3/main/pg_hba.conf

# restart service
service postgresql restart

# run web
nohup concourse web --postgres-user=concourse --postgres-password=admin &

# run worker
nohup concourse worker &
