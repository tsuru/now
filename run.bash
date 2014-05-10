#!/bin/bash -ue

# Copyright 2013 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

host_ip="127.0.0.1"
mongohost="127.0.0.1"
mongoport="27017"
dockerhost="127.0.0.1"
dockerport=""

GANDALF_CONF=$(cat <<EOF
bin-path: /usr/bin/gandalf-ssh
git:
  bare:
    location: /var/lib/gandalf/repositories
    template: /home/git/bare-template
host: {{{HOST_IP}}}
bind: localhost:8000
uid: git
EOF
)

BEANSTALKD_CONF=$(cat <<EOF
BEANSTALKD_LISTEN_ADDR=127.0.0.1
BEANSTALKD_LISTEN_PORT=11300
DAEMON_OPTS="-l \$BEANSTALKD_LISTEN_ADDR -p \$BEANSTALKD_LISTEN_PORT -b /var/lib/beanstalkd"
START=yes
EOF
)

TSURU_CONF=$(cat <<EOF
listen: "0.0.0.0:8080"
admin-listen: "0.0.0.0:8888"
host: http://{{{HOST_IP}}}:8080
debug: true

database:
  url: {{{MONGO_HOST}}}:{{{MONGO_PORT}}}
  name: tsurudb

git:
  unit-repo: /home/application/current
  api-server: http://127.0.0.1:8000
  rw-host: {{{HOST_IP}}}
  ro-host: {{{HOST_IP}}}

auth:
  user-registration: true
  scheme: native

provisioner: docker
hipache:
  domain: tsuru-sample.com
docker:
  collection: docker_containers
  repository-namespace: tsuru
  router: hipache
  deploy-cmd: /var/lib/tsuru/deploy
  ssh-agent-port: 4545
  segregate: true
  scheduler:
    redis-server: 127.0.0.1:6379
    redis-prefix: docker-cluster
  run-cmd:
    bin: /var/lib/tsuru/start
    port: "8888"
  ssh:
    add-key-cmd: /var/lib/tsuru/add-key
    public-key: /var/lib/tsuru/.ssh/id_rsa.pub
    user: ubuntu
EOF
)

function set_host {
    host_ip=$(curl -s -L -m2 http://169.254.169.254/latest/meta-data/public-hostname || true)
    if [[ $host_ip == "" ]]; then
        host_ip=$(ifconfig | grep -A1 eth | grep "inet addr" | tail -n1 | sed "s/.*addr:\([0-9.]*\).*/\1/")
    fi
    echo "Chosen host ip: $host_ip"
}

function check_support {
    if [ `id -u` == "0" ]; then
        echo -e "Error: You should NOT run this script as root, it'll sudo commands as needed."
        exit 1
    fi

    which apt-get > /dev/null
    if [ $? -ne 0 ]; then
        echo "Error: apt-get should be available on the system"
        exit 1
    fi
}

function install_basic_deps {
    echo "Updating apt-get and installing basic dependencies..."
    sudo apt-get update -qq
    sudo apt-get install curl mercurial git bzr redis-server python-software-properties -qqy
    sudo apt-add-repository ppa:tsuru/lvm2 -y >/dev/null 2>&1
    sudo apt-add-repository ppa:tsuru/ppa -y >/dev/null 2>&1
    sudo apt-get update -qq
}

function install_docker {
    local version=$(docker version 2>/dev/null | grep "Client version" | cut -d" " -f3)
    local max_version=$(echo -e "0.9.0min\n$version" | sort -V | tail -n 1)
    if [[ ${install_docker-} != "1" && $max_version != "0.9.0min" ]]; then
        echo "Skipping docker installation, version installed: $max_version"
    else
        echo "Installing docker..."
        curl -s https://get.docker.io/gpg | sudo apt-key add -
        echo "deb http://get.docker.io/ubuntu docker main" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update -qq
        sudo apt-get install lxc-docker -qqy
    fi
    local opts=$(bash -c 'source /etc/default/docker && echo $DOCKER_OPTS')
    if [[ ! $opts =~ "tcp://" ]]; then
        echo "Changing /etc/default/docker to listen on tcp://127.0.0.1:4243..."
        echo 'DOCKER_OPTS="$DOCKER_OPTS -H tcp://127.0.0.1:4243"' | sudo tee -a /etc/default/docker > /dev/null
    fi
    sudo stop docker 1>&2 2>/dev/null || true
    sudo start docker
    sleep 1
    dockerport=$(sudo netstat -tnlp | grep docker | tr -s " " | cut -d' ' -f 4 | sed s/.*://)
    if [[ $dockerport == "" ]]; then
        echo "Error: Couldn't find docker port, please check /var/log/upstart/docker.log for more information"
        exit 1
    fi
    echo "Docker found running at $dockerhost:$dockerport"
    local home_host=$(bash -ic 'source ~/.bashrc && echo $DOCKER_HOST')
    if [[ $home_host != "$dockerhost:$dockerport" ]]; then
        echo "Adding DOCKER_HOST to ~/.bashrc"
        echo -e "export DOCKER_HOST=$dockerhost:$dockerport" | tee -a ~/.bashrc > /dev/null
    fi
}

function install_mongo {
    local version=$(mongod --version | grep "db version" | sed s/^.*v//)
    local max_version=$(echo -e "2.4.0min\n$version" | sort -V | tail -n 1)
    if [[ ${install_mongo-} != "1" && $max_version != "2.4.0min" ]]; then
        echo "Skipping mongod installation, version installed: $max_version"
    else
        echo "Installing mongodb..."
        sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
        echo "deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen" | sudo tee /etc/apt/sources.list.d/mongodb.list > /dev/null
        sudo apt-get update -qq
        sudo apt-get install mongodb-10gen -qqy
    fi
    sudo stop mongodb 1>&2 2>/dev/null || true
    sudo start mongodb
    sleep 1
    mongoport=$(sudo netstat -tnlp | grep mongod | tr -s " " | cut -d' ' -f 4 | sed s/.*:// | sort | head -n1)
    if [[ $mongoport == "" ]]; then
        echo "Error: Couldn't find mongod port, please check /var/log/mongodb/mongodb.log for more information"
        exit 1
    fi
    echo "Mongodb found running at $mongohost:$mongoport"
}

function install_hipache {
    sudo apt-get install node-hipache -qqy
    sudo stop hipache 1>&2 2>/dev/null || true
    sudo start hipache
}

function install_gandalf {
    sudo apt-get install gandalf-server -qqy
    local hook_dir=/home/git/bare-template/hooks
    sudo mkdir -p $hook_dir
    sudo curl -s -L https://raw.github.com/tsuru/tsuru/master/misc/git-hooks/post-receive -o ${hook_dir}/post-receive
    sudo chmod +x ${hook_dir}/post-receive
    sudo chown -R git:git /home/git/bare-template
    echo $GANDALF_CONF | sudo tee /etc/gandalf.conf > /dev/null
    sudo sed -i.old -e "s/{{{HOST_IP}}}/${host_ip}/" /etc/gandalf.conf
    sudo rm /etc/gandalf.conf.old
    sudo stop gandalf-server 1>&2 2>/dev/null || true
    sudo start gandalf-server
}

function install_beanstalkd {
    yes N | sudo apt-get install beanstalkd -qqy
    echo $BEANSTALKD_CONF | sudo tee /etc/default/beanstalkd > /dev/null
    sudo service beanstalkd stop 1>&2 2>/dev/null || true
    sudo service beanstalkd start
}

function generate_key {
    if [[ -e /var/lib/tsuru/.ssh/id_rsa ]]; then
        echo "SSH key for tsuru already exist at /var/lib/tsuru/.ssh/id_rsa"
    else
        echo "Creating SSH key for tsuru at /var/lib/tsuru/.ssh/id_rsa"
        sudo mkdir -p /var/lib/tsuru/.ssh
        yes | sudo ssh-keygen -t rsa -b 4096 -N "" -f /var/lib/tsuru/.ssh/id_rsa > /dev/null
        local user_name=$(id -un)
        sudo chown -R $user_name:$user_name /var/lib/tsuru
    fi
}

function install_tsuru {
    sudo apt-get install tsuru-server -qqy

    echo $TSURU_CONF | sudo tee /etc/tsuru/tsuru.conf > /dev/null
    sudo sed -i.old -e "s/{{{HOST_IP}}}/${host_ip}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_HOST}}}/${mongohost}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_PORT}}}/${mongoport}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e 's/=no/=yes/' /etc/default/tsuru-server

    sudo stop tsuru-ssh-agent >/dev/null 2>&1 || true
    sudo stop tsuru-server-api >/dev/null 2>&1 || true
    sudo stop tsuru-server-collector >/dev/null 2>&1 || true
    sudo stop tsuru-server-admin >/dev/null 2>&1 || true

    sudo start tsuru-ssh-agent
    sudo start tsuru-server-api
    sudo start tsuru-server-collector
    sudo start tsuru-server-admin

    local existing_node=$(tsr docker-list-nodes | grep $dockerhost:$dockerport)
    if [[ $existing_node == "" ]]; then
        tsr docker-add-node node1 http://$dockerhost:$dockerport
    fi
}

function install_all {
    check_support
    install_basic_deps
    set_host
    install_docker
    install_mongo
    install_hipache
    install_beanstalkd
    install_gandalf
    generate_key
    install_tsuru
}

while [ "${1-}" != "" ]; do
    case $1 in
        "-f" | "--force-install")
            shift
            declare "install_$1=1"
            ;;
    esac
    shift
done

install_all
