#!/bin/bash -ue

# Copyright 2013 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

host_ip=""
host_name="tsuru-sample.com"
mongohost="127.0.0.1"
mongoport="27017"
dockerhost="127.0.0.1"
dockerport="4243"

IFS=''

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
admin-listen: "127.0.0.1:8888"
host: http://{{{HOST_IP}}}:8080
debug: true
admin-team: admin

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
  domain: {{{HOST_NAME}}}
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

#############################################################################

function running_port {
    local appname=$1
    echo $(running_addr $appname | sed s/.*://)
}

function running_addr {
    local appname=$1
    sleep 1
    if [[ $appname == "node" ]]; then sleep 2; fi
    echo $(sudo netstat -tnlp | grep $appname | tr -s " " | cut -d' ' -f 4 | sort | head -n1)
}

function installed_version {
    local cmdid=${1-}
    local minversion=${2-}
    local version=${3-}
    local max_version=$(echo -e "${minversion}min\n$version" | sort -V | tail -n 1)
    local install_var=$(eval echo $`echo '{install_'`${cmdid}`echo '-}'`)
    if [[ $install_var != "1" && $max_version != "${minversion}min" ]]; then
        echo $max_version
    fi
}

#############################################################################

function set_host {
    if [[ $host_ip == "" ]]; then
        host_ip=$(curl -s -L -m2 http://169.254.169.254/latest/meta-data/public-hostname || true)
    fi
    if [[ $host_ip == "" ]]; then
        host_ip=$(ifconfig | grep -A1 eth | grep "inet addr" | tail -n1 | sed "s/.*addr:\([0-9.]*\).*/\1/")
    fi
    if [[ $host_ip == "" || $host_ip == "127.0.0.1" ]]; then
        echo "Couldn't find suitable host_ip, please run with --host-ip <external ip>"
        exit 1
    fi
    echo "Chosen host ip: $host_ip. You can override with --host-ip <external ip>"
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
    echo "Updating apt-get and installing basic dependencies (this could take a while)..."
    sudo apt-get update -qq
    sudo apt-get install screen curl mercurial git bzr redis-server python-software-properties -qqy
    sudo apt-add-repository ppa:tsuru/lvm2 -y >/dev/null 2>&1
    sudo apt-add-repository ppa:tsuru/ppa -y >/dev/null 2>&1
    sudo apt-get update -qq
}

function install_docker {
    local version=$(docker version 2>/dev/null | grep "Client version" | cut -d" " -f3)
    local iversion=$(installed_version docker 0.9.0 $version)
    if [[ $iversion != "" ]]; then
        echo "Skipping docker installation, version installed: $iversion"
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
    dockerport=$(running_port docker)
    if [[ $dockerport == "" ]]; then
        echo "Error: Couldn't find docker port, please check /var/log/upstart/docker.log for more information"
        exit 1
    fi
    echo "docker found running at $dockerhost:$dockerport"
    local home_host=$(bash -ic 'source ~/.bashrc && echo $DOCKER_HOST')
    if [[ $home_host != "$dockerhost:$dockerport" ]]; then
        echo "Adding DOCKER_HOST to ~/.bashrc"
        echo -e "export DOCKER_HOST=$dockerhost:$dockerport" | tee -a ~/.bashrc > /dev/null
    fi
}

function install_mongo {
    local version=$(mongod --version | grep "db version" | sed s/^.*v//)
    local iversion=$(installed_version mongo 2.4.0 $version)
    if [[ $iversion != "" ]]; then
        echo "Skipping mongod installation, version installed: $iversion"
    else
        echo "Installing mongodb..."
        sudo apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv 7F0CEB10
        echo "deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen" | sudo tee /etc/apt/sources.list.d/mongodb.list > /dev/null
        sudo apt-get update -qq
        sudo apt-get install mongodb-10gen -qqy
    fi
    sudo stop mongodb 1>&2 2>/dev/null || true
    sudo start mongodb
    mongoport=$(running_port mongod)
    if [[ $mongoport == "" ]]; then
        echo "Error: Couldn't find mongod port, please check /var/log/mongodb/mongodb.log for more information"
        exit 1
    fi
    echo "mongodb found running at $mongohost:$mongoport"
}

function install_hipache {
    # TODO detect existing installation
    sudo apt-get install node-hipache -qqy
    sudo stop hipache 1>&2 2>/dev/null || true
    sudo start hipache
    local addr=$(running_addr node)
    if [[ $addr == "" ]]; then
        echo "Error: Couldn't find hipache addr, please check /var/log/upstart/hipache.log for more information"
        exit 1
    fi
    echo "node hipache found running at $addr"

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
    local gandalfaddr=$(running_addr gandalf)
    if [[ $gandalfaddr == "" ]]; then
        echo "Error: Couldn't find gandalf addr, please check /var/log/upstart/gandalf-server.log for more information"
        exit 1
    fi
    echo "gandalf found running at $gandalfaddr"
    sudo stop git-daemon 1>&2 2>/dev/null || true
    sudo start git-daemon
    local gitaddr=$(running_addr git-daemon)
    if [[ $gitaddr == "" ]]; then
        echo "Error: Couldn't find git-daemon addr, please check your logs"
        exit 1
    fi
    echo "git-daemon found running at $gitaddr"

}

function install_beanstalkd {
    local version=$(beanstalkd -v | sed "s/[^0-9]*\([0-9.]*\)/\1/")
    local iversion=$(installed_version beanstalkd 1.4.5 $version)
    if [[ $iversion != "" ]]; then
        echo "Skipping beanstalkd installation, version installed: $iversion"
    else
        echo "Installing beanstalkd..."
        yes N | sudo apt-get install beanstalkd -qqy
    fi
    sudo service beanstalkd stop 1>&2 2>/dev/null || true
    sudo service beanstalkd start
    local port=$(running_port beanstalkd)
    if [[ $port == "" ]]; then
        echo $BEANSTALKD_CONF | sudo tee /etc/default/beanstalkd > /dev/null
        sudo service beanstalkd stop 1>&2 2>/dev/null || true
        sudo service beanstalkd start
        local port=$(running_port beanstalkd)
        if [[ $port == "" ]]; then
            echo "Error: Couldn't find beanstalkd port, please check your logs."
            exit 1
        fi
    fi
    echo "beanstalkd found running at 127.0.0.1:$port"
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

function install_go {
    local version=$(go version | sed "s/go version[^0-9]*\([0-9.]*\).*/\1/")
    local iversion=$(installed_version mongo 1.1.0 $version)
    if [[ $iversion != "" ]]; then
        echo "Skipping golang installation, version installed: $iversion"
    else
        echo "Installing golang..."
        if [[ $(uname -p | grep 64) == "" ]]; then
            local plat="386"
        else
            local plat="amd64"
        fi
        curl -sL https://godeb.s3.amazonaws.com/godeb-$plat.tar.gz -o /tmp/godeb.tgz
        tar -C /tmp -zxpf /tmp/godeb.tgz
        chmod +x /tmp/godeb
        /tmp/godeb install
    fi
    local gopath=$(bash -ic 'source ~/.bashrc && echo $GOPATH')
    if [[ $gopath != "$HOME/go" ]]; then
        echo "Adding GOPATH to ~/.bashrc"
        echo -e "export GOPATH=$HOME/go" | tee -a ~/.bashrc > /dev/null
    fi
    local path=$(bash -ic 'source ~/.bashrc && echo $PATH')
    if [[ ! $path =~ "$HOME/go/bin" ]]; then
        echo "Adding GOPATH/bin to PATH in ~/.bashrc"
        echo -e "export PATH=$HOME/go/bin:$PATH" | tee -a ~/.bashrc > /dev/null
    fi
    export GOPATH=$HOME/go
    export PATH=$HOME/go/bin:$PATH
}

function config_tsuru_pre {
    echo $TSURU_CONF | sudo tee /etc/tsuru/tsuru.conf > /dev/null
    sudo sed -i.old -e "s/{{{HOST_IP}}}/${host_ip}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{HOST_NAME}}}/${host_name}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_HOST}}}/${mongohost}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_PORT}}}/${mongoport}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e 's/=no/=yes/' /etc/default/tsuru-server
}

function config_tsuru_post {
    tsuru-admin target-add default 127.0.0.1:8080 || true
    tsuru-admin target-set default
}

function add_as_docker_node {
    mongo tsurudb --eval "db.docker_scheduler.insert({_id: 'theonepool'})"
    mongo tsurudb --eval "db.docker_scheduler.update({_id: 'theonepool'}, {\$addToSet: {nodes: 'http://$dockerhost:$dockerport'}})"
}

function add_initial_user {
    # TODO: Non-interactive admin user registration
    # admin:admin123
    # mongo tsurudb --eval 'db.users.insert({email: "admin", password: "$2a$10$WyfKu8CJeWpSHiC2EBntqeHKSn5j7bhcP/tBZer181Hs3DeOjl/Q."})'
    mongo tsurudb --eval 'db.teams.insert({_id: "admin"})'
    mongo tsurudb --eval "db.teams.update({_id: 'admin'}, {\$addToSet: {users: 'admin@example.com'}})"
    if [[ ! -e ~/.tsuru_token ]]; then
        echo 'Registering admin@example.com user. Please enter a password.'
        tsuru-admin user-create admin@example.com
        echo 'Please type the password again.'
        tsuru-admin login admin@example.com
    fi
}

function install_abyss {
    if [[ ! -e ~/.ssh/id_rsa ]]; then
        yes | ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/id_rsa > /dev/null
        tsuru key-add
    fi
    has_plat=$(tsuru platform-list | grep python)
    if [[ $has_plat == "" ]]; then
        tsuru-admin platform-add python --dockerfile https://raw.githubusercontent.com/tsuru/basebuilder/master/python/Dockerfile
    fi
    tsuru app-create abyss python || true
    pushd /tmp
    if [[ ! -e /tmp/abyss/app.yaml ]]; then
        git clone https://github.com/tsuru/tsuru-dashboard abyss
    fi
    pushd abyss
    git reset --hard
    git clean -dfx
    git pull
    git remote add tsuru git@192.168.50.6:abyss.git || true
    git push tsuru master
    popd
    popd
}

function install_tsuru_pkg {
    echo "Installing Tsuru from deb package..."
    sudo apt-get install tsuru-server -qqy

    sudo stop tsuru-ssh-agent >/dev/null 2>&1 || true
    sudo stop tsuru-server-api >/dev/null 2>&1 || true
    sudo stop tsuru-server-collector >/dev/null 2>&1 || true
    sudo stop tsuru-server-admin >/dev/null 2>&1 || true

    sudo start tsuru-ssh-agent
    sudo start tsuru-server-api
    sudo start tsuru-server-collector
    sudo start tsuru-server-admin
}

function install_tsuru_src {
    echo "Installing Tsuru from source (this could take some minutes)..."
    if [[ -e $GOPATH/src/github.com/tsuru/tsuru ]]; then
        pushd $GOPATH/src/github.com/tsuru/tsuru
        git reset --hard && git clean -dfx && git pull
        popd
    fi
    go get github.com/tsuru/tsuru/cmd/tsr
    go get github.com/tsuru/tsuru/cmd/tsuru-admin
    go get github.com/tsuru/tsuru/cmd/tsuru

    screen -X -S admin quit || true
    screen -X -S api quit || true
    screen -X -S collector quit || true
    screen -X -S ssh quit || true

    local config_file=/etc/tsuru/tsuru.conf
    screen -S admin -d -m tsr admin-api --config=$config_file
    screen -S api -d -m tsr api --config=$config_file
    screen -S collector -d -m tsr collector --config=$config_file
    screen -S ssh -d -m tsr docker-ssh-agent -l 0.0.0.0:4545 -u ubuntu -k /var/lib/tsuru/.ssh/id_rsa
}

function config_git_key {
    local tsuru_token=$(bash -ic 'source ~git/.bash_profile && echo $TSURU_TOKEN')
    if [[ $tsuru_token == "" ]]; then
        echo "Adding tsr token to ~git/.bash_profile"
        local token=$(tsr token)
        echo "export TSURU_TOKEN=$token" | sudo tee -a ~git/.bash_profile > /dev/null
    fi
    local tsuru_host=$(bash -ic 'source ~git/.bash_profile && echo $TSURU_HOST')
    if [[ $tsuru_host != "$host_ip:8080" ]]; then
        echo "Adding tsr host to ~git/.bash_profile"
        echo "export TSURU_HOST=$host_ip:8080" | sudo tee -a ~git/.bash_profile > /dev/null
    fi
    sudo chown -R git:git ~git/.bash_profile
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
    config_tsuru_pre
    if [[ ${install_tsuru_pkg-} == "1" ]]; then
        install_tsuru_pkg
    else
        install_go
        install_tsuru_src
    fi
    config_tsuru_post
    config_git_key
    add_as_docker_node
    add_initial_user
    install_abyss

    echo '######################## DONE! ########################'
    echo
    local cont_id=$(docker ps | grep abyss | cut -d ' ' -f 1)
    local abyss_port=$(docker inspect $cont_id | grep HostPort  | head -n1 | sed "s/[^0-9]//g")
    echo "Your dashboard is running at $host_ip:$abyss_port"
    echo
    echo "Your tsuru target is $host_ip:8080"
    echo
    echo "To use Tsuru router you should have a DNS entry *.$host_name -> $host_ip"
}

while [ "${1-}" != "" ]; do
    case $1 in
        "--host-name")
            shift
            host_name=$1
            ;;
        "--host-ip")
            shift
            host_ip=$1
            ;;
        "--tsuru-pkg")
            install_tsuru_pkg=1
            ;;
        "-f" | "--force-install")
            shift
            declare "install_$1=1"
            ;;
    esac
    shift
done

install_all
