#!/bin/bash -ue

# Copyright 2013 tsuru authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -u
set -e

host_ip=""
host_name="tsuru-sample.com"
mongohost="127.0.0.1"
mongoport="27017"
dockerhost="127.0.0.1"
dockerport="4243"
adminuser="admin@example.com"
adminpassword="admin123"
install_archive_server=0
hook_url=https://raw.github.com/tsuru/tsuru/master/misc/git-hooks/post-receive
hook_name=post-receive
git_envs=(A=B)
aws_access_key=""
aws_secret_key=""

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

TSURU_CONF=$(cat <<EOF
listen: "0.0.0.0:8080"
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
queue: redis
redis-queue:
  host: localhost
  port: 6379
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
    for counter in {1..10}; do
        sleep 0.5
        local addr=$(sudo netstat -tnlp | grep $appname | tr -s " " | cut -d' ' -f 4 | sort | head -n1)
        if [[ $addr != "" ]]; then
            echo $addr
            break
        fi
        echo "Waiting for ${appname}..." 1>&2
    done
}

function installed_version {
    local cmdid=${1-}
    local minversion=${2-}
    local version=${3-}
    local max_version=$(echo -e "${minversion}min\n$version" | sort -V | tail -n 1)
    local install_var=$(eval echo $`echo '{force_install_'`${cmdid}`echo '-}'`)
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
        host_ip=$(ifconfig | grep -A1 eth | grep "inet addr" | tail -n1 | sed "s/[^0-9]*\([0-9.]*\).*/\1/")
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
    sudo apt-get install jq screen curl mercurial git bzr redis-server python-software-properties -qqy
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
    export DOCKER_HOST=$dockerhost:$dockerport
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
    sudo curl -sL ${hook_url} -o ${hook_dir}/${hook_name}
    sudo chmod +x ${hook_dir}/${hook_name}
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
    echo -e "Host ${host_ip}\n\tStrictHostKeyChecking no\n" >> ~/.ssh/config
    sudo stop git-daemon 1>&2 2>/dev/null || true
    sudo start git-daemon
    local gitaddr=$(running_addr git-daemon)
    if [[ $gitaddr == "" ]]; then
        echo "Error: Couldn't find git-daemon addr, please check your logs"
        exit 1
    fi
    echo "git-daemon found running at $gitaddr"

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
    local iversion=$(installed_version go 1.1.0 $version)
    if [[ $iversion != "" ]]; then
        echo "Skipping go installation, version installed: $iversion"
    else
        echo "Installing go..."
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
    sudo mkdir -p /etc/tsuru
    echo $TSURU_CONF | sudo tee /etc/tsuru/tsuru.conf > /dev/null
    sudo sed -i.old -e "s/{{{HOST_IP}}}/${host_ip}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{HOST_NAME}}}/${host_name}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_HOST}}}/${mongohost}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_PORT}}}/${mongoport}/g" /etc/tsuru/tsuru.conf
    if [[ -e /etc/default/tsuru-server ]]; then
        sudo sed -i.old -e 's/=no/=yes/' /etc/default/tsuru-server
    fi
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
    echo "Adding initial admin user..."
    mongo tsurudb --eval 'db.teams.insert({_id: "admin"})'
    mongo tsurudb --eval "db.teams.update({_id: 'admin'}, {\$addToSet: {users: '${adminuser}'}})"
    curl -s -XPOST -d"{\"email\":\"${adminuser}\",\"password\":\"${adminpassword}\"}" http://${host_ip}:8080/users
    local token=$(curl -s -XPOST -d"{\"password\":\"${adminpassword}\"}" http://${host_ip}:8080/users/${adminuser}/tokens | jq -r .token)
    echo $token > ~/.tsuru_token
}

function install_dashboard {
    echo "Installing tsuru-dashboard..."
    if [[ ! -e ~/.ssh/id_rsa ]]; then
        yes | ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/id_rsa > /dev/null
    fi
    tsuru key-add || true
    has_plat=`(tsuru platform-list | grep python) || true`
    if [[ $has_plat == "" ]]; then
        tsuru-admin platform-add python --dockerfile https://raw.githubusercontent.com/tsuru/basebuilder/master/python/Dockerfile
    fi
    local platform_ok=$(docker run --rm tsuru/python bash -c "circusd --daemon /etc/circus/circus.ini && sleep 2 && ps aux | grep circusd | grep -v grep")
    if [[ $platform_ok == "" ]]; then
        # Circusd bugged version, rebuilding platform
        tsuru-admin platform-update python --dockerfile https://raw.githubusercontent.com/tsuru/basebuilder/master/python/Dockerfile
    fi
    local platform_ok=$(docker run --rm tsuru/python bash -c "circusd --daemon /etc/circus/circus.ini && sleep 2 && ps aux | grep circusd | grep -v grep")
    if [[ $platform_ok == "" ]]; then
        echo "Error trying to start circus inside python docker image. Please report this as a bug in https://github.com/tsuru/now/issues"
        echo "Additional information:"
        uname -a
        docker version
        echo "Tsuru hash: "
        git --git-dir ~/go/src/github.com/tsuru/tsuru/.git log | head -n1
        exit 1
    fi
    tsuru app-create tsuru-dashboard python || true
    pushd /tmp
    if [[ ! -e /tmp/tsuru-dashboard/app.yaml ]]; then
        git clone https://github.com/tsuru/tsuru-dashboard
    fi
    pushd tsuru-dashboard
    git reset --hard
    git clean -dfx
    git pull
    git remote add tsuru git@${host_ip}:tsuru-dashboard.git || true
    git push tsuru master
    popd
    popd
}

function install_tsuru_pkg {
    echo "Installing Tsuru from deb package..."
    sudo apt-get install tsuru-server tsuru-admin tsuru -qqy

    sudo stop tsuru-ssh-agent >/dev/null 2>&1 || true
    sudo stop tsuru-server-api >/dev/null 2>&1 || true
    sudo stop tsuru-server-collector >/dev/null 2>&1 || true

    sudo start tsuru-ssh-agent
    sudo start tsuru-server-api
    sudo start tsuru-server-collector
}

function install_tsuru_src {
    echo "Installing Tsuru from source (this could take some minutes)..."
    go get github.com/tools/godep
    if [[ -e $GOPATH/src/github.com/tsuru/tsuru ]]; then
        pushd $GOPATH/src/github.com/tsuru/tsuru
        git reset --hard && git clean -dfx && git pull
        godep restore
        popd
    else
        mkdir -p $GOPATH/src/github.com/tsuru/tsuru
        pushd $GOPATH/src/github.com/tsuru/tsuru
        git clone https://github.com/tsuru/tsuru .
        godep restore
        popd
    fi
    go get github.com/tsuru/tsuru/cmd/tsr
    go get github.com/tsuru/tsuru/cmd/tsuru-admin
    go get github.com/tsuru/tsuru/cmd/tsuru

    screen -X -S api quit || true
    screen -X -S collector quit || true
    screen -X -S ssh quit || true

    local config_file=/etc/tsuru/tsuru.conf
    screen -S api -d -m tsr api --config=$config_file
    screen -S collector -d -m tsr collector --config=$config_file
    screen -S ssh -d -m tsr docker-ssh-agent -l 0.0.0.0:4545 -u ubuntu -k /var/lib/tsuru/.ssh/id_rsa
}

function install_archive_server_src {
    echo "Installing archive-server from source..."
    if [[ -e $GOPATH/src/github.com/tsuru/archive-server ]]; then
        pushd $GOPATH/src/github.com/tsuru/archive-server
        git reset --hard && git clean -dfx && git pull
        popd
    fi
    go get github.com/tsuru/archive-server

    screen -X -S archiveserver quit || true
    sudo mkdir -p /var/lib/archives
    sudo chown `id -nu`:`id -ng` /var/lib/archives

    local archive_server_read=$(bash -ic 'source ~git/.bash_profile && echo $ARCHIVE_SERVER_READ')
    if [[ $archive_server_read != "http://${host_ip}:6161" ]]; then
        echo "Adding archive server environment to ~git/.bash_profile"
        echo "export ARCHIVE_SERVER_READ=http://${host_ip}:6060" | sudo tee -a ~git/.bash_profile > /dev/null
        echo "export ARCHIVE_SERVER_WRITE=http://127.0.0.1:6161" | sudo tee -a ~git/.bash_profile > /dev/null
    fi

    screen -S archiveserver -d -m archive-server -read-http=0.0.0.0:6060 -write-http=127.0.0.1:6161 -dir=/var/lib/archives
}

function install_swift {
    sudo apt-get install python-pip -y
    sudo pip install python-swiftclient
}

function install_s3cmd {
    sudo apt-get install s3cmd -y
    sudo -u git cat > ~git/.s3cfg <<END
[default]
access_key = ${aws_access_key}
bucket_location = US
cloudfront_host = cloudfront.amazonaws.com
default_mime_type = binary/octet-stream
delete_removed = False
dry_run = False
enable_multipart = True
encoding = ANSI_X3.4-1968
encrypt = False
follow_symlinks = False
force = False
get_continue = False
gpg_command = /usr/bin/gpg
gpg_decrypt = %(gpg_command)s -d --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
gpg_encrypt = %(gpg_command)s -c --verbose --no-use-agent --batch --yes --passphrase-fd %(passphrase_fd)s -o %(output_file)s %(input_file)s
gpg_passphrase =
guess_mime_type = True
host_base = s3.amazonaws.com
host_bucket = %(bucket)s.s3.amazonaws.com
human_readable_sizes = False
invalidate_on_cf = False
list_md5 = False
log_target_prefix =
mime_type =
multipart_chunk_size_mb = 15
preserve_attrs = True
progress_meter = True
proxy_host =
proxy_port = 0
recursive = False
recv_chunk = 4096
reduced_redundancy = False
secret_key = ${aws_secret_key}
send_chunk = 4096
simpledb_host = sdb.amazonaws.com
skip_existing = False
socket_timeout = 300
urlencoding_mode = normal
use_https = True
verbosity = WARNING
website_endpoint = http://%(bucket)s.s3-website-%(location)s.amazonaws.com/
website_error =
website_index = index.html
END
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

function add_git_envs {
    if [ "${#git_envs[@]}" > 1 ]; then
        echo "Serializing provided env vars to ~git/.bash_profile"
        echo export ${git_envs[@]:1} | sudo tee -a ~git/.bash_profile > /dev/null
    fi
}

function install_all {
    check_support
    # install_basic_deps
    set_host
    install_docker
    install_mongo
    install_hipache
    install_gandalf
    generate_key
    config_tsuru_pre
    if [[ ${install_tsuru_pkg-} == "1" ]]; then
        install_tsuru_pkg
    else
        install_go
        install_tsuru_src
    fi
    if [[ ${install_archive_server} == "1" ]]; then
        install_go
        install_archive_server_src
    fi
    install_swift
    if [[ ${aws_access_key} != "" && ${aws_secret_key} != "" ]]; then
        install_s3cmd
    fi
    config_tsuru_post
    config_git_key
    add_git_envs
    add_as_docker_node
    add_initial_user
    install_dashboard

    local cont_id=$(docker ps | grep tsuru-dashboard | cut -d ' ' -f 1)
    local dashboard_port=$(docker inspect $cont_id | grep HostPort  | head -n1 | sed "s/[^0-9]//g")
    echo '######################## DONE! ########################'
    echo
    echo "Some information about your tsuru installation:"
    echo
    echo "Admin user: ${adminuser}"
    echo "Admin password: ${adminpassword} (PLEASE CHANGE RUNNING: tsuru change-password)"
    echo "Target address: $host_ip:8080"
    echo "Dashboard address: $host_ip:$dashboard_port"
    echo
    echo "To use Tsuru router you should have a DNS entry *.$host_name -> $host_ip"
    echo
    echo "You should run \`source ~/.bashrc\` on your current terminal."
    echo
    echo "Installed apps:"
    sleep 1
    tsuru app-list
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
            declare "force_install_$1=1"
            ;;
        "--archive-server")
            install_archive_server=1
            ;;
        "--hook-url")
            shift
            hook_url=$1
            ;;
        "--hook-name")
            shift
            hook_name=$1
            ;;
        "--env")
            shift
            git_envs=("${git_envs[@]}" "$1=\"$2\"")
            shift
            ;;
        "--aws-access-key")
            shift
            aws_access_key=$1
            ;;
        "--aws-secret-key")
            shift
            aws_secret_key=$1
            ;;
    esac
    shift
done

install_all
