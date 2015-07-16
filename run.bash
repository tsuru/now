#!/bin/bash -ue

# Copyright 2015 tsuru-now authors. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -eu

release=""
codename=""
host_ip=""
host_name=""
set_interface=""
is_debug=""
docker_node=""
set_interface=""
router=""
install_func=install_all
pool="theonepool"
mongohost="127.0.0.1"
mongoport="27017"
dockerhost="127.0.0.1"
dockerport="2375"
registryport="5000"
adminuser="admin@example.com"
adminpassword="admin123"
install_archive_server=0
hook_url=https://raw.github.com/tsuru/tsuru/master/misc/git-hooks/post-receive
hook_name=post-receive
git_envs=(A=B)
aws_access_key=""
aws_secret_key=""
ext_repository=""
export DEBIAN_FRONTEND=noninteractive

declare -A DISTMAP=(
    [wheezy]=wheezy-backports
    [precise]=precise
    [saucy]=saucy
    [trusty]=trusty
    [utopic]=utopic
)

ROUTER_HIPACHE=$(cat <<EOF
  hipache:
    type: hipache
    domain: {{{HOST_NAME}}}
    redis-server: 127.0.0.1:6379
EOF
)

ROUTER_VULCAND=$(cat <<EOF
  vulcand:
    type: vulcand
    api-url: http://127.0.0.1:8182
    domain: {{{HOST_NAME}}}
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

auth:
  user-registration: true
  scheme: native
routers:
{{{ROUTER_ENTRY}}}
repo-manager: gandalf
provisioner: docker
queue:
  mongo-url: {{{MONGO_HOST}}}:{{{MONGO_PORT}}}
  mongo-database: tsuru_queue
redis-queue:
  host: localhost
  port: 6379
docker:
  bs:
    image: tsuru/bs
    reporter-interval: 10
    socket: /var/run/docker.sock
  collection: docker_containers
  registry: {{{HOST_IP}}}:$registryport
  repository-namespace: tsuru
  router: {{{ROUTER}}}
  deploy-cmd: /var/lib/tsuru/deploy
  segregate: true
  cluster:
    storage: mongodb
    mongo-url: {{{MONGO_HOST}}}:{{{MONGO_PORT}}}
    mongo-database: dockercluster
  run-cmd:
    bin: /var/lib/tsuru/start
    port: "8888"
  ssh:
    add-key-cmd: /var/lib/tsuru/add-key
    user: ubuntu
EOF
)

function error {
    echo "$@" 1>&2
}

function running_port {
    local appname=$1
    running_addr "${appname}" | sed "s/.*://"
}

function running_addr {
    local appname=$1
    for _ in {1..30}; do
        sleep 0.5
        local addr=$(sudo netstat -tnlp | grep "${appname}" | tr -s " " | cut -d' ' -f 4 | sort | head -n1)
        if [[ $addr != "" ]]; then
            echo "${addr}"
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
        echo "${max_version}"
    fi
}

function public_ip {
    local ip=$(curl -s -L -m2 http://169.254.169.254/latest/meta-data/public-ipv4 || true)
    if [[ $ip == "" ]]; then
        ip=$(/sbin/ifconfig | grep -A1 eth | grep "inet addr" | tail -n1 | sed "s/[^0-9]*\([0-9.]*\).*/\1/")
    fi
    if [[ $ip == "" ]]; then
        ip=$(/sbin/ifconfig | grep -A1 venet0 | grep "inet addr" | tail -n1 | sed "s/[^0-9]*\([0-9.]*\).*/\1/")
    fi
    if [[ $ip == "" ]]; then
        ip=$(ifconfig | grep -A1 wlan | grep "inet addr" | tail -n1 | sed "s/[^0-9]*\([0-9.]*\).*/\1/")
    fi
    if [[ $ip == "" ]]; then
        error "Couldn't find suitable public ip"
        exit 1
    fi
    echo "${ip}"
}

function set_host {
    if [[ "$host_ip" && "$set_interface" ]]; then
        sudo ifconfig lo:0 $host_ip netmask 255.255.255.255 up
    fi
    if [[ $host_ip == "" ]]; then
        host_ip=$(public_ip)
    fi
    if [[ $host_ip == "127.0.0.1" ]]; then
        echo "Couldn't find suitable host_ip, please run with --host-ip <external ip>"
        exit 1
    fi
    echo "Chosen host ip: $host_ip. You can override with --host-ip <external ip>"

    if [[ $host_name == "" ]]; then
        host_name="$host_ip.nip.io"
        dockerhost=$host_name
        echo "$host_ip $host_name" | sudo tee -a /etc/hosts
    fi
    echo "Chosen host name: $host_name. You can override with --host-name <hostname>"
}

function check_support {
    which apt-get > /dev/null
    if [ $? -ne 0 ]; then
        error "Error: apt-get should be available on the system"
        exit 1
    fi
    distid=$(lsb_release -is)
    release=$(lsb_release -rs)
    codename=$(lsb_release -cs)
    if [[ $distid == "Debian" && $release -lt 7 ]]; then
        error "Error: This script requires Debian release >= 7"
    fi
    echo "Detect ${distid} ${release} (${codename}), supported system"
}

function install_basic_deps {
    local tsuru_ppa_source=$1
    echo "Updating apt-get and installing basic dependencies (this could take a while)..."
    if [[ $distid == "Debian" && $release -gt 7 && $release -lt 8 ]]; then
        if ! apt-cache policy | grep "l=Debian Backports" > /dev/null; then
            echo 'deb http://http.debian.net/debian wheezy-backports main contrib non-free' | sudo tee /etc/apt/sources.list.d/backports.list
        fi
        sudo apt-get update -qq
        sudo apt-get install virtualbox-guest-utils virtualbox-guest-dkms linux-image-amd64 linux-headers-amd64 -qqy -t wheezy-backports
    fi
    sudo apt-get update
    sudo apt-get install jq screen curl mercurial git bzr redis-server software-properties-common -y
    if [[ $ext_repository ]]; then
        curl -sS ${ext_repository}/public.key | sudo apt-key add -
        echo "deb ${ext_repository} ${DISTMAP[$codename]} main contrib" | sudo tee /etc/apt/sources.list.d/tsuru-deb.list
        echo "deb-src ${ext_repository} ${DISTMAP[$codename]} main contrib" | sudo tee -a /etc/apt/sources.list.d/tsuru-deb.list
    elif [[ $distid == "Ubuntu" ]]; then
        if ! apt-cache policy | grep "l=tsuru-deb" > /dev/null; then
            sudo apt-add-repository ppa:tsuru/ppa -y >/dev/null 2>&1
            if [[ $tsuru_ppa_source == "nightly" ]]; then
                sudo apt-add-repository ppa:tsuru/snapshots -y >/dev/null 2>&1
            fi
        fi
    else
        error "PPA is only available in Ubuntu, please run with --ext-repository <repo>"
    fi
    sudo apt-get update
}

function install_docker {
    local version=$(docker version 2>/dev/null | grep "Client version" | cut -d" " -f3)
    local iversion=$(installed_version docker 0.20.0 "${version}")
    if [[ $iversion != "" ]]; then
        echo "Skipping docker installation, version installed: $iversion"
    else
        echo "Installing docker..."
        curl -sS https://get.docker.com/gpg | sudo apt-key add -
        echo "deb https://get.docker.com/ubuntu docker main" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        sudo apt-get update
        sudo apt-get install lxc-docker -y
    fi
    local opts=$(bash -c 'source /etc/default/docker && echo $DOCKER_OPTS')
    if [[ ! $opts =~ :// ]]; then
        echo "Changing /etc/default/docker to listen on tcp://0.0.0.0:${dockerport}..."
        echo "DOCKER_OPTS=\"\$DOCKER_OPTS -H tcp://0.0.0.0:${dockerport} -H unix:///var/run/docker.sock --insecure-registry=${host_ip}:${registryport}\"" | sudo tee -a /etc/default/docker > /dev/null
    fi
    sudo service docker stop 1>&2 2>/dev/null || true
    sudo service docker start
    sleep 1
    sudo service docker stop 1>&2 2>/dev/null || true
    sudo service docker start
    sleep 5
    dockerport=$(running_port docker)
    if [[ $dockerport == "" ]]; then
        echo "Error: Couldn't find docker port, please check /var/log/upstart/docker.log for more information"
        echo "/var/log/upstart/docker.log contents:"
        cat /var/log/upstart/docker.log
        exit 1
    fi
    echo "docker found running at $dockerhost:$dockerport"
    local home_host=$(bash -ic 'source ~/.bashrc && echo $DOCKER_HOST')
    if [[ $home_host != "tcp://$dockerhost:$dockerport" ]]; then
        echo "Adding DOCKER_HOST to ~/.bashrc"
        echo -e "export DOCKER_HOST=tcp://$dockerhost:$dockerport" | tee -a ~/.bashrc > /dev/null
    fi
    export DOCKER_HOST=tcp://$dockerhost:$dockerport
    docker_node="$docker_node $dockerhost:$dockerport"
}

function install_docker_registry {
    echo "Installing docker-registry..."
    sudo mkdir -p /var/lib/registry
    docker run -d -p ${registryport}:${registryport} -e REGISTRY_STORAGE_FILESYSTEM_ROOTDIRECTORY=/var/lib/registry -v /var/lib/registry:/var/lib/registry --restart=always --name registry registry:2
}

function install_mongo {
    sudo service mongod stop 1>&2 2>/dev/null || true
    sudo service mongodb stop 1>&2 2>/dev/null || true
    sudo apt-get remove --purge mongodb-10gen mongodb-org -y || true
    local version=$(mongod --version 2>/dev/null | grep "db version" | sed s/^.*v//)
    local iversion=$(installed_version mongo 2.4.0 "${version}")
    if [[ $iversion != "" ]]; then
        echo "Skipping mongod installation, version installed: ${iversion}"
    else
        echo "Installing mongodb..."
        sudo apt-get install mongodb -y
        sudo sed -i 's/^journal=true//' /etc/mongodb.conf
        echo "nojournal = true" | sudo tee -a /etc/mongodb.conf > /dev/null
    fi
    sudo service mongodb stop 1>&2 2>/dev/null || true
    sudo service mongodb start
    sleep 5
    mongoport=$(running_port mongod)
    if [[ $mongoport == "" ]]; then
        echo "Error: Couldn't find mongod port, please check /var/log/mongodb/mongod.log for more information"
        exit 1
    fi
    echo "mongodb found running at $mongohost:$mongoport"
}

function install_hipache {
    local version=$(npm list hipache -g | grep hipache@ | sed "s/.*hipache@//g")
    local iversion=$(installed_version hipache 0.3.0 "${version}")
    if [[ $iversion != "" ]]; then
        echo "Skipping hipache installation, version installed: $iversion"
    else
        echo "Installing hipache..."
        sudo apt-get install node-hipache -y
    fi
    sudo service hipache stop 1>&2 2>/dev/null || true
    sudo service hipache start
    sleep 5
    local addr=$(running_addr node)
    if [[ $addr == "" ]]; then
        echo "Error: Couldn't find hipache addr, please check /var/log/upstart/hipache.log for more information"
        echo "/var/log/upstart/hipache.log contents:"
        cat /var/log/upstart/hipache.log
        exit 1
    fi
    echo "node hipache found running at $addr"
    router="hipache"
}

function install_vulcand {
    docker rm -f tsuru_etcd tsuru_vulcand || true
    docker run -d --restart=always -p 4001:4001 --name tsuru_etcd quay.io/coreos/etcd:v2.0.12 --listen-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001 --advertise-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001
    docker run -d --restart=always -p 8182:8182 -p 80:8181 --name tsuru_vulcand mailgun/vulcand:v0.8.0-beta.2 /go/bin/vulcand -apiInterface="0.0.0.0" --etcd=http://172.17.42.1:4001
    router="vulcand"
}

function install_gandalf {
    sudo apt-get install gandalf-server -y
    local hook_dir=/home/git/bare-template/hooks
    sudo mkdir -p $hook_dir
    sudo curl -sSL ${hook_url} -o ${hook_dir}/${hook_name}
    sudo chmod +x ${hook_dir}/${hook_name}
    sudo chown -R git:git /home/git/bare-template
    sudo sed "s/^\(host: \).*$/\1${host_name}/" /etc/gandalf.conf -i
    sudo sed "s/^#\(\s*template: \).*$/\1\/home\/git\/bare-template/" /etc/gandalf.conf -i
    sudo service gandalf-server stop 1>&2 2>/dev/null || true
    sudo service gandalf-server start
    sleep 5
    local gandalfaddr=$(running_addr gandalf)
    if [[ $gandalfaddr == "" ]]; then
        echo "Error: Couldn't find gandalf addr, please check /var/log/upstart/gandalf-server.log for more information"
        echo "/var/log/upstart/gandalf-server.log contents:"
        cat /var/log/upstart/gandalf-server.log
        exit 1
    fi
    echo "gandalf found running at $gandalfaddr"
    sudo cp /usr/share/doc/gandalf-server/examples/git-daemon.default.example /etc/default/git-daemon
    sudo service git-daemon restart
    sleep 5
    local gitaddr=$(running_addr git-daemon)
    if [[ $gitaddr == "" ]]; then
        echo "Error: Couldn't find git-daemon addr, please check your logs"
        exit 1
    fi
    echo "git-daemon found running at $gitaddr"
}

function install_go {
    local version=$(go version 2>/dev/null | sed "s/go version[^0-9]*\([0-9.]*\).*/\1/")
    local iversion=$(installed_version go 1.1.0 "${version}")
    if [[ $iversion != "" ]]; then
        echo "Skipping go installation, version installed: $iversion"
    else
        echo "Installing go..."
        sudo apt-add-repository ppa:tsuru/golang -y
        sudo apt-get update
        sudo apt-get install golang -y
    fi
    if [[ ${GOPATH-} == "" ]]; then
        export GOPATH=$HOME/go
    fi
    mkdir -p $GOPATH
    local bash_gopath=$(bash -ic 'source ~/.bashrc && echo $GOPATH')
    if [[ $bash_gopath != $GOPATH ]]; then
        echo "Adding GOPATH=$GOPATH to ~/.bashrc"
        echo -e "export GOPATH=$GOPATH" | tee -a ~/.bashrc > /dev/null
    fi
    go get github.com/tools/godep
    sudo cp $(echo "${GOPATH}" | awk -F ':' '{print $1}')/bin/godep /usr/local/bin
}

function config_tsuru_pre {
    sudo mkdir -p /etc/tsuru
    echo "$TSURU_CONF" | sudo tee /etc/tsuru/tsuru.conf > /dev/null
    if [[ $router == "hipache" ]]; then
        router_entry="${ROUTER_HIPACHE}"
    elif [[ $router == "vulcand" ]]; then
        router_entry="${ROUTER_VULCAND}"
    fi
    sudo perl -pi.old -e "s;{{{ROUTER_ENTRY}}};${router_entry};g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{HOST_IP}}}/${host_ip}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{HOST_NAME}}}/${host_name}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_HOST}}}/${mongohost}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{MONGO_PORT}}}/${mongoport}/g" /etc/tsuru/tsuru.conf
    sudo sed -i.old -e "s/{{{ROUTER}}}/${router}/g" /etc/tsuru/tsuru.conf
    if [[ -e /etc/default/tsuru-server ]]; then
        sudo sed -i.old -e 's/=no/=yes/' /etc/default/tsuru-server
    fi
}

function config_tsuru_post {
    tsuru-admin target-remove default
    tsuru-admin target-add default "${host_name}:8080" || true
    tsuru-admin target-set default
}

function create_initial_user {
    echo "Creating initial admin user..."
    mongo tsurudb --eval 'db.teams.update({_id: "admin"}, {_id: "admin"}, {upsert: true})'
    mongo tsurudb --eval "db.teams.update({_id: 'admin'}, {\$addToSet: {users: '${adminuser}'}})"
    curl -sS -XPOST -d"{\"email\":\"${adminuser}\",\"password\":\"${adminpassword}\"}" "http://${host_name}:8080/users"
}

function enable_initial_user {
    echo "Retriving token and uploading public key for initial admin user..."
    if [[ ! -e ~/.tsuru_token ]]; then
        local token=$(curl -sS -XPOST -d"{\"password\":\"${adminpassword}\"}" "http://${host_name}:8080/users/${adminuser}/tokens" | jq -r .token)
        echo "${token}" > ~/.tsuru_token
    fi
    mkdir -p ~/.ssh
    if ! grep -Pzo "Host ${host_ip}\s+StrictHostKeyChecking no" ~/.ssh/config >/dev/null; then
        echo -e "Host ${host_ip}\n\tStrictHostKeyChecking no\n" >> ~/.ssh/config
    fi
    if ! grep -Pzo "Host ${host_name}\s+StrictHostKeyChecking no" ~/.ssh/config >/dev/null; then
        echo -e "Host ${host_name}\n\tStrictHostKeyChecking no\n" >> ~/.ssh/config
    fi
    if [[ ! -e ~/.ssh/id_rsa ]]; then
        yes | ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/id_rsa > /dev/null
    fi
    tsuru key-add rsa ~/.ssh/id_rsa.pub || true
}

function add_as_docker_node {
    echo "Adding docker node to pool..."
    tsuru-admin pool-add $pool -p 2>/dev/null || tsuru-admin pool-add $pool 2>/dev/null || true
    amount=0
    for node in $docker_node; do
        tsuru-admin docker-node-add --register address="http://${node}" pool=$pool 2>/dev/null || true
        amount=$((amount+1))
    done
    set +e
    status=1
    while [ $status != 0 ]; do
        tsuru-admin docker-node-list | grep "| http://" | wc -l | grep -q "${amount}$"
        status=$?
    done
    set -e
}

function install_platform {
    echo "Installing platform container..."
    local has_plat=$((tsuru platform-list | grep "${1}"$) || true)
    local dockerfile="https://raw.githubusercontent.com/tsuru/basebuilder/master/$1/Dockerfile"
    if [[ $has_plat == "" ]]; then
        tsuru-admin platform-add "$1" --dockerfile "$dockerfile"
    fi
    local platform_ok=$(docker run --rm "${host_ip}:5000/tsuru/$1" bash -c 'source /var/lib/tsuru/config && ${VENV_DIR}/bin/circusd --daemon /etc/circus/circus.ini && sleep 2 && ps aux | grep circusd | grep -v grep')
    if [[ $platform_ok == "" ]]; then
        # Circusd bugged version, rebuilding platform
        tsuru-admin platform-update "$1" --dockerfile "$dockerfile"
    fi
    local platform_ok=$(docker run --rm "${host_ip}:5000/tsuru/$1" bash -c 'source /var/lib/tsuru/config && ${VENV_DIR}/bin/circusd --daemon /etc/circus/circus.ini && sleep 2 && ps aux | grep circusd | grep -v grep')
    if [[ $platform_ok == "" ]]; then
        echo "Error trying to start circus inside $1 docker image. Please report this as a bug in https://github.com/tsuru/now/issues"
        echo "Additional information:"
        uname -a
        docker version
        echo "Tsuru hash: "
        git --git-dir ~/go/src/github.com/tsuru/tsuru/.git log | head -n1
        exit 1
    fi
}

function install_dashboard {
    echo "Installing tsuru-dashboard..."
    tsuru app-create tsuru-dashboard python -o theonepool || tsuru app-create tsuru-dashboard python || true
    pushd ~/
    if [[ ! -e ~/tsuru-dashboard/app.yaml ]]; then
        git clone https://github.com/tsuru/tsuru-dashboard
    fi
    pushd tsuru-dashboard
    git reset --hard
    git clean -dfx
    git pull
    git remote add tsuru "git@${host_name}:tsuru-dashboard.git" || true
    git push tsuru master
    popd
    popd
}

function install_tsuru_pkg {
    echo "Installing Tsuru from deb package..."
    sudo apt-get install tsuru-server tsuru-admin tsuru-client -y

    sudo service tsuru-server-api stop >/dev/null 2>&1 || true
    config_tsuru_pre
    sudo service tsuru-server-api start

    sleep 5
}

function install_tsuru_client {
    echo "Installing Tsuru admin & client from deb package..."
    sudo apt-get install tsuru-admin tsuru-client -qqy
}

function install_tsuru_src {
    echo "Installing Tsuru from source (this could take some minutes)..."
    if [[ -e ${GOPATH}/src/github.com/tsuru/tsuru ]]; then
        pushd "${GOPATH}/src/github.com/tsuru/tsuru"
        git reset --hard && git clean -dfx && git pull
        godep restore
        popd
    else
        mkdir -p "${GOPATH}/src/github.com/tsuru/tsuru"
        pushd "${GOPATH}/src/github.com/tsuru/tsuru"
        git clone https://github.com/tsuru/tsuru .
        godep restore
        popd
    fi
    go get github.com/tsuru/tsuru/cmd/tsr
    go get -d github.com/tsuru/tsuru-admin
    go get github.com/tsuru/tsuru-client/tsuru
    sed "s/0\.4\.3/0.5.0/g" -i $(echo "${GOPATH}" | awk -F ':' '{print $1}')/src/github.com/tsuru/tsuru-admin/main.go
    go install github.com/tsuru/tsuru-admin
    sed "s/0\.5\.0/0.4.3/g" -i $(echo "${GOPATH}" | awk -F ':' '{print $1}')/src/github.com/tsuru/tsuru-admin/main.go
    sudo cp $(echo "${GOPATH}" | awk -F ':' '{print $1}')/bin/{tsr,tsuru-admin,tsuru} /usr/local/bin

    screen -X -S api quit || true
    screen -S api -d -m tsr api --config=/etc/tsuru/tsuru.conf

    local tsraddr=$(running_addr tsr)
    if [[ $tsraddr == "" ]]; then
        echo "Error: Couldn't find tsr api addr, please check /var/log/syslog for more information"
        exit 1
    fi
    echo "tsr api found running at $tsraddr"
}

function install_archive_server_pkg {
    sudo apt-get install archive-server -y

    sudo service archive-server stop || true

    local archive_server_read=$(bash -ic 'source ~git/.bash_profile && echo $ARCHIVE_SERVER_READ')
    if [[ $archive_server_read != "http://${host_ip}:6161" ]]; then
        echo "Adding archive server environment to ~git/.bash_profile"
        echo "export ARCHIVE_SERVER_READ=http://${host_ip}:6060" | sudo tee -a ~git/.bash_profile > /dev/null
        echo "export ARCHIVE_SERVER_WRITE=http://127.0.0.1:6161" | sudo tee -a ~git/.bash_profile > /dev/null
    fi

    echo 'export ARCHIVE_SERVER_OPTS="-dir=/var/lib/archive-server/archives -read-http=0.0.0.0:6060 -write-http=127.0.0.1:6161"' | sudo tee -a /etc/default/archive-server > /dev/null 2>&1
    sudo service archive-server start
}

function install_swift {
    sudo apt-get install python-pip python-dev libxml2-dev libxslt-dev libz-dev -y
    sudo pip install python-swiftclient python-keystoneclient
}

function install_s3cmd {
    sudo apt-get install s3cmd python-magic -y
    cat > /tmp/s3cfg <<END
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
    sudo mv /tmp/s3cfg ~git/.s3cfg
}

function config_git_key {
    local tsuru_token=$(bash -ic 'source ~git/.bash_profile && echo $TSURU_TOKEN')
    if [[ $tsuru_token == "" ]]; then
        echo "Adding tsr token to ~git/.bash_profile"
        local token=$(tsr token)
        echo "export TSURU_TOKEN=$token" | sudo tee -a ~git/.bash_profile > /dev/null
    fi
    local tsuru_host=$(bash -ic 'source ~git/.bash_profile && echo $TSURU_HOST')
    if [[ $tsuru_host != "$host_name:8080" ]]; then
        echo "Adding tsr host to ~git/.bash_profile"
        echo "export TSURU_HOST=$host_name:8080" | sudo tee -a ~git/.bash_profile > /dev/null
    fi
    sudo chown -R git:git ~git/.bash_profile
}

function add_git_envs {
    if [[ "${#git_envs[@]}" -gt 1 ]]; then
        echo "Serializing provided env vars to ~git/.bash_profile"
        echo export ${git_envs[@]:1} | sudo tee -a ~git/.bash_profile > /dev/null
    fi
}

function install_all {
    check_support
    install_basic_deps ${tsuru_ppa_source-"nightly"}
    set_host
    install_docker
    install_docker_registry
    install_mongo
    if [[ ${tsuru_ppa_source-"nightly"} == "nightly" ]]; then
        install_vulcand
    else
        install_hipache
    fi
    install_gandalf
    if [[ ${install_tsuru_source-} == "1" ]]; then
        config_tsuru_pre
        install_go
        install_tsuru_src
    else
        install_tsuru_pkg
    fi
    if [[ ${install_archive_server} == "1" ]]; then
        install_archive_server_pkg
    fi
    install_swift
    if [[ ${aws_access_key} != "" && ${aws_secret_key} != "" ]]; then
        install_s3cmd
    fi
    config_tsuru_post
    config_git_key
    add_git_envs
    create_initial_user
    enable_initial_user
    add_as_docker_node
    install_platform python
    if [[ ${without_dashboard-} != "1" ]]; then
        install_dashboard
    fi

    echo '######################## DONE! ########################'
    echo
    echo "Some information about your tsuru installation:"
    echo
    echo "Admin user: ${adminuser}"
    echo "Admin password: ${adminpassword} (PLEASE CHANGE RUNNING: tsuru change-password)"
    echo "Target address: $host_ip:8080"
    if [[ ${without_dashboard-} != "1" ]]; then
        local cont_id=$(docker ps | grep tsuru-dashboard | cut -d ' ' -f 1)
        local dashboard_port=$(docker inspect $cont_id | grep HostPort  | head -n1 | sed "s/[^0-9]//g")
        echo "Dashboard address: $host_ip:$dashboard_port"
        echo
        echo "You should run \`source ~/.bashrc\` on your current terminal."
        echo
        echo "Installed apps:"
        sleep 1
        tsuru app-list
    fi
}

function install_server {
    check_support
    install_basic_deps ${tsuru_ppa_source-"nightly"}
    set_host
    install_docker
    install_docker_registry
    install_mongo
    if [[ ${tsuru_ppa_source-"nightly"} == "nightly" ]]; then
        install_vulcand
    else
        install_hipache
    fi
    install_gandalf
    install_tsuru_pkg
    if [[ ${install_archive_server} == "1" ]]; then
        install_archive_server_pkg
    fi
    install_swift
    if [[ ${aws_access_key} != "" && ${aws_secret_key} != "" ]]; then
        install_s3cmd
    fi
    config_tsuru_post
    config_git_key
    add_git_envs
    create_initial_user
    enable_initial_user
    add_as_docker_node
    install_platform python

    echo '######################## DONE! ########################'
    echo
    echo "Some information about your tsuru installation:"
    echo
    echo "Admin user: ${adminuser}"
    echo "Admin password: ${adminpassword} (PLEASE CHANGE RUNNING: tsuru change-password)"
    echo "Target address: $host_ip:8080"
}

function install_client {
    check_support
    install_basic_deps ${tsuru_ppa_source-"nightly"}
    set_host
    install_tsuru_client
    install_swift
    if [[ ${aws_access_key} != "" && ${aws_secret_key} != "" ]]; then
        install_s3cmd
    fi
    config_tsuru_post
    enable_initial_user
    if [[ ${without_dashboard-} != "1" ]]; then
        install_dashboard
    fi

    echo '######################## DONE! ########################'
    echo
    echo "Some information about your tsuru installation:"
    echo
    echo "Admin user: ${adminuser}"
    echo "Admin password: ${adminpassword} (PLEASE CHANGE RUNNING: tsuru change-password)"
    echo "Target address: $host_ip:8080"
    if [[ ${without_dashboard-} != "1" ]]; then
        local cont_id=$(docker ps | grep tsuru-dashboard | cut -d ' ' -f 1)
        local dashboard_port=$(docker inspect $cont_id | grep HostPort  | head -n1 | sed "s/[^0-9]//g")
        echo "Dashboard address: $host_ip:$dashboard_port"
        echo
        echo "You should run \`source ~/.bashrc\` on your current terminal."
        echo
        echo "Installed apps:"
        sleep 1
        tsuru app-list
    fi
}

function install_dockerfarm {
    check_support
    install_basic_deps ${tsuru_ppa_source-"nightly"}
    set_host
    dockerhost=$(public_ip)
    install_docker
    install_tsuru_client
    config_tsuru_post
    enable_initial_user
    add_as_docker_node
}

function install_exportvars {
    declare -p
}

function show_help {
    PROGRAM_NAME=$(basename $0)
    echo -e "Usage: $PROGRAM_NAME [options]

Options:

 -n, --host-name [name]         Set the VM's hostname
 -i, --host-ip [name]           Set the VM's IP
 -c, --tsuru-from-source        Install tsuru from master source code (default: nightly packages)
 -p, --tsuru-pkg-stable         Install tsuru from stable packages   (default: nightly packages)
 -N, --tsuru-pkg-nightly        Install tsuru from nightly build packages
 -f, --force-install [pkg]      Force installation of named package
 -g, --gopath [path]            prepend new path to env var GOPATH
 -a, --archive-server           Install the archive server
 -u, --hook-url [url]           Git hook URL
 -o, --hook-name [name]         Git hook name
 -e, --env [key] [value]        Set environment variable for git user in the VM
 -k, --aws-access-key [key]     Set the AWS access key
 -s, --aws-secret-key [key]     Set the AWS secret key
 -r, --ext-repository [repo]    Set the external repository URL produced by tsuru/tsuru-deb
 -d, --docker-only              Only install docker          (default: docker, dashboard)
 -w, --without-dashboard        Install without dashboard    (default: with dashboard)
 -I, --set-interface            The IP provided by --host-ip is not really allocated to this VM,
                                use ifconfig to set up an interface so it can be reached
 -D, --docker-node [node1] [node2] ...
                                Add extra docker nodes to tsuru server for building clusters
 -t, --template [name]          Install template, name options:
                                - all: install all packages (default)
                                - dockerfarm: install docker only
                                - server: install mongo, hipache, gandalf, archiver, tsuru-server
                                  and their dependencies
                                - client: install tsuru-admin, tsuru-client and their dependencies
 -v, --verbose                  Print debug messages
 -P, --docker-pool [name]       Add docker to distination pool of tsuru (default: theonepool)

 -h, --help                     This help screen
"
}

while [ "${1-}" != "" ]; do
    case $1 in
        "-v" | "--verbose")
            set -x
            is_debug=1
            ;;
        "-P" | "--docker-pool")
            shift
            pool=$1
            ;;
        "-I" | "--set-interface")
            set_interface="y"
            ;;
        "-D" | "--docker-node")
            while [ "${2-}" != "" ]; do
                shift
                [[ ${1:0:1} != "-" ]] || break
                docker_node="$docker_node $1"
            done
            ;;
        "-t" | "--template")
            shift
            install_func=install_$1
            ;;
        "-n" | "--host-name")
            shift
            host_name=$1
            ;;
        "-i" | "--host-ip")
            shift
            host_ip=$1
            ;;
        "-c" | "--tsuru-from-source")
            install_tsuru_source=1
            ;;
        "-p" | "--tsuru-pkg-stable")
            tsuru_ppa_source="stable"
            install_tsuru_pkg=1
            ;;
        "-N" | "--tsuru-pkg-nightly")
            tsuru_ppa_source="nightly"
            install_tsuru_pkg=1
            ;;
        "-f" | "--force-install")
            shift
            declare "force_install_$1=1"
            ;;
        "-g" | "--gopath")
            shift
            mkdir -p $1
            if [[ -v GOPATH ]]; then
                export GOPATH=$1:$GOPATH
            else
                export GOPATH=$1
            fi
            ;;
        "-a" | "--archive-server")
            install_archive_server=1
            ;;
        "-u" | "--hook-url")
            shift
            hook_url=$1
            ;;
        "-o" | "--hook-name")
            shift
            hook_name=$1
            ;;
        "-e" | "--env")
            shift
            git_envs=("${git_envs[@]}" "$1=\"$2\"")
            shift
            ;;
        "-k" | "--aws-access-key")
            shift
            aws_access_key=$1
            ;;
        "-s" | "--aws-secret-key")
            shift
            aws_secret_key=$1
            ;;
        "-r" | "--ext-repository")
            shift
            ext_repository=$1
            ;;
        "-d" | "--docker-only")
            install_func=install_dockerfarm
            ;;
        "-w" | "--without-dashboard")
            without_dashboard=1
            ;;
        * | "-h" | "--help")
            show_help
            exit
            ;;

    esac
    shift
done

$install_func
