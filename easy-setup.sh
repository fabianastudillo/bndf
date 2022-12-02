#!/bin/bash

# Copyright(C) 2021, Stamus Networks
# Written by Raphaël Brogat <rbrogat@stamus-networks.com> based on the work of Peter Manev <pmanev@stamus-networks.com>
#
# Please run on Debian
#
# This script comes with ABSOLUTELY NO WARRANTY!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

############################################################
# Help Function       #
############################################################
function Help(){
  # Display Help
  { echo
    echo "Botnet Detection setup script"
    echo
    #echo -e "\t Syntax: easy-setup.sh [-h|--help] [-d|--debug] [-i|--interfaces <eth0 eth1 eth2 ...>] [-n|--non-interactive] [--skip-checks] [--scirius-version <version>] [--elk-version <version>] [--es-datapath <path>]"
    #echo
    echo "OPTIONS"
    echo -e " -h, --help"
    echo -e "       Display this help menu\n"
    #echo -e " -i,--interface <interface>"
    #echo -e "       Defines an interface on which BNDF should listen."
    echo -e "       This options can be called multiple times. Ex : easy-setup.sh -i eth0 -i eth1"
    echo -e "       The interactive prompt regarding this option will be skipped\n"
    echo -e " -n,--non-interactive"
    echo -e "       Run the script without interacive prompt. This will activate the '--skip-checks' option. '--interfaces' option is required\n"
    echo -e " --skip-checks"
    echo -e "       Run the script without checking if docker and docker-compose are installed\n"
    echo -e " --elk-version <version>"
    echo -e "       Defines the version of the ELK stack to use. Default is '7.12.0'. The version should match a tag of Elasticsearch, Kibana and Logstash images on the dockerhub\n"
    echo -e " --es-datapath <path>"
    echo -e "       Defines the path where Elasticsearch will store it's data. The path must already exists and the current user must have write permissions. Default will be in a named docker volume ('/var/lib/docker')"
    echo -e "       The interactive prompt regarding this option will be skipped\n"
    echo -e " --print-options"
    echo -e "       Print how the command line options have been interpreted \n"
  } | fmt
}


# Parse command-line options

# Option strings
SHORT=hdi:n
#LONG=help,debug,interfaces:,non-interactive,skip-checks,scirius-version:,elk-version:,es-datapath:,print-options
LONG=help,debug,non-interactive,skip-checks,scirius-version:,elk-version:,es-datapath:,print-options

# read the options
OPTS=$(getopt -o $SHORT -l $LONG --name "$0" -- "$@")

if [ $? != 0 ] ; then echo "Failed to parse options...exiting." >&2 ; exit 1 ; fi

eval set -- "$OPTS"

# set initial values
INTERACTIVE="true"
DEBUG="false"
SKIP_CHECKS="false"
#INTERFACES=""
ELASTIC_DATAPATH=""
PRINT_PARAM="false"
# extract options and their arguments into variables.
while true ; do
  case "${1}" in
    -h | --help )
      Help
      exit
      ;;
    --print-options )
      PRINT_PARAM="true"
      shift
      ;;
#    -i | --interfaces )
#      INTERFACES="${INTERFACES} $2"
#      shift 2
#      ;;
    -n | --non-interactive )
      INTERACTIVE="false"
      SKIP_CHECKS="true"
      shift
      ;;
    --skip-checks )
      SKIP_CHECKS="true"
      shift
      ;;
    --elk-version)
      ELK_VERSION="$2"
      shift 2
      ;;
    --es-datapath)
      ELASTIC_DATAPATH="$2"
      shift 2
      ;;
      
    -- )
      shift
      break
      ;;
    *)
      echo "Internal error!"
      exit 1
      ;;
  esac
done

#if [[ "${INTERACTIVE}" == "false" ]] && [[ "${INTERFACES}" == "" ]]; then
 # echo "ERROR: --non-interactive option must be use with --interface option"
 # exit
#fi

if [[ "${PRINT_PARAM}" == "true" ]]; then
  # Print the variables
  echo "DEBUG = ${DEBUG}"
 # echo "INTERFACES = ${INTERFACES}"
  echo "INTERACTIVE = ${INTERACTIVE}"
  echo "SKIP_CHECKS = ${SKIP_CHECKS}"
  echo "ELK_VERSION = ${ELK_VERSION}"
  echo "ELASTIC_DATAPATH = ${ELASTIC_DATAPATH}"
  if [[ "${INTERACTIVE}" == "true" ]] ; then
    read
  fi
fi


##########################
# Check Curl and Time         #
##########################
curl=$(curl -V)
if [[ -z "$curl" ]]; then
  echo -e "\n\n  Please install curl and re-run the script\n"
  exit
fi

time=$(time echo "" && echo "time is installed")
if [[ -z "$time" ]]; then
  echo -e "\n\n  Please install time and re-run the script\n"
  exit
else
  clear
fi


##########################
# Set the colors         #
##########################

red=`tput setaf 1``tput bold`
green=`tput setaf 2``tput bold`
reset=`tput sgr0`
BASEDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"


echo -e "DISCLAIMER : This script comes with absolutely no warranty. It provides a quick and easy way to install BNDF on your system\n
Altough this script should run properly on major linux distribution, it has only been tested on Debian 10 (buster)\n"

if [[ "${INTERACTIVE}" == "true" ]] ; then
  echo "Press any key to continue or ^c to exit"
  read
fi
echo -e "  This version of BNDF relies on docker containers. We will now check if docker is already installed"

echo -e "\n"
echo "##################"
echo "#  INSTALLATION  #"
echo "##################"
echo -e "\n"

#############################
#          DOCKER           #
#############################
function test_docker_user(){
  hello=$(docker run --rm hello-world) || \
  echo "${red}-${reset} Docker test failed"
  
  if [[ $hello == *"Hello from Docker"* ]]; then
    echo -e "${green}+${reset} Docker seems to be installed properly"
  else
    echo -e "${red}-${reset} Error running docker."
    exit
  fi
}
function install_docker(){
  curl -fsSL https://get.docker.com -o get-docker.sh && \
  sh get-docker.sh || \
  ( echo "${red}-${reset} Docker installation failed" && exit )
  echo "${green}+${reset} Docker installation succeeded"
  sudo systemctl enable docker && \
  sudo systemctl start docker
}
function adduser_to_docker(){
  sudo groupadd docker
  sudo usermod -aG docker $USER && \
  echo -e "${green}+${reset} Added user to docker group successfully \n  Please logout and login again for the group permissions to be applied, and re-run the script" || \
  ( echo "${red}-${reset} Error while adding user to docker group" && exit )
}
function install_docker_compose(){
  sudo curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && \
  sudo chmod +x /usr/local/bin/docker-compose && \
  echo "${green}+${reset} docker-compose installation succeeded" || \
  ( echo "${red}-${reset} docker-compose finstallation failed" && exit )
}
function Version(){
  # $1-a $2-op $3-$b
  # Compare a and b as version strings. Rules:
  # R1: a and b : dot-separated sequence of items. Items are numeric. The last item can optionally end with letters, i.e., 2.5 or 2.5a.
  # R2: Zeros are automatically inserted to compare the same number of items, i.e., 1.0 < 1.0.1 means 1.0.0 < 1.0.1 => yes.
  # R3: op can be '=' '==' '!=' '<' '<=' '>' '>=' (lexicographic).
  # R4: Unrestricted number of digits of any item, i.e., 3.0003 > 3.0000004.
  # R5: Unrestricted number of items.
  local a=$1 op=$2 b=$3 al=${1##*.} bl=${3##*.}
  while [[ $al =~ ^[[:digit:]] ]]; do al=${al:1}; done
  while [[ $bl =~ ^[[:digit:]] ]]; do bl=${bl:1}; done
  local ai=${a%$al} bi=${b%$bl}

  local ap=${ai//[[:digit:]]} bp=${bi//[[:digit:]]}
  ap=${ap//./.0} bp=${bp//./.0}

  local w=1 fmt=$a.$b x IFS=.
  for x in $fmt; do [ ${#x} -gt $w ] && w=${#x}; done
  fmt=${*//[^.]}; fmt=${fmt//./%${w}s}
  printf -v a $fmt $ai$bp; printf -v a "%s-%${w}s" $a $al
  printf -v b $fmt $bi$ap; printf -v b "%s-%${w}s" $b $bl

  case $op in
    '<='|'>=' ) [ "$a" ${op:0:1} "$b" ] || [ "$a" = "$b" ] ;;
    * )         [ "$a" $op "$b" ] ;;
  esac
}


if [[ "${SKIP_CHECKS}" == "false" ]] ; then
  dockerV=$(docker -v)
  if [[ $dockerV == *"Docker version"* ]]; then
    echo -e "${green}+${reset} Docker installation found: $dockerV"
  else
    echo -e "${red}-${reset} No docker installation found\n\n  We can try to install docker for you"
    read -p "  Do you want to install docker automatically? [y/N] " yn
    case $yn in
        [Yy]* ) install_docker;;
        * ) echo -e "  See https://docs.docker.com/engine/install to learn how to install docker on your system"; exit;;
    esac
  fi
  

  dockerV=$(docker version --format '{{.Server.Version}}')

  if [[ ! -z "$dockerV" ]]; then
    echo -e "${green}+${reset} Docker is available to the current user"
    test_docker_user
  else
    echo -e "${red}-${reset} Docker engine is not available to the current user.\n  Either allow current user to execute docker commands or run this script as privileged user.\n"
    read -p "  Do you want to allow '${USER}' to run docker commands? [y/N] " yn
    case $yn in
        [Yy]* ) adduser_to_docker; exit;;
        * ) echo -e "  See https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user to learn how to allow current standard user to run docker commands."; exit;;
    esac
  fi

  dockerV=$(docker version --format '{{.Server.Version}}')

  if Version $dockerV '<' 17.06.0; then
    echo -e "${red}-${reset} Docker version is too old, please upgrade it to 17.06.0 minimum"
    exit
  fi

  #############################
  #      DOCKER-COMPOSE       #
  #############################

  dockerV=$(docker-compose --version)

  if [[ $dockerV == *"docker-compose version"* ]]; then
    echo -e "${green}+${reset} docker-compose installation found"
  else
    echo -e "${red}-${reset} No docker-compose installation found, see https://docs.docker.com/compose/install/ to learn how to install docker-compose on your system"
    read -p "  Do you want to install docker-compose automatically? [y/N] " yn
    case $yn in
        [Yy]* ) install_docker_compose;;
        * ) echo -e "  See https://docs.docker.com/compose/install/ to learn how to install docker-compose on your system"; exit;;
    esac
  fi


  dockerV=( $dockerV )
  dockerV=$( echo ${dockerV[2]} |tr ',' ' ')
  if Version $dockerV '<' 1.27.0; then
    echo -e "${red}-${reset} Docker version is too old, please upgrade it to 1.27.0 minimum"
    exit
  fi
  
fi

echo -e "\n"
echo "##################"
echo "#    SETTINGS    #"
echo "##################"
echo -e "\n"


######################
# Setting Stack name #
######################
echo "COMPOSE_PROJECT_NAME=BNDF" > ${BASEDIR}/.env

##############
# DEBUG MODE #
##############


if [[ "${DEBUG}" == "true" ]]; then
  echo "y"
  yn="y"
else
  if [[ ${INTERACTIVE} == "true" ]]; then
    read -p "Do you want to use debug mode? [y/N] " yn
  else
    echo "n"
    yn="n"
  fi
fi

echo

######################
# ELASTIC DATA PATH #
######################

docker_root_dir=$(docker system info |grep "Docker Root Dir")
docker_root_dir=${docker_root_dir/'Docker Root Dir: '/''}

echo ""
echo -e "With BNDF running, database can take up a lot of disk space"
echo -e "You might want to save them on an other disk/partition"
echo -e "Docker partition free space : ${docker_root_dir} - $(df --output=avail -h ${docker_root_dir} | tail -n 1 )"
echo -e "Please give the path where you want the data to be saved, or hit enter to use a docker volume in the docker path :"

if [[ "${ELASTIC_DATAPATH}" == "" ]] && [[ "${INTERACTIVE}" == "true" ]]; then
  read elastic_data_path
else
  echo "${ELASTIC_DATAPATH}"
  elastic_data_path=${ELASTIC_DATAPATH}
fi

if ! [ -z "${elastic_data_path}" ]; then

  while ! [ -w "${elastic_data_path}" ]; do 
    echo -e "\nYou don't seem to own write access to this directory\n"
    echo -e "Please give the path where you want the data to be saved, or hit enter to use a docker volume in the docker path :"
    if [[ "${INTERACTIVE}" == "true" ]]; then
      read elastic_data_path
    else
      exit
    fi

  done
echo "ELASTIC_DATAPATH=${elastic_data_path}" >> ${BASEDIR}/.env
fi



######################
# Generate KEY FOR DJANGO #
######################

output=$(docker run --rm -it python:3.8.6-slim-buster /bin/bash -c "python -c \"import secrets; print(secrets.token_urlsafe())\"")



######################
# Setting ELK VERSION to use #
######################
if [ ! -z "${ELK_VERSION}" ] ; then
  echo "ELK_VERSION=$ELK_VERSION" >> ${BASEDIR}/.env
fi



echo -e "\n"
echo "#######################"
echo "# BUILDING CONTAINERS #"
echo "#######################"
echo -e "\n"
######################
# BUILDING           #
######################

echo -e "Pulling containers \n"

docker-compose pull || exit

echo -e "Building containers, this can take a while... (arround 10 minutes)\n"

now=$(date)
echo -e "BUILD : $now\n\n=========================" >> ${BASEDIR}/build.log
time docker-compose build >> ${BASEDIR}/build.log


######################
# Starting           #
######################
echo -e "\n\nTo start BNDF, run 'docker-compose up -d'"
[[ PORTAINER_INSTALLED=="true" ]] && echo "You have chose to install Portainer, visit https://localhost:9000 to set your portainer password, and select the docker option"
