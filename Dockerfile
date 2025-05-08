##############################################################
# Dockerfile to build SRxCryptoAPI ExaBGPSRx container images 
# Based on CentOS 7
##############################################################
FROM centos:7
MAINTAINER "Kyehwan Lee".
ENV container docker


################## patch repo ######################
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo && \
    sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo && \
    sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo

# ========== Stage 1: Build and install SRxCryptoAPI ==========
RUN yum -y install epel-release && \
    yum -y install wget libconfig libconfig-devel openssl openssl-devel libcrypto.so.* telnet less gcc && \
    yum -y install uthash-devel net-snmp readline-devel patch git net-snmp-config net-snmp-devel automake rpm-build autoconf libtool && \
    yum -y install git python3

# clone source
WORKDIR /root
RUN git clone https://github.com/usnistgov/NIST-BGP-SRx.git


# KeyVolt directory
RUN mkdir -p /var/lib/bgpsec-keys/
VOLUME ["/var/lib/bgpsec-keys/"]


# build SRxCryptoAPI 
WORKDIR /root/NIST-BGP-SRx/srx-crypto-api
RUN autoreconf -i && \
    ./configure --prefix=/ CFLAGS="-O0 -g" && \
    make all install 



# SRxCryptoAPI post scripts 
RUN   mv -f /root/NIST-BGP-SRx/srx-crypto-api/srxcryptoapi.conf /etc/srxcryptoapi.conf && \
	  touch /var/lib/bgpsec-keys/ski-list.txt && \
	  touch /var/lib/bgpsec-keys/priv-ski-list.txt && \
	  mv -f /root/NIST-BGP-SRx/srx-crypto-api/tools/qsrx-router-key.conf /etc/qsrx-router-key.cnf && \
	  cp -rf ./srxcryptoapi_lib64.conf /etc/ld.so.conf.d/ && \
	  rm -rf /etc/ld.so.cache && ldconfig



# ========== Stage 2: Install ExaBGPSRx ==========
WORKDIR /root
RUN git clone https://github.com/usnistgov/exabgpsrx.git exabgp
WORKDIR /root/exabgp

# Install pip & dependencies (optional, if pip install . needed)
# RUN wget https://bootstrap.pypa.io/get-pip.py && python get-pip.py && pip install .


################## CONFIGURATION ##########################
EXPOSE 179
VOLUME ["/root/exabgp"]
ENV PATH /root/exabgp:/root/exabgp/sbin:$PATH

# Start ExaBGP with sample configuration
CMD env exabgp.daemon.user=root exabgp /etc/exabgp.conf

