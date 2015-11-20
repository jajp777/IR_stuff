#get the base default ubuntu 14.04 image
FROM ubuntu:14.04

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update && apt-get -y upgrade 

#lots of dependencies, this could be slimmed probably as originally included stuff for bro 
RUN apt-get -y install cmake make gcc g++ flex bison libpcap-dev libgeoip-dev python-m2crypto
RUN apt-get -y install libssl-dev python-dev zlib1g-dev libmagic-dev swig python-pip
RUN apt-get -y install libgoogle-perftools-dev tcpdump stunnel wget openssh-server software-properties-common
RUN apt-get -y install gperf ruby perl libsqlite3-dev libfontconfig1-dev libicu-dev git
RUN apt-get -y install libfreetype6 libssl-dev libpng-dev libjpeg-dev python libx11-dev libxext-dev

#update and install additional python libraries
#need python 2.7.9+ as early versions don't support SNI and have shitty SSL support in general
RUN add-apt-repository -y ppa:fkrull/deadsnakes-python2.7
RUN add-apt-repository -y ppa:oisf/suricata-stable
RUN apt-get -y update && apt-get -y upgrade
RUN pip install selenium whois ipwhois elasticsearch

#install suricata
#RUN echo "deb http://ppa.launchpad.net/oisf/suricata-stable/ubuntu trusty main" >> /etc/apt/sources.list
#RUN echo "deb-src http://ppa.launchpad.net/oisf/suricata-stable/ubuntu trusty main" >> /etc/apt/sources.list
#RUN apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 9F6FC9DDB1324714B78062CBD7F87B2966EB736F
#RUN add-apt-repository -y ppa:oisf/suricata-stable
RUN apt-get -y install suricata whois

#install phantomjs
#we aren't compiling from source just yet....will take up to an hour to finish...
#RUN git clone git://github.com/ariya/phantomjs.git
#RUN cd phantomjs && git checkout 2.0 && yes | ./build.sh
RUN git clone https://github.com/Pyppe/phantomjs2.0-ubuntu14.04x64.git phantom_bin

#install dev stuff for now
RUN apt-get -y install vim screen
RUN pip install ipython tldextract

ADD suricata.yaml /etc/suricata/suricata.yaml
ADD eye.py /eye.py
#creating an empty file
RUN touch /var/log/suricata/eve.json

ENTRYPOINT ["python", "/eye.py"]

