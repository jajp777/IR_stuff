FROM ubuntu:latest 

MAINTAINER jbull

RUN apt-get update -q && apt-get -y install wget curl 

RUN wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
RUN echo "deb http://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list

RUN apt-get update -q
RUN sudo apt-get install elasticsearch
RUN apt-get -y install default-jre-headless

ENV KIBANA_VERSION 4.2.0 

RUN cd /tmp && \
    wget -nv https://download.elastic.co/kibana/kibana/kibana-4.2.0-linux-x64.tar.gz && \
    tar zxf kibana-${KIBANA_VERSION}-linux-x64.tar.gz && \
    rm -f kibana-${KIBANA_VERSION}-linux-x64.tar.gz && \
    mv /tmp/kibana-${KIBANA_VERSION}-linux-x64 /kibana

RUN echo 'network.host: 0.0.0.0' >> /etc/elasticsearch/elasticsearch.yml
ADD mapping.json /mapping.json
ADD start.sh /start.sh

#CMD service elasticsearch restart & sleep 10 & curl -XPUT http://127.0.0.1:9200/flurb -d @/mapping.json & /kibana/bin/kibana -q
CMD cd / && chmod +x start.sh; sync; ./start.sh

EXPOSE 9200 5601

