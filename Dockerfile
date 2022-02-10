FROM ubuntu:20.04
MAINTAINER qeeqbox
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y syslog-ng
ADD syslog-ng.conf /etc/syslog-ng/syslog-ng.conf
EXPOSE 514/udp
WORKDIR /var/log/syslog-ng/
ENTRYPOINT ["syslog-ng", "-F"]
