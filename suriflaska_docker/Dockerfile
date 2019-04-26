FROM ubuntu:16.04

# Install requirements for using add-apt
RUN apt-get update && apt-get install -y software-properties-common
RUN add-apt-repository ppa:oisf/suricata-stable
RUN apt-get update

# Install requirements for suricata
RUN apt-get install -y libpcre3-dbg libpcre3-dev autoconf automake libtool libpcap-dev libnet1-dev libyaml-dev zlib1g-dev libcap-ng-dev libmagic-dev libjansson-dev libjansson4

# Install suricata

RUN apt-get install -y suricata

# Install Python 3 if not installed already
RUN apt-get install -y python3-pip python3-dev build-essential

# Add the script and required folder
COPY . /suriflaska
WORKDIR /suriflaska

# Install the required Python modules
RUN pip3 install Flask
RUN pip3 install werkzeug

# Docker command to run the server
ENTRYPOINT ["python3"]
CMD ["server.py"]
