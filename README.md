# suriflaska
Snort / Suricata rule testing for poor people.

This is a python script that runs a local flask server. The flask server can be used to test out new Snort / Suricata rules. It does this by using an edited suricata configuration which writes its output to a file locally and reads its contents after testing the rule.

The flask server runs the suricata offline replay functionality by executing the following command on the system:

suricata -c suricata.yaml --runmode autofp -S rules_file.rules -r testPCAP.pcap

To get the above to work the server takes a PCAP file and tests if the rules defined in 'rules_file.rules' match any data present in the packets of the PCAP. The output of suricata is written in 'fast.log' as is defined in 'suricata.yaml', a check will be made if this file contains any data, and if it does, display the 'Signature matches!' to the user.

## Running the server from the terminal
You can run the server straight from the terminal if you have installed the following requirements:
* Python 3
* Suricata

You will need the following Python modules:
* Flask
* Werkzeug


Execute the following command to run the server:
```sh
python3 server.py
```
The server will run on port 5000 of the machine. If you do not want this server to be accessible publicly you will need to change the 'host' value that is displayed on the bottom of the server.py file.

## Running the server using Docker
You can also run the server in a docker by navigating to the 'suriflaska_docker' directory and executing:
```sh
docker build -t suriflaska_complete .
```

And running the docker image with the following command, forwarding port 5000:
```sh
docker run -p 5000:5000 suriflaska
```

## NOTE
Do NOT use this in a production environment as I'm fairly certain this is a very insecure flask server!
