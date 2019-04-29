'''
Author: sud0woodo

DESCRIPTION:
    This is a python script that runs a local flask server. The flask server can be used to test out new Snort / Suricata
    rules. It does this by using an edited suricata configuration which writes its output to a file locally and reads its
    contents after testing the rule.

    The flask server runs the suricata offline replay functionality by executing the following command on the system:

    suricata -c suricata.yaml --runmode autofp -S rules_file.rules -r testPCAP.pcap

    To get the above to work the server takes a PCAP file and tests if the rules
    defined in 'rules_file.rules' match any data present in the packets of the PCAP. The output of suricata is written in 'fast.log'
    as is defined in 'suricata.yaml', this 'fast.log' output (by using the cat command) will be fed back to the flask server and shown
    to the user.

NOTE:
    Do NOT use this in a production environment as I'm fairly certain this is a very insecure flask server!
'''

from flask import Flask, flash, request, redirect, render_template, url_for
import os
import subprocess
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = 'uploads'
RULE_FOLDER = 'rules'
ALLOWED_EXTENSIONS = set(['pcap', 'pcapng'])

app = Flask('suriflaska')
app.secret_key = "ee7c13b30a220d785b9374baaef02cfad1b7bdc0"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Check if the file has the right extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function that executes the suricata command and returns the output of the logfile
def suri_replay(pcapfile):
    # Define the command to be executed
    replay_command = 'suricata -c suricata.yaml -k none --runmode autofp \
        -S rules/match.rules -r uploads/{0} -l log/ 2>log/error.log && cat log/fast.log'.format(pcapfile)

    # Execute the command
    try:
        result = subprocess.check_output([replay_command], shell=True)
    except subprocess.CalledProcessError:
        return "An error occured while trying to execute the command: {0}".format(replay_command)

    # Signature matches if the fast.log > 1
    if os.stat('log/fast.log').st_size != 0:
        return "Signature matches!"
    # Display the suricata error log if the size of the error log > 0
    elif os.stat('log/error.log').st_size != 0:
        error_log = []
        with open("log/error.log") as suricata_err:
            content = suricata_err.readlines()
        # Convert the newlines to work with HTML
        for line in content:
            error_log.append(line.replace('\n', '<br>'))
        return ' '.join(error_log)
    # If none of the above it means that the signature does not match the traffic that was replayed
    else:
        return "Signature doesn't match!"  

# Define the accepted methods and actions of the page 
@app.route('/', methods=['GET', 'POST'])
def rule_testing():
    # Show option to replay already uploaded pcaps
    uploaded_files = os.popen('ls uploads/')
    pcap_files = []
    for item in uploaded_files:
        if allowed_file(item.strip('\n')):
            pcap_files.append(item.strip('\n'))
    
    # Do something with POST request
    if request.method == 'POST':
        # Check if the POST request has the rule part
        if 'rule' in request.form:
            rule = request.form['rule']   
            # Put the new rule in the 'match.rules' file
            rule_file = open("rules/match.rules", "w")
            rule_file.write(rule)
            rule_file.close()
        # Return to template of page if it doesn't have the rule   
        else:
            return render_template('detect.html', rule=rule, listpcaps=pcap_files) 
        read_rule = open("rules/match.rules", "r")
        rule = ''.join(read_rule.readlines())

        # Check if the POST request contains one of the selected options
        if request.form.get('listpcaps'):
            file = request.form.get('listpcaps')
            replay = suri_replay(file)
            # Clean up the created files
            os.system('rm log/fast.log && rm log/error.log')
            return render_template('detect.html', rule=rule, output=replay, listpcaps=pcap_files)
        # Check if the POST request has the file part
        elif 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):                
                filename = secure_filename(file.filename)
                # Write the uploaded file to the right folder
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                # Execute the command that runs suricata
                replay = suri_replay(filename)
                # Clean up the created files
                if os.path.isfile('log/fast.log'):
                    os.system('rm log/fast.log')
                if os.path.isfile('log/error.log'):
                    os.system('rm log/error.log')
                return render_template('detect.html', rule=rule, output=replay, listpcaps=pcap_files)

    # Do something with GET request
    else:
        read_rule = open("rules/match.rules", "r")
        rule = ''.join(read_rule.readlines())
        return render_template('detect.html', rule=rule, listpcaps=pcap_files)         

if __name__ == '__main__':
    app.run()
