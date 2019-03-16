from flask import Flask, render_template, url_for, abort, request, g, flash, redirect, session, Blueprint
import json, hashlib, paramiko, bcrypt, binascii

site = Blueprint('site', __name__)

#paramiko.util.log_to_file("demo_server.log")
site.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

###################################################################
#
#                           Connect to pi cluster
#
###################################################################

def isConnected():

    if (ssh.get_transport().is_authenticated() == True):
        return 'Connected'
    else:
        return 'Not Connected'

def getSettings():

    with open('static/json/config.json') as data_file:
     settings = json.load(data_file)
     data_file.close()
     return settings

def getCommmands():

    with open('static/json/commands.json') as data_file:
     commands = json.load(data_file)
     data_file.close()
     return commands

def toNTLM(passwordInput):

    toHash = passwordInput
    ntlm_hash = binascii.hexlify(hashlib.new('md4', toHash.encode('utf-16le')).digest())
    return ntlm_hash

def toMD5(passwordInput):

    toHash = passwordInput
    md5_hash = hashlib.md5(toHash.encode('utf-8')).hexdigest()
    return md5_hash


@site.route('/settings', methods=['POST','GET'])
def connectionSettings():

    data = getSettings()


    if request.method == 'POST':

        print request.form


        #ip = request.form['ip']
        data['config'][0]['ip'] = request.form['ip']
        data['config'][0]['port'] = request.form['port']
        data['config'][0]['username'] = request.form['username']
        data['config'][0]['ip'] = request.form['ip']
        #port = request.form['port']
        #username = request.form['username']
        #password = request.form['password']
        #entry = {'ip': ip, 'port': port, 'username':username}

        #data['config'].append(entry)

        with open('static/json/config.json', 'w') as new_file:
          json.dump(data, new_file, indent=4, sort_keys=True)

        return redirect(url_for('connect'))

        #with open('static/json/config.json', 'w') as new_file:
         # json.dump(data, new_file, indent=4, sort_keys=True)
    else:
        for settings in data['config']:
            ip = settings['ip']
            port = settings['port']
            username = settings['username']
            password = settings['password']


            return render_template('settings.html', ip=ip, port=port, username=username), 200


@site.route('/advanced', methods=['POST','GET'])
def advancedOptions():
    return 'advanced'



@site.route('/')
def index():

    #return render_template('main.html')
    return redirect(url_for('connect'))

@site.route('/connect', methods=['POST','GET'])
def connect():
    if request.method == 'POST':

        print request.form
        with open('static/json/config.json') as data_file:
         data = json.load(data_file)
         #data.close()


        password = request.form['password']
        #password = bcrypt.hashpw((request.form['password']).encode('utf-8'), bcrypt.gensalt())
        #data['config'][0]['password'] = password
        #entry = {'password': password}
        #data['config'].append(entry)

        hashedPass = data['config'][0]['password']
        #return hashedPass
        if hashedPass == bcrypt.hashpw(password.encode('utf-8'), hashedPass.encode('utf-8')):
            return redirect(url_for('sendHash'))
        else:
            flash('Incorrect Password Entered!')
            return render_template('connect.html'), 200

        #with open('static/json/config.json', 'w') as new_file:
         # json.dump(data, new_file, indent=4, sort_keys=True)
    else:
     return render_template('connect.html'), 200




@site.route('/ssh',)
def ssh_test():


        ip='192.168.1.81'
        port=22
        username='root'
        password='white43flame'

        cmd = 'john --show --format=raw-md5 /usr/share/wordlists/rockyou.txt /root/Desktop/passw'

        ssh=paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip,port,username,password)

        stdin,stdout,stderr=ssh.exec_command(cmd)
        outlines=stdout.readlines()
        resp=''.join(outlines)
        return resp

        #stdin,stdout,stderr=ssh.exec_command('some really useful command')
        #outlines=stdout.readlines()
        #resp=''.join(outlines)
        #print(resp)

@site.route('/home', methods=['POST','GET'])
def home():
    if request.method == 'POST':

        print request.form
        with open('static/json/config.json') as data_file:
         data = json.load(data_file)
         #data.close()


        password = request.form['password']
        #password = bcrypt.hashpw((request.form['password']).encode('utf-8'), bcrypt.gensalt())
        #data['config'][0]['password'] = password
        #entry = {'password': password}
        #data['config'].append(entry)

        hashedPass = data['config'][0]['password']
        #return hashedPass
        if hashedPass == bcrypt.hashpw(password.encode('utf-8'), hashedPass.encode('utf-8')):
            return redirect(url_for('sendHash'))
        else:
            flash('Incorrect Password Entered!')
            return render_template('paratest.html'), 200

        #with open('static/json/config.json', 'w') as new_file:
         # json.dump(data, new_file, indent=4, sort_keys=True)
    else:
     return render_template('paratest.html'), 200





@site.route('/sendhash', methods=['POST','GET'])
def sendHash():
    if request.method == 'POST':

        print request.form
        userHash = request.form['hash']
        return redirect(url_for('build_command',userHash=userHash))
    else:
     return render_template('main.html'), 200

@site.route('/test')
def testmod():

    data = getSettings()

    for settings in data['config']:
        ip = str(settings['ip'])
        port = str(settings['port'])
        username = str(settings['username'])
        password = str(settings['password'])



    cmd = 'ls'#command'john --show --format=raw-md5 /usr/share/wordlists/rockyou.txt /root/Desktop/passw'

    ssh=paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip,port,username,password)

    stdin,stdout,stderr=ssh.exec_command(cmd)
    outlines=stdout.readlines()
    resp=''.join(outlines)
    return resp


###################################################################
#
#                           ERRORS
#
###################################################################
@site.errorhandler(404)
def page_not_found(error):
  return render_template('errors/404.html'), 404

@site.errorhandler(500)
def internal_server_error(error):
  return render_template('errors/500.html'), 500


if __name__ == "__main__":

    app.run(host='0.0.0.0', debug=True)
