#!/usr/bin/env python2

# This file is part of wpa_web.
#
# wpa_web is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# wpa_web is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wpa_web.  If not, see <http://www.gnu.org/licenses/>.

import os, sys, signal, threading, stat, psutil, subprocess, time, wpactrl, string, json
from twisted.web import server, resource
from twisted.internet import reactor, endpoints
from jinja2 import Environment, FileSystemLoader

# Set up template system
cwd_template_dir = '{}/views'.format(os.path.dirname(os.path.realpath(__file__)))

if os.path.isdir(cwd_template_dir):
    env = Environment(loader=FileSystemLoader(cwd_template_dir))
else:
    env = Environment(loader=FileSystemLoader('/usr/lib/wpa_web/views'))

def error(request, message):
    request.setResponseCode(500)
    return env.get_template('500.html').render(message=message).encode('utf-8')

# Returns wpa_supplicant's state as a string
def get_status():
    global wpa
    status = parse_wpa(wpa.request('STATUS'))
    return status['wpa_state']

# Set the wpa_supplicant socket to use (one per interface)
def set_socket(new_socket):
    global socket_name, socket, sockets, wpa, wpa_event
    socket_name = new_socket
    socket = sockets[socket_name]
    wpa = wpactrl.WPACtrl(socket)
    wpa_event = wpactrl.WPACtrl(socket)
    wpa_event.attach()

# Run a scan and wait for the results before returning
def scan():
    global wpa, wpa_event, networks
    wpa.request('SCAN')
    while wpa_event.pending():
        wpa_event.recv()
        time.sleep(0.1)
    networks = parse_wpa_list(wpa.scanresults())
    # Sort by signal level
    networks = sorted(networks, key=lambda network: network['level'])

# Connect to an SSID with an optional passphrase
def connect(ssid, passphrase):
    global wpa, dhclient
    disconnect()
    time.sleep(1)
    id = find_network(ssid)
    # Add a new network if we haven't found one for this SSID
    if id == False:
        id = wpa.request('ADD_NETWORK').strip()
    wpa.request('SET_NETWORK {0} ssid "{1}"'.format(id, ssid))
    # If passphrase is provided, run it through the wpa_passphrase utility and set the network PSK
    if passphrase:
        passphrase_output = parse_wpa(subprocess.check_output(['wpa_passphrase', ssid, passphrase]))
        wpa.request('SET_NETWORK {0} psk {1}'.format(id, passphrase_output['psk']))
    wpa.request('SELECT_NETWORK {0}'.format(id))
    while wpa_event.pending():
        wpa_event.recv()
        time.sleep(0.1)
    timeout = time.time() + 20
    last_status = ''
    while True:
        if time.time() > timeout:
            return
        status = get_status()
        # These are two patterns that seem to occur with incorrect passwords
        if status == 'SCANNING' and last_status == '4WAY_HANDSHAKE':
            return False
        if status == 'DISCONNECTED' and last_status == 'AUTHENTICATING':
            return False
        if status == 'COMPLETED':
            dhcp_request()
            return True
        last_status = status
        time.sleep(1)

# Disconnect from anything existing
def disconnect():
    global wpa, wpa_event, dhclient, state, socket_name
    if dhclient:
        dhclient.terminate()
    wpa.request('DISCONNECT')
    while wpa_event.pending():
        wpa_event.recv()
        time.sleep(0.1)
    state = {}
    DEVNULL = open(os.devnull, 'wb')
    dhclient = subprocess.Popen(['/usr/bin/ip', 'addr', 'flush', 'dev', socket_name], stdout=DEVNULL, stderr=DEVNULL)

# Fire up dhclient and send a client request
def dhcp_request():
    global socket_name, dhclient
    client = '/usr/bin/dhclient'
    if not os.path.isfile(client) or not os.access(client, os.X_OK):
        return
    if 'ip_address' in parse_wpa(wpa.request('STATUS-VERBOSE')):
        return
    DEVNULL = open(os.devnull, 'wb')
    dhclient = subprocess.Popen(['/usr/bin/dhclient', '-d', '-1', socket_name], stdout=DEVNULL, stderr=DEVNULL)

# Parse the output of a wpa_ctrl command
def parse_wpa(output):
    lines = {}
    for line in string.split(output, '\n'):
        if line and not '' and ('=' in line):
            parts = string.split(line, '=')
            lines[parts[0].strip()] = parts[1].strip()
    return lines

# Parse the list output of a wpa_ctrl command
def parse_wpa_list(output):
    elements = []
    for element in output:
        lines = {}
        for line in string.split(element, '\n'):
            if line and not '':
                parts = string.split(line, '=')
                lines[parts[0]] = parts[1]
        elements.append(lines)
    return elements

# Parse the wpa_ctrl list_networks command
def parse_list_networks(output):
    lines = {}
    for line_number, line in enumerate(string.split(output, '\n')):
        if line_number == 0:
            continue
        if line and not '':
            parts = string.split(line, '\t')
            lines[parts[0].strip()] = parts[1].strip()
    return lines

# Find an existing wpa_ctrl network
def find_network(needle_ssid):
    global wpa
    networks = parse_list_networks(wpa.request('LIST_NETWORKS'))
    for id, ssid in networks.iteritems():
        if ssid == needle_ssid:
            return id
    return False

def store_state():
    global state_file, state
    file = open(state_file, 'w')
    json.dump(state, file)

def restore_state():
    global state_file, state
    if not os.path.isfile(state_file):
        return
    file = open(state_file, 'r')
    state = json.load(file)
    if 'ssid' in state:
        print('Restoring connection to {}'.format(state['ssid']))
        connect(state['ssid'], state['passphrase'])

def shutdown(signal, frame):
    global wpa_event
    print('Shutting down...')
    store_state()
    wpa_event.detach()
    sys.exit(0)

# Root controller
class Root(resource.Resource):
    def getChild(self, name, request):
        if name == '':
            return self
        if name == 'diagnostics':
            return Diagnostics()
        if not request.postpath:
            return Missing()
        return resource.Resource.getChild(self, name, request)

    def render_GET(self, request):
        global socket_name, socket, wpa, networks, error
        template = env.get_template('control.html')
        status = parse_wpa(wpa.request('STATUS-VERBOSE'))
        if status['wpa_state'] == 'COMPLETED':
            state_text = 'Connected'
        elif status['wpa_state'] == 'SCANNING':
            state_text = 'Scanning'
        else:
            state_text = 'Disconnected'
        ssid = request.args['ssid'][0] if 'ssid' in request.args else ''
        error_cache = error
        error = ''
        return template.render(sockets=sockets, socket_name=socket_name, status=status, state=state_text, networks=networks, ssid=ssid, error=error_cache).encode('utf-8')

    def render_POST(self, request):
        global wpa, wpa_event, state, error
        if request.args['method'][0] == 'setsocket':
            set_socket(request.args['socket'][0])
        elif request.args['method'][0] == 'scan':
            scan()
        elif request.args['method'][0] == 'connect':
            result = connect(request.args['ssid'][0], request.args['passphrase'][0])
            if result is True:
                state['ssid'] = request.args['ssid'][0]
                state['passphrase'] = request.args['passphrase'][0]
            elif result is False:
                error = 'Wrong password'
            else:
                error = 'Connection timed out'
        elif request.args['method'][0] == 'disconnect':
            disconnect()
        elif request.args['method'][0] == 'dhcp':
            dhcp_request()

        request.redirect('/')
        return ''

# 404 controller
class Missing(Root):
    def render_GET(self, request):
        request.setResponseCode(404)
        return env.get_template('404.html').render().encode('utf-8')

# Diagnostics controller
class Diagnostics(Root):
    def render_GET(self, request):
        template = env.get_template('diagnostics.html')
        status = parse_wpa(wpa.request('STATUS-VERBOSE'))
        return template.render(status=status).encode('utf-8')

# Main loop
def main():
    global sockets, networks, dhclient, state_file, state, error
    sockets = {}
    networks = []
    dhclient = False
    state = {}
    state_file = '/var/lib/wpa_web/state.json'
    error = ''
    port = 80

    print 'wpa_web 1.0.0 (Copyright 2015 Tom Pitcher)'

    signal.signal(signal.SIGINT, shutdown)

    site = server.Site(Root())
    reactor.listenTCP(port, site)
    reactor.startRunning(False)
    print 'Started web server on port %d' % port

    # Find running wpa_supplicant process
    wpa_supplicant_running = False
    for proc in psutil.process_iter():
        if proc.name() == 'wpa_supplicant':
            wpa_supplicant_running = True

    if not wpa_supplicant_running:
        sys.stderr.write('wpa_supplicant is not running. Use systemctl status to see if there is a startup error.\n')
        sys.exit(1)

    # Sanity checks for wpa_supplicant sockets
    run = '/var/run/wpa_supplicant'

    if os.path.isdir(run):
        try:
            for i in os.listdir(run):
                sockets[i] = os.path.join(run, i)
        except OSError, error:
            sys.stderr.write('Cannot read wpa_supplicant run directory at %s. Make sure this server script has permissions to read that directory.\n' % run)
            sys.exit(1)
    else:
        sys.stderr.write('wpa_supplicant run directory at %s does not exist. Check wpa_supplicant is running and that its configuration has a ctrl_interface directive.\n' % run)
        sys.exit(1)

    if not sockets:
        sys.stderr.write('Cannot find any wpa_supplicant sockets in %s. Check wpa_supplicant is running and that its configuration has a ctrl_interface directive.\n' % run)
        sys.exit(1)

    socket = sockets.iterkeys().next()

    # Use the first found socket as the default
    set_socket(socket)
    print 'Using socket %s' % socket

    restore_state()

    while True:
        reactor.iterate()
        time.sleep(0.001)

if __name__ == "__main__":
    main()
