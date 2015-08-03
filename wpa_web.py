#!/usr/bin/env python2

import os, sys, stat, psutil, subprocess, time, wpactrl, string
from twisted.web import server, resource
from twisted.internet import reactor, endpoints
from jinja2 import Environment, PackageLoader

# Set up template system
env = Environment(loader=PackageLoader('wpa_web', 'views'))

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
    while True:
        if wpa_event.recv() and wpa_event.pending() == False:
            networks = parse_wpa_list(wpa.scanresults())
            # Sort by signal level
            networks = sorted(networks, key=lambda network: network['level'])
            break
        time.sleep(0.5)

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
    while True:
        if get_status() == 'COMPLETED':
            dhcp_request()
            break
        time.sleep(0.5)

# Disconnect from anything existing
def disconnect():
    global wpa, dhclient
    if dhclient:
        dhclient.terminate()
    wpa.request('DISCONNECT')
    while True:
        if wpa_event.recv() and wpa_event.pending() == False:
            break
        time.sleep(0.5)

# Fire up dhclient and send a client request
def dhcp_request():
    global socket_name, dhclient
    DEVNULL = open(os.devnull, 'wb')
    dhclient = subprocess.Popen(['dhclient', '-d', '-1', socket_name], stdout=DEVNULL, stderr=DEVNULL)

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
        global socket_name, socket, wpa, networks
        template = env.get_template('control.html')
        status = parse_wpa(wpa.request('STATUS-VERBOSE'))
        if status['wpa_state'] == 'COMPLETED':
            state = 'Connected'
        elif status['wpa_state'] == 'SCANNING':
            state = 'Scanning'
        else:
            state = 'Disconnected'
        ssid = request.args['ssid'][0] if 'ssid' in request.args else ''
        return template.render(sockets=sockets, socket_name=socket_name, status=status, state=state, networks=networks, ssid=ssid).encode('utf-8')

    def render_POST(self, request):
        global wpa, wpa_event
        if request.args['method'][0] == 'setsocket':
            set_socket(request.args['socket'][0])
        elif request.args['method'][0] == 'scan':
            scan()
        elif request.args['method'][0] == 'connect':
            connect(request.args['ssid'][0], request.args['passphrase'][0])
        elif request.args['method'][0] == 'disconnect':
            disconnect()

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
    global sockets, networks, dhclient
    sockets = {}
    networks = []
    dhclient = False
    port = 80

    print 'wpa_cli 1.0.0 (Copyright 2015 Tom Pitcher)'

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

    # Check for keyboard interrupts
    try:
        while True:
            reactor.iterate()
            time.sleep(0.001)
    except KeyboardInterrupt:
        # Detach the wpa_ctrl event handler
        wpa_event.detach()
        # Output a newline
        print ''
        # Exit without error status
        sys.exit(0)

if __name__=="__main__":
    main()
