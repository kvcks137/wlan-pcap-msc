#!/usr/bin/python

import sys
import subprocess
import re

def usage():
  print >>sys.stderr, '%s: <.pcap> [tshark additional options] "wireshark display filter"' % sys.argv[0]
  sys.exit(1)

def usage1():
  print >>sys.stderr, '%s: <.pcap> [tshark additional options] "wireshark display filter: assuming "wlan""' % sys.argv[0]


n = len(sys.argv)
if n < 2:
  usage()

if n < 3:
  usage1()

capture = sys.argv[1]
dfilter = sys.argv[-1]
# -Tfields -ewlan.fc.type -ewlan.fc.type_subtype -ewlan.addr -ewlan.ra

#print >>sys.stderr, '%s ' % sys.argv[0]
#print >>sys.stderr, '%s ' % sys.argv[1]
tshark_cmd = [ 'tshark']
tshark_cmd.append('-r')
tshark_cmd.append(sys.argv[1])
if n < 3:
  tshark_cmd.append('wlan')
else:
  tshark_cmd.append(sys.argv[2])

#tshark_cmd.append('-o')
#tshark_cmd.append('column.format:"Info","%i"')

tshark_cmd.append('-Tfields')
tshark_cmd.append('-ewlan.fc.type')
tshark_cmd.append('-ewlan.fc.type_subtype')
tshark_cmd.append('-ewlan.addr')
tshark_cmd.append('-ewlan.ra')
print >>sys.stderr, '%s' % tshark_cmd
# start tshark subprocess and prepare a pipe to which it will write stdout
shark = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE)
sharkout = shark.stdout

frame_names = {
'0x00': 'mgmt-Association request', '0x01': 'mgmt-Association response', 
'0x02': 'mgmt-Reassociation request', '0x03': 'mgmt-Reassociation response', 
'0x04': 'mgmt-Probe request', '0x05': 'mgmt-Probe response', 
'0x07': 'mgmt-Timing Advertisement', '0x07': 'mgmt-Reserved', 
'0x08': 'mgmt-Beacon', '0x09': 'mgmt-ATIM', '0x0a': 'mgmt-Disassociation', 
'0x0b': 'mgmt-Authentication', '0x0c': 'mgmt-Deauthentication', 
'0x0d': 'mgmt-Action', '0x0e': 'mgmt-Action No Ack', '0x0f': 'mgmt-Reserved',         
'0x17': 'ctrl-Control Wrapper', '0x18': 'ctrl-BlockAckReq', '0x19': 'ctrl-BlockAck', 
'0x1a': 'ctrl-PS-Poll', '0x1b': 'ctrl-RTS', '0x1c': 'ctrl-CTS', '0x1d': 'ctrl-ACK', 
'0x1e': 'ctrl-CF-End', '0x1f': 'ctrl-CF-End + CF-Ack',     
'0x20': 'Data', '0x21': 'Data + CF-Ack', '0x22': 'Data + CF-Poll', 
'0x23': 'Data + CF-Ack + CF-Poll', '0x24': 'Null (no data)', '0x25': 'CF-Ack (no data)', 
'0x26': 'CF-Poll (no data)', '0x27': 'CF-Ack + CF-Poll (no data)', 
'0x28': 'QoS Data', '0x29': 'QoS Data + CF-Ack', '0x2a': 'QoS Data + CF-Poll', 
'0x2b': 'QoS Data + CF-Ack + CF-Poll', '0x2c': 'QoS Null (no data)', '0x2d': 'Data-Reserved', 
'0x2e': 'QoS CF-Poll (no data)', '0x2f': 'QoS CF-Ack + CF-Poll (no data)'}
 

# list of messages displayed by tshark
messages = []

while True:
  line = sharkout.readline()
  # eof encountered
  if len(line) == 0:
    break
#0	0x08	ff:ff:ff:ff:ff:ff,00:0c:41:82:b2:55	
#1	0x1d		00:0c:41:82:b2:55

#  regex = re.compile('^ *(\d+) +(\d+\.\d+) +(\d+\.\d+\.\d+\.\d+) -> (\d+\.\d+\.\d+\.\d+) (.*?)$')
#  regex = re.compile('^(.+) +(.+) +(.+) -> (.+) +(.+) +(\d+) +(.*?)$')
#  regex2 = re.compile('^(.+) +(.+) +(.+) -> (.+) +(.+) +(\d+) +(.*?)$')
  regex = re.compile('^(.+)\t+(.+)\t+(.+),(.+)\t$')
  regex2 = re.compile('^(.+)\t+(.+)\t\t+(.+)$')

  ret = regex.match(line)
  if ret != None:
    msg = {}
    msg['sub_type'] = ret.group(2)
    msg['msg'] = frame_names[msg['sub_type']]    
    msg['dst'] = ret.group(3)
    msg['src'] = ret.group(4)
    messages.append(msg)
#    print >>sys.stderr, "%s" % msg
  else:
    ret = regex2.match(line)
    if ret != None:
      msg = {}
      msg['sub_type'] = ret.group(2)
      msg['msg'] = frame_names[msg['sub_type']]    
      msg['dst'] = ret.group(3)
      msg['src'] = 'ff:ff:ff:ff:ff:ff'
      messages.append(msg)
#      print >>sys.stderr, "%s" % msg
    else:
      print >>sys.stderr, "line '%s' not handled by regex !" % line
      continue

# synchronously wait for tshark termination
shark.wait()
if shark.returncode != 0:
  print >>sys.stderr, "tshark returned error code %d" % shark.returncode
  sys.exit(1)

# list of entity
# contains IP addresses used IP datagrams exchanged in this capture
entities = []
for msg in messages:
  if msg['src'] not in entities:
    entities.append(msg['src'])
  if msg['dst'] not in entities:
    entities.append(msg['dst'])

# print msc generated file on stdout
# declare participants
line = ''
for i in range(0, len(entities)):
  line = 'participant \"%s\" as u%d' % (entities[i],i)
  print("%s" % line)

# add messages
for msg in messages:
  src = entities.index(msg['src'])
  dst = entities.index(msg['dst'])
  print("u%d->u%d:\"%s\"" % (src, dst, msg['msg']))

