#!/usr/bin/python

import sys
import subprocess
import urllib
import re

#START: local functions
def usage():
  print >>sys.stderr, '%s: <.pcap> [tshark additional options] "wireshark display filter"' % sys.argv[0]
  sys.exit(1)

def usage1():
  print >>sys.stderr, '%s: <.pcap> [tshark additional options] "wireshark display filter: assuming "wlan""' % sys.argv[0]

def getSequenceDiagram( text, outputFile, style = 'default' ):
    request = {}
    request["message"] = text
    request["style"] = style
    request["apiVersion"] = "1"

    url = urllib.urlencode(request)

    f = urllib.urlopen("http://www.websequencediagrams.com/", url)
    line = f.readline()
    f.close()

    expr = re.compile("(\?(img|pdf|png|svg)=[a-zA-Z0-9]+)")
    m = expr.search(line)

    if m == None:
        print "Invalid response from server."
        return False

    urllib.urlretrieve("http://www.websequencediagrams.com/" + m.group(0),
            outputFile )
    return True

#END: local functions

#START: Main code

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
# Information is extracted by executing tshark twice
# one instance of tshark prints the fields and another prints the info (both cannot be clubbed)

# tshark command to print the fields
tshark_cmd = [ 'tshark']
tshark_cmd.append('-r')
tshark_cmd.append(sys.argv[1])
if n < 3:
  tshark_cmd.append('wlan')
else:
  tshark_cmd.append(sys.argv[2])

# tshark command to print the decoded info
tshark_cmd_info = [ 'tshark']
tshark_cmd_info.append('-r')
tshark_cmd_info.append(sys.argv[1])
if n < 3:
  tshark_cmd_info.append('wlan')
else:
  tshark_cmd_info.append(sys.argv[2])

tshark_cmd.append('-Tfields')
tshark_cmd.append('-ewlan.fc.type')
tshark_cmd.append('-ewlan.fc.type_subtype')
tshark_cmd.append('-ewlan.addr')
tshark_cmd.append('-ewlan.ra')

tshark_cmd_info.append('-o')
tshark_cmd_info.append('column.format:"Info","%i","Protocol","%p"')
print >>sys.stderr, '%s' % tshark_cmd
print >>sys.stderr, '%s' % tshark_cmd_info

# start tshark subprocesses and prepare a pipe to which it will write stdout
shark = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE)
sharkout = shark.stdout

shark_info = subprocess.Popen(tshark_cmd_info, stdout=subprocess.PIPE)
sharkout_info = shark_info.stdout

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
  line_info = sharkout_info.readline()
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
  regex_info =re.compile('^(.+) +(.+)$')
  ret = regex.match(line)
  ret_info = regex_info.match(line_info)
  if ret != None:
    msg = {}
    msg['sub_type'] = ret.group(2)
    msg['msg'] = frame_names[msg['sub_type']]    
    msg['dst'] = ret.group(3)
    msg['src'] = ret.group(4)
    msg['info'] = ""
    if ret_info != None:
      if ret_info.group(2) != "802.11":
        msg['info'] = '%s(%s)' %(ret_info.group(2), ret_info.group(1))
      else:
        msg['info'] = '%s' %ret_info.group(1)
    if len(msg ['info']) > 46:
      msg['info'] = (msg['info'][:44]+'??')
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
      msg['info'] = ""
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

# list of entities
# contains MAC addresses
entities = []
for msg in messages:
  if msg['src'] not in entities:
    entities.append(msg['src'])
  if msg['dst'] not in entities:
    entities.append(msg['dst'])

# print msc generated file on stdout
# declare participants
line = ''
msc_text = ''
for i in range(0, len(entities)):
  line = 'participant \"%s\" as u%d' % (entities[i],i)
  msc_text += '%s\n' % line
  print("%s" % line)

# add messages
line = ''
for msg in messages:
  src = entities.index(msg['src'])
  dst = entities.index(msg['dst'])
  if msg['info'] == "":
    msg_text = '%s' % msg['msg']
  else:
    msg_text = '%s' % msg['info']
  line = 'u%d->u%d:\"%s\"' % (src, dst, msg_text)
#  print("u%d->u%d:\"%s\"" % (src, dst, msg_text))
  print("%s" % line)
  msc_text += '%s\n' % line

style = "qsd"
pngFile = "out.png"
getSequenceDiagram( msc_text, pngFile, style )
#End: Main code


