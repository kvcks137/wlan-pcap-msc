#!/usr/bin/python

import sys
import subprocess
import urllib
import re
import os

#START: local functions
def usage():
  print >>sys.stderr, '%s: <.pcap> [tshark additional options] "wireshark display filter"' % sys.argv[0]
  sys.exit(1)

def usage1():
  print >>sys.stderr, '%s: <.pcap> [tshark additional options] "wireshark display filter: assuming "wlan""' % sys.argv[0]

# Connects to websequencediagrams.com and generates sequence diagram image from text. 
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
#end: getSequenceDiagram

#END: local functions

#START: Main code

#Validate the input parameters
debug= 0 # Set this to >1 to enable debug logs

n = len(sys.argv)
if n < 2:
  usage()

if n < 3:
  usage1()

capture = sys.argv[1]
dfilter = sys.argv[-1]

if debug > 0:
   print >>sys.stderr, 'sys.argv[0]: %s ' % sys.argv[0]
   print >>sys.stderr, 'sys.argv[1]: %s ' % sys.argv[1]

# Information is extracted by executing tshark twice
# one instance of tshark prints the fields and another prints the info (both cannot be clubbed)

# tshark command to print the fields
# 
# Run "tshark --help" at command line for more details

# -Tfields -ewlan.fc.type -ewlan.fc.type_subtype -ewlan.addr -ewlan.ra

tshark_cmd = [ 'tshark']
tshark_cmd.append('-r')
tshark_cmd.append(sys.argv[1])
if n < 3:
  tshark_cmd.append('wlan')
else:
  tshark_cmd.append(sys.argv[2])
tshark_cmd.append('-Tfields')
tshark_cmd.append('-eframe.number') #1
tshark_cmd.append('-ewlan.fc.type_subtype') #2
tshark_cmd.append('-ewlan.fc.fromds') #3
tshark_cmd.append('-ewlan.fc.tods') #4
#tshark_cmd.append('-ewlan.addr')
tshark_cmd.append('-ewlan.da') #5
tshark_cmd.append('-ewlan.sa') #6
tshark_cmd.append('-ewlan.bssid') #7
tshark_cmd.append('-ewlan.ra') #5
tshark_cmd.append('-ewlan.ta') #6

tshark_cmd.append('-Eseparator=;');


# tshark command to print the decoded info
tshark_info_cmd = [ 'tshark']
tshark_info_cmd.append('-r')
tshark_info_cmd.append(sys.argv[1])
if n < 3:
  tshark_info_cmd.append('wlan')
else:
  tshark_info_cmd.append(sys.argv[2])
tshark_info_cmd.append('-o')
tshark_info_cmd.append('column.format:"Info","%i","Protocol","%p"')
print >>sys.stderr, '%s' % tshark_cmd
print >>sys.stderr, '%s' % tshark_info_cmd

# start tshark subprocesses and prepare a pipe to which it will write stdout
shark = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE)
sharkout = shark.stdout

shark_info = subprocess.Popen(tshark_info_cmd, stdout=subprocess.PIPE)
sharkout_info = shark_info.stdout

frame_names = {
'0x00': 'Association request', '0x01': 'Association response', 
'0x02': 'Reassociation request', '0x03': 'Reassociation response', 
'0x04': 'Probe request', '0x05': 'Probe response', 
'0x07': 'Timing Advertisement', '0x07': 'Reserved', 
'0x08': 'Beacon', '0x09': 'ATIM', '0x0a': 'Disassociation', 
'0x0b': 'Authentication', '0x0c': 'Deauthentication', 
'0x0d': 'Action', '0x0e': 'Action No Ack', '0x0f': 'Reserved',         
'0x17': 'Control Wrapper', '0x18': 'BlockAckReq', '0x19': 'BlockAck', 
'0x1a': 'PS-Poll', '0x1b': 'RTS', '0x1c': 'CTS', '0x1d': 'ACK', 
'0x1e': 'CF-End', '0x1f': 'CF-End + CF-Ack',     
'0x20': 'Data', '0x21': 'Data + CF-Ack', '0x22': 'Data + CF-Poll', 
'0x23': 'Data + CF-Ack + CF-Poll', '0x24': 'Null (no data)', '0x25': 'CF-Ack (no data)', 
'0x26': 'CF-Poll (no data)', '0x27': 'CF-Ack + CF-Poll (no data)', 
'0x28': 'QoS Data', '0x29': 'QoS Data + CF-Ack', '0x2a': 'QoS Data + CF-Poll', 
'0x2b': 'QoS Data + CF-Ack + CF-Poll', '0x2c': 'QoS Null (no data)', '0x2d': 'Data-Reserved', 
'0x2e': 'QoS CF-Poll (no data)', '0x2f': 'QoS CF-Ack + CF-Poll (no data)'}
 

# list of messages displayed by tshark
messages = []
msg_prev = {}
msg_prev['dst'] = 'ff:ff:ff:ff:ff:ff'

while True:
  line = sharkout.readline()
  line_info = sharkout_info.readline()
  # eof encountered
  if len(line) == 0:
    break

#0	0x08	ff:ff:ff:ff:ff:ff,00:0c:41:82:b2:55	
#Number type_subtype wlan.addr(dst,src)
#  regex = re.compile('^(.+)\t+(.+)\t+(.+),(.+)\t+(.+)\t+(.+)\t$')
  regex_da_sa_bssid = re.compile('^(.+);+(.+);+(.+);+(.+);+(.+);+(.+);(.+);;$')
  regex_ra_ta = re.compile('^(.+);+(.+);+(.+);+(.+);;;;(.+);(.+)$')
  regex_ra = re.compile('^(.+);+(.+);+(.+);+(.+);;;;(.+);$')
#1	0x1d		00:0c:41:82:b2:55
#Number type_subtype wlan.addr(receiver)
#  regex_ra = re.compile('^(.+)\t+(.+)\t\t\t\t+(.+)$')
  regex_info =re.compile('^(.+) +(.+)$')
  ret = regex_da_sa_bssid.match(line)
  ret_info = regex_info.match(line_info)
  if ret != None:
    msg = {}
    msg['sub_type'] = ret.group(2)
    msg['msg'] = frame_names[msg['sub_type']]    
    fromds = ret.group(3)
    tods = ret.group(4)
    bssid = ret.group(7)
    if fromds=="1":
      msg['src'] = bssid
    else:
      msg['src'] = ret.group(6)
    if tods=="1":
      msg['dst'] = bssid
    else:
      msg['dst'] = ret.group(5)

    print("**** %s:%s:%s:%s:%s:%s" % (ret.group(1),ret.group(3),ret.group(4),ret.group(5),ret.group(6),ret.group(7)))

    msg['number'] = ret.group(1)
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
    ret = regex_ra.match(line)
    if ret == None:
      ret = regex_ra_ta.match(line)
      if ret == None:
        print >>sys.stderr, "line '%s' not handled by regex !" % line
        continue
      else:
        ta_match=1
    else:
      ta_match = 0

    msg = {}
    msg['sub_type'] = ret.group(2)
    msg['msg'] = frame_names[msg['sub_type']]    
    msg['dst'] = ret.group(5)
    if ta_match==0:
      msg['src'] = 'ff:ff:ff:ff:ff:ff'
    else:
      msg['src'] = ret.group(6)
    msg['number'] = ret.group(1)
    msg['info'] = ""
    messages.append(msg)
  if debug==1:
    print("**** %s" % msg)
    print("^^^^ %s" % msg_prev)
#  if msg['src']=='ff:ff:ff:ff:ff:ff':
#    msg['src']=msg_prev['dst']
  msg_prev = msg

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
    msg_text = '%s %s' % (msg['number'],msg['msg'])
  else:
    msg_text = '%s %s' % (msg['number'],msg['info'])
  line = 'u%d->u%d:\"%s\"' % (src, dst, msg_text)
#  print("u%d->u%d:\"%s\"" % (src, dst, msg_text))
  print("%s" % line)
  msc_text += '%s\n' % line

style = "qsd"
pngFile = "out.png"
getSequenceDiagram( msc_text, pngFile, style )
#End: Main code


