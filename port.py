#USAGE: python port.py -H www.inkeep.org -p 21,22,80
import optparse
import socket
from socket import *
  
def connScan(tgtHost, tgtPort):
  try:
    connSkt = socket(AF_INET, SOCK_STREAM)
    connSkt.connect((tgtHost, tgtPort))
    connSkt.send('000\r\n')
    results = connSkt.recv(100)
    print '[+] %d/tcp open'% tgtPort
    print '[+] ' + str(results)
    connSkt.close()
  except Exception, e:
    print '[-] %d/tcp closed'% tgtPort
    print e
  
def portScan(tgtHost, tgtPorts):
  try:
    tgtIP = gethostbyname(tgtHost)
  except:
    print "[-] Cannot resolve '%s': Unknown host" %tgtHost
    return

  try:
    tgtName = gethostbyaddr(tgtIP)
    print '\n[+] Scan results for: ' + tgtName[0]
  except:
    print'\n[+] Scan results for: ' + tgtIP
  
  setdefaulttimeout(5)
  
  for tgtPort in tgtPorts:
    print '\nScanning port ' + tgtPort
    connScan(tgtHost, int(tgtPort))
    
def main():
  parser = optparse.OptionParser('usage%prog -H <target host> -p <target port>')
  parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
  parser.add_option('-p', dest='tgtPort', type='string', help='specify target port')

  (options, args) = parser.parse_args()

  tgtHost = options.tgtHost
  tgtPorts = str(options.tgtPort).split(',')

  if (tgtHost == None) | (tgtPorts[0] == None):
    print '[-] You must specify a target host and port[s].'
    exit(0)
    
  portScan(tgtHost, tgtPorts)

if __name__ == '__main__':
  main()