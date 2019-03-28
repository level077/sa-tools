#! /usr/bin/python

import psutil
from subprocess import PIPE

software = []

def get_version(name=None,cmdline=None,ports=None):
  version = None
  with psutil.Popen(["/usr/bin/rpm", '-qf',cmdline], stdout=PIPE,stderr=PIPE) as p:
    p.wait(timeout=1)
    if p.returncode == 0:
      version = p.communicate()[0].strip()
      return version
  if not version:
    if name == 'nginx':
      with psutil.Popen([cmdline,"-v"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split("/")[-1]
          return version
    elif name == "redis-server":
      with psutil.Popen([cmdline,"-v"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2].split("=")[-1]
          return version
    elif name == "etcd":
      with psutil.Popen([cmdline,"-version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2]
          return version
    elif name == "mysqld":
      with psutil.Popen([cmdline,"--version"],stdout=PIPE,stderr=PIPE) as p:
        p.wait(timeout=1)
        if p.returncode == 0:
          version = p.communicate()[0].split()[2]
          return version
  return "Unknown" 

def get_centos_software():
  for proc in psutil.process_iter(attrs=['name','cmdline','connections']):
    s = {}
    s['name'] = proc.info['name']
    s['listen'] = []
    s['ports'] = []
    cmdline = proc.info['cmdline']
    if len(cmdline) != 0:
      s['cmdline'] = cmdline[0].split()[0]
    for c in proc.info['connections']:
      if c.status == "LISTEN":
        s['ports'].append(c.laddr.port)
        s['listen'].append(c.laddr.ip + ":" + str(c.laddr.port))
    if len(s['listen']) != 0:
      s['ports'] = list(set(s['ports']))
      s['version'] = get_version(s['name'],s['cmdline'],s['ports'])
      software.append(s)
  return software

if __name__ == "__main__":
  info = get_centos_software()
  print(info)
