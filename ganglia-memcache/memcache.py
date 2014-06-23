import os
import socket

OBSOLETE_POPEN = False
try:
    import subprocess
except ImportError:
    import popen2
    OBSOLETE_POPEN = True

import threading
import time

_WorkerThread = None    #Worker thread object
_glock = threading.Lock()   #Synchronization lock
_refresh_rate = 10 #Refresh rate of the netstat data
_host = None
_port = None
_cmd = None
_metric_prefix =None
sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

_status = {}

def memcache_status(name):
    '''Return the mysql status.'''
    global _WorkerThread
   
    if _WorkerThread is None:
        print 'Error: No netstat data gathering thread created for metric %s' % name
        return 0
        
    if not _WorkerThread.running and not _WorkerThread.shuttingdown:
        try:
            _WorkerThread.start()
        except (AssertionError, RuntimeError):
            pass

    if _WorkerThread.num < 2:
        return 0
    _glock.acquire()
    ret = float(_status[name])
    _glock.release()
    return ret

#create descriptions
def create_desc(skel,prop):
    d = skel.copy()
    for k,v in prop.iteritems():
        d[k] = v
    return d

class NetstatThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.running = False
        self.shuttingdown = False
	self.num = 0

    def shutdown(self):
        self.shuttingdown = True
        if not self.running:
            return
        self.join()

    def run(self):
        global _status,sock
   
        tempstatus = _status.copy()
        
        #Set the state of the running thread
        self.running = True
        
        #Continue running until a shutdown event is indicated
        while not self.shuttingdown:
            if self.shuttingdown:
                break
            
            sock.send('stats\r\n')
	    lines = sock.recv(2048).split("\r\n")
            #Iterate through the netstat output looking for the 'tcp' keyword in the tcp_at 
            # position and the state information in the tcp_state_at position. Count each 
            # occurance of each state.
            for status in lines:
                # skip empty lines
                if status == '':
                    continue
		if status == "END":
		    continue
                line = status.split()
                if line[1] == 'curr_connections':
                    tempstatus[_metric_prefix + 'curr_connections'] = line[2]
   		elif line[1] == 'cmd_get':
		    tempstatus[_metric_prefix + 'get'] = line[2]
		    tempstatus[_metric_prefix + 'get_delta'] = (int(line[2])- int(_status[_metric_prefix + 'get']))/_refresh_rate
          	elif line[1] == 'cmd_set':
                    tempstatus[_metric_prefix + 'set'] = line[2]
                    tempstatus[_metric_prefix + 'set_delta'] = (int(line[2])- int(_status[_metric_prefix + 'set']))/_refresh_rate
		elif line[1] == 'cmd_flush':
                    tempstatus[_metric_prefix + 'flush'] = line[2]
                    tempstatus[_metric_prefix + 'flush_delta'] = (int(line[2])- int(_status[_metric_prefix + 'flush']))/_refresh_rate
		elif line[1] == 'cmd_touch':
                    tempstatus[_metric_prefix + 'touch'] = line[2]
                    tempstatus[_metric_prefix + 'touch_delta'] = (int(line[2])- int(_status[_metric_prefix + 'touch']))/_refresh_rate
		elif line[1] == 'evictions':
                    tempstatus[_metric_prefix + 'evictions'] = line[2]
                    tempstatus[_metric_prefix + 'evictions_delta'] = (int(line[2])- int(_status[_metric_prefix + 'evictions']))/_refresh_rate
                elif line[1] == 'get_hits':
                    tempstatus[_metric_prefix + 'hit_ratio'] = float(float(line[2]) / float(tempstatus[_metric_prefix + 'get']))
                elif line[1] == 'bytes':
                    tempstatus[_metric_prefix + 'bytes'] = float(line[2]) /1024/1204/1024
                        
            #Acquire a lock and copy the temporary connection state dictionary
            # to the global state dictionary.
            _glock.acquire()
            for tmpstatus in _status:
                _status[tmpstatus] = tempstatus[tmpstatus]
            _glock.release()
            
            #Wait for the refresh_rate period before collecting the netstat data again.
            if not self.shuttingdown:
                time.sleep(_refresh_rate)

	    self.num += 1
            if self.num >= 2:
                self.num = 2
            
        #Set the current state of the thread after a shutdown has been indicated.
        self.running = False

def metric_init(params):
    global sock,_metric_prefix, _refresh_rate, _WorkerThread, _host, _port, _status,descriptors
    
    #Read the refresh_rate from the gmond.conf parameters.
    if 'RefreshRate' in params:
        _refresh_rate = int(params['RefreshRate'])

    if 'Host' in params:
        _host = params['Host']
  
    if 'Port' in params:
	_port = params['Port']

    sock.connect((_host,int(_port)))

    _metric_prefix = "memcache_"+_host + "_" + _port + "_"

    _status = {_metric_prefix +'curr_connections': 0,
        _metric_prefix + 'get':0,
        _metric_prefix + 'get_delta':0,
        _metric_prefix + 'set':0,
        _metric_prefix + 'set_delta':0,
        _metric_prefix + 'flush':0,
        _metric_prefix + 'flush_delta':0,
        _metric_prefix + 'touch':0,
        _metric_prefix + 'touch_delta':0,
        _metric_prefix + 'hit_ratio':0,
        _metric_prefix + 'bytes':0,
        _metric_prefix + 'evictions':0,
        _metric_prefix + 'evictions_delta':0}

    #create descriptors
    descriptors = []
    
    Desc_Skel = {
        'name'        : 'XXX',
        'call_back'   : memcache_status,
        'time_max'    : 30,
        'value_type'  : 'float',
        'format'      : '%.2f',
        'units'       : 'XXX',
        'slope'       : 'both', # zero|positive|negative|both
        'description' : 'XXX',
        'groups'      : 'memcache'+ _host + '_' + _port,
        }

    descriptors.append(create_desc(Desc_Skel,{
			'name': _metric_prefix + 'get_delta',
			'units': 'count/s',
			'description': 'get_delta',
			})) 
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'set_delta',
                        'units': 'count/s',
                        'description': 'set_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'flush_delta',
                        'units': 'count/s',
                        'description': 'flush_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'touch_delta',
                        'units': 'count/s',
                        'description': 'touch_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'evictions_delta',
                        'units': 'count/s',
                        'description': 'evictions_delta',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'hit_ratio',
                        'units': '%',
                        'description': 'hit_ratio',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'bytes',
                        'units': 'G',
                        'description': 'bytes',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'curr_connections',
                        'units': 'count',
                        'description': 'curr_connections',
                        }))
    
    #Start the worker thread
    _WorkerThread = NetstatThread()
    
    #Return the metric descriptions to Gmond
    return descriptors

def metric_cleanup():
    '''Clean up the metric module.'''
    
    #Tell the worker thread to shutdown
    _WorkerThread.shutdown()
    sock.send('quit\r\n')
    sock.close()

#This code is for debugging and unit testing    
if __name__ == '__main__':
    params = {'RefreshRate': '2','Host':'192.168.10.1',"Port":"11211"}
    metric_init(params)
    while True:
        try:
            for d in descriptors:
                v = d['call_back'](d['name'])
                print 'value for %s is %.2f' % (d['name'],  v)
            time.sleep(2)
        except KeyboardInterrupt:
            os._exit(1)
