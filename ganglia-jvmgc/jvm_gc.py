import os
import subprocess
import threading
import time

_WorkerThread = None    #Worker thread object
_glock = threading.Lock()   #Synchronization lock
_refresh_rate = 10 #Refresh rate of the netstat data
_port = None
_cmd = None
_java_home =  None
_metric_prefix = None 
_status = {}

def jvm_status(name):
    global _WorkerThread
   
    if _WorkerThread is None:
        print 'Error: No data gathering thread created for metric %s' % name
        return 0
        
    if not _WorkerThread.running and not _WorkerThread.shuttingdown:
        try:
            _WorkerThread.start()
        except (AssertionError, RuntimeError):
            pass

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

    def shutdown(self):
        self.shuttingdown = True
        if not self.running:
            return
        self.join()

    def run(self):
        global _status
        self.running = True
        while not self.shuttingdown:
            if self.shuttingdown:
                break
            java_pid = subprocess.Popen(_cmd,shell=True,stdout=subprocess.PIPE).communicate()[0].split("\n")[0]
    	    cmd = _java_home + "/bin/jstat -gcutil " + java_pid 
            lines = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE).communicate()[0].split("\n")[1]
	    _glock.acquire()
	    _status[_metric_prefix + "jvm_old"] = lines.split()[3]
	    _status[_metric_prefix + "jvm_perm"] = lines.split()[4]
	    _status[_metric_prefix + "jvm_full_gc"] = lines.split()[7]
            _status[_metric_prefix + "jvm_ygc"] = lines.split()[5]
            _glock.release()
            
            #Wait for the refresh_rate period before collecting the netstat data again.
            if not self.shuttingdown:
                time.sleep(_refresh_rate)

        #Set the current state of the thread after a shutdown has been indicated.
        self.running = False

def metric_init(params):
    global _java_home, _metric_prefix, _refresh_rate, _WorkerThread, _port, _status,descriptors,_cmd
    
    #Read the refresh_rate from the gmond.conf parameters.
    if 'RefreshRate' in params:
        _refresh_rate = int(params['RefreshRate'])

    if 'Port' in params:
	_port = params['Port']

    if 'JAVA_HOME' in params:
	_java_home = params['JAVA_HOME']
   
    if 'PID_CMD' in params:
	_cmd = params['PID_CMD']

    _metric_prefix = "JVMGC_"+  _port + "_"

    _status = {_metric_prefix +'jvm_perm': 0,
        _metric_prefix + 'jvm_old':0,
        _metric_prefix + 'jvm_full_gc':0,
	_metric_prefix + 'jvm_ygc':0}


    #create descriptors
    descriptors = []
    
    Desc_Skel = {
        'name'        : 'XXX',
        'call_back'   : jvm_status,
        'time_max'    : 30,
        'value_type'  : 'float',
        'format'      : '%.2f',
        'units'       : 'XXX',
        'slope'       : 'both', # zero|positive|negative|both
        'description' : 'XXX',
        'groups'      : 'JVMGC_' + _port,
        }

    descriptors.append(create_desc(Desc_Skel,{
			'name': _metric_prefix + 'jvm_perm',
			'units': '%',
			'description': 'jvm perm',
			})) 
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'jvm_old',
                        'units': '%',
                        'description': 'jvm old',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'jvm_full_gc',
                        'units': 'count',
                        'description': 'jvm full gc',
                        }))
    descriptors.append(create_desc(Desc_Skel,{
                        'name': _metric_prefix + 'jvm_ygc',
                        'units': 'count',
                        'description': 'jvm young gc',
                        }))
    #Start the worker thread
    _WorkerThread = NetstatThread()
    
    #Return the metric descriptions to Gmond
    return descriptors

def metric_cleanup():
    '''Clean up the metric module.'''
    
    #Tell the worker thread to shutdown
    _WorkerThread.shutdown()

#This code is for debugging and unit testing    
if __name__ == '__main__':
    params = {'RefreshRate': '2','JAVA_HOME':'/usr/local/jdk1.6.0_32',"Port":"8110","PID_CMD":"ps axu | grep java | grep -v grep | grep _8110 | awk '{print $2}'"}
    metric_init(params)
    while True:
        try:
            for d in descriptors:
                v = d['call_back'](d['name'])
                print 'value for %s is %.2f' % (d['name'],  v)
            time.sleep(2)
        except KeyboardInterrupt:
            os._exit(1)
