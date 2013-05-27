import subprocess

def Gc_Handle(name):
    cmd = "ps axu | grep java | grep -v grep | awk '{print $2}'"
    java_pid = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE).communicate()[0].split("\n")[0]
    java_home = "/usr/local/app/jdk"
    cmd_jstat = java_home + "/bin/jstat -gcutil " + java_pid
    try:
        gcstat = subprocess.Popen(cmd_jstat,shell=True,stdout=subprocess.PIPE).communicate()[0].split("\n")[1].split()[3:5]
    except IndexError:
	return float(00.00)
	
    if name == "jvm_old_generation":
        return float(gcstat[0])
    if name == "jvm_perm_generation":
        return float(gcstat[1])

def metric_init(params):
    global descriptors
    d1 = {'name': 'jvm_old_generation',
        'call_back': Gc_Handle,
        'time_max': 90,
        'value_type': 'float',
        'units': 'percent',
        'slope': 'both',
        'format': '%.2f',
        'description': 'jvm old generation',
        'groups': 'jvm gc'}

    d2 = {'name': 'jvm_perm_generation',
        'call_back': Gc_Handle,
        'time_max': 90,
        'value_type': 'float',
        'units': 'percent',
        'slope': 'both',
        'format': '%.2f',
        'description': 'jvm perm generation',
	'groups': 'jvm gc'}

    descriptors = [d1,d2]
    return descriptors

def metric_cleanup():
    pass

#This code is for debugging and unit testing    
if __name__ == '__main__':
    metric_init({})
    for d in descriptors:
        v = d['call_back'](d['name'])
        print 'value for %s is %.2f' % (d['name'],v)

