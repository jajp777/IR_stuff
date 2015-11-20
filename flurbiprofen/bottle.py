import sys
import time
import random
import threading
import subprocess

max_dockers = 7

drop_tag  = 'flurb:dropper'
drop_cmd = 'docker run --privileged --rm -t %s %s' 

es_tag = 'flurb:es'
es_cmd = 'docker run --name es -p 9200:9200 -p 5601:5601 -t %s' % es_tag

def ip_gen(list_file):
    """basic helper func to get ips in a more memory efficient way"""

    with open(list_file, 'r') as f:
        for line in f:
            #we are only interested in full urls
            check = line.startswith('http')
            if check:
                yield line.strip()
            if not check:
                print('[*] Error we got got a bad url: %s' % line.strip())
            

def check_dockers():
    """there is probably a better way to do this with the docker inspect command
        but for now this just parses the running dockers to see how many are
        currently running"""

    n = 0
    out = subprocess.check_output(['docker', 'ps', '-a']).split('\n')[1:-1]
    for line in out:
        n += 1

    return n


def start_es():
    """this starts elasticsearch, will need to add better checking
        to see if one is already running, just going to fail for now"""

    cmd = es_cmd.split(' ')
    subprocess.call(cmd)


def dropper(target_url):
    """just a wrapper so we can thread out creating dockers"""

    tmp = drop_cmd % (drop_tag, target_url)
    print('[*] Running %s', tmp)
    cmd = tmp.split(' ')
    subprocess.call(cmd)




if __name__ == "__main__":
    
   
    print('[*] Starting elasticsearch')
    t = threading.Thread(target=start_es)
    t.start()
    time.sleep(20)

    for line in ip_gen(sys.argv[1]):
        time.sleep(random.uniform(1,2))
        #check the number of running dockers

        while check_dockers() >= max_dockers:
            print('[*] %d dockers running, sleeping before checking again' % check_dockers())
            time.sleep(random.uniform(1,3))

        t = threading.Thread(target=dropper, args=(line,))
        t.start()
    


