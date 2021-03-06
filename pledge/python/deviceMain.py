import sys

#import GRASP to use its thread safe print function
sys.path.insert(0, 'graspy/')
from grasp import tprint

from _thread import start_new_thread
import datetime

#import all the modules
import grasp_device
#import TLS_client
import NETCONF_server
import REST_client

from queue import Queue
from math import floor

def main(args):
    """
    - initialize the queues to communicate with the threads
    - start the modules as individual threads
    """

    tprint("starting main Thread")

    #start_new_thread(TLS_Server.main,())

    threads = []
    connectCandidates = []
    graspDiscoverQueue = Queue()
    tlsConnectionQueue = Queue()
    threads.append(grasp_device.GRASP_device_Thread(graspDiscoverQueue, ))
    #threads.append(TLS_client.TLS_device_Thread(tlsConnectionQueue, ))

    threads.append(NETCONF_server.NETCONF_device_Thread())
    threads.append(REST_client.REST_device_Thread(tlsConnectionQueue))


    for t in threads:
        t.start()

    #tlsConnectionQueue.put('172.20.0.3')
    while(True):

        """
        - read data from the graspDiscoverQueue und check if it is already known
        - if its already know, check when it was last tried
        - if the last connection attempt is longer than 30sek ago, try again (might change the value later)
        """

        tmpValues = [graspDiscoverQueue.get(), datetime.datetime.now()]
        deviceKnown = False
        for candidate in connectCandidates:
            if tmpValues[0] == candidate[0]:
                deviceKnown = True
                timeNow = datetime.datetime.now()
                elapsedTime = (timeNow - candidate[1]).seconds
                #print('#####################last connected: ',  elapsedTime)
                if elapsedTime > 30:
                    candidate[1] = timeNow
                    tlsConnectionQueue.put(candidate[0])

        if not deviceKnown:
            connectCandidates.append(tmpValues)
            tlsConnectionQueue.put(tmpValues[0])

        tprint("\n#################\n", connectCandidates, "\n#################\n" )

        #tprint('##############\n##############')
        pass

if __name__ == '__main__':
    main(sys.argv[1:])
