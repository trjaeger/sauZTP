import sys

#import GRASP to use its thread safe print function
#sys.path.insert(0, 'graspy/')
#from grasp import tprint

from _thread import start_new_thread
from queue import Queue

#import all the modules
import GRASP_RegServer
#import TLS_Server
import NETCONF_client
import REST_Server



def main(args):
    print("starting main Thread")

    devicesQueue = Queue()
    """
    threads = []
    threads.append(REST_Server.REST_Server_Thread(devicesQueue))
    for t in threads:
        t.start()
    """
    start_new_thread(REST_Server.main,(devicesQueue,))
    #start_new_thread(TLS_Server.main,())
    start_new_thread(GRASP_RegServer.main, (1,))
    #start_new_thread(NETCONF_client.main, (,))

    while(True):

        tmpIP = devicesQueue.get()
        print("received ", tmpIP, "starting NETCONF therad")
        start_new_thread(NETCONF_client.main, (tmpIP,))
        pass


if __name__ == '__main__':
    main(sys.argv[1:])
