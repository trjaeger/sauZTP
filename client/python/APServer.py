import sys

#import GRASP to use its thread safe print function
sys.path.insert(0, 'graspy/')
from grasp import tprint

from _thread import start_new_thread

#import all the modules
import GRASP_RegServer
import TLS_Server

def main(args):
    tprint("starting main Thread")

    start_new_thread(TLS_Server.main,())
    start_new_thread(GRASP_RegServer.main, (1,))

    while(True):
        pass

if __name__ == '__main__':
    main(sys.argv[1:])
