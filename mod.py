#!/usr/bin/python
# -*- coding: utf-8 -*-
# -*- filename: collect_modbus.py -*-




import os
import sys
import re
import time
import math
import random
import datetime
import threading
import struct

import serial

import modbus_tk_m.defines as cst
import modbus_tk_m.modbus_tcp as modbus_tcp


try:
 
    master = modbus_tcp.TcpMaster("172.18.105.7",502)  
    master.set_timeout(5.0) 

    master.execute(1, cst.HOLDING_REGISTERS, 0, 16)
   

except KeyboardInterrupt:
    server.stop()
    sys.exit(1)
    
























