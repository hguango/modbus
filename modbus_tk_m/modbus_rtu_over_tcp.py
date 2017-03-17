#!/usr/bin/env python
# -*- coding: utf-8 -*-


from modbus import *
import socket
import select
import logging
from hooks import call_hooks
from utils import threadsafe_function
import sys
import binascii


#-------------------------------------------------------------------------------
class RtuOverTcpQuery(Query):
    """Subclass of a Query. Adds the Modbus TCP specific part of the protocol"""    
    
    #static variable for giving a unique id to each query
    #_last_transaction_id = 0
    
    def __init__(self):
        """Constructor"""
        Query.__init__(self)
         
        self._request_address = 0
        self._response_address = 0

    
    def build_request(self, pdu, slave):
        """Add the Modbus RTU part to the request"""
        self._request_address = slave
        if (slave < 0) or (slave > 255):
            raise InvalidArgumentError, "%d Invalid value for slave id" % (slave)
        data = struct.pack(">B", self._request_address) + pdu
        crc = struct.pack(">H", utils.calculate_crc(data))
        return (data + crc)


    def parse_response(self, response):
        """Extract the pdu from the Modbus RTU response"""
        if len(response) < 3:
            raise ModbusInvalidResponseError, "Response length is invalid %d" % (len(response))

        (self._response_address, ) = struct.unpack(">B", response[0])
        if self._request_address != self._response_address:
            raise ModbusInvalidResponseError, "Response address %d is different from request address %d" % \
                (self._response_address, self._request_address)

        (crc, ) = struct.unpack(">H", response[-2:])

        if crc != utils.calculate_crc(response[:-2]):
            raise ModbusInvalidResponseError, "Invalid CRC in response"

        return response[1:-2]


    def parse_request(self, request):
        """Extract the pdu from the Modbus RTU request"""
        if len(request) < 3:
            raise ModbusInvalidRequestError, "Request length is invalid %d" % (len(request))

        (self._request_address, ) = struct.unpack(">B", request[0])

        (crc, ) = struct.unpack(">H", request[-2:])
        if crc != utils.calculate_crc(request[:-2]):
            raise ModbusInvalidRequestError, "Invalid CRC in request"

        return (self._request_address, request[1:-2])

    def build_response(self, response_pdu):
        """Build the response"""
        self._response_address = self._request_address
        data = struct.pack(">B", self._response_address) + response_pdu
        crc = struct.pack(">H", utils.calculate_crc(data))
        return (data + crc)

#-------------------------------------------------------------------------------
class RtuOverTcpMaster(Master):
    """Subclass of Master. Implements the Modbus TCP MAC layer"""
    
    def __init__(self, host="127.0.0.1", port=502, timeout_in_sec=5.0):
        """Constructor. Set the communication settings"""
        Master.__init__(self, timeout_in_sec)
        self._host = host
        self._port = port
        self._sock = None
        
    def _do_open(self):
        """Connect to the Modbus slave"""
        if self._sock:
            self._sock.close()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_timeout(self.get_timeout())
        call_hooks("modbus_rtu_over_tcp.RtuOverTcpMaster.before_connect", (self, ))
        self._sock.connect((self._host, self._port))
        call_hooks("modbus_rtu_over_tcp.RtuOverTcpMaster.after_connect", (self, ))    
            
    def _do_close(self):
        """Close the connection with the Modbus Slave"""
        if self._sock:
            call_hooks("modbus_rtu_over_tcp.RtuOverTcpMaster.before_close", (self, ))
            self._sock.close()
            call_hooks("modbus_rtu_over_tcp.RtuOverTcpMaster.after_close", (self, ))
            self._sock = None
    
    def set_timeout(self, timeout_in_sec):
        """Change the timeout value"""
        Master.set_timeout(self, timeout_in_sec)
        if self._sock:
            self._sock.setblocking(timeout_in_sec>0)
            if timeout_in_sec:
                self._sock.settimeout(timeout_in_sec)        
        
    def _send(self, request):
        """Send request to the slave"""
        retval = call_hooks("modbus_rtu_over_tcp.RtuOverTcpMaster.before_send", (self, request))
        if retval <> None:
            request = retval
        try:
            utils.flush_socket(self._sock, 3)
        except Exception, msg:
            #if we can't flush the socket successfully: a disconnection may happened
            #try to reconnect
            LOGGER.error('Error while flushing the socket: {0}'.format(msg))
            #raise ModbusNotConnectedError(msg)
            self._do_open();
        self._sock.send(request)
        
    def _recv(self, expected_length=-1):
        """
        Receive the response from the slave
        Do not take expected_length into account because the length of the response is
        written in the mbap. Used for RTU only
        """
        
        response = ""

##################### Modified by yaoming.lin on 2013-07-09 ####################

        is_ok = True

        #read the 5 bytes of the pdu message
        while (len(response) < 5) and is_ok: 
            new_byte = self._sock.recv(1)
            if len(new_byte) == 0:
                is_ok = False
            else:
                response += new_byte
        if is_ok:
            #read the rest of the request
            #length = self._get_request_length(request)
            if ord(response[1]) < 7:  # Modified by yaoming.lin on 2015-08-17
                length = ord(response[2]) + 5
            elif ord(response[1]) < 17:
                 length = 8
            else:
                 length = 5
                        
        while (len(response) < length) and is_ok:
            new_byte = self._sock.recv(1)
            if len(new_byte) == 0:
                is_ok = False
            else:
                 response += new_byte

################################################################################

        retval = call_hooks("modbus_rtu_over_tcp.RtuOverTcpMaster.after_recv", (self, response))
        if retval <> None:
            return response
        return response
        
    def _make_query(self):
        """Returns an instance of a Query subclass implementing the modbus TCP protocol"""
        return RtuOverTcpQuery()

#-------------------------------------------------------------------------------
class RtuOverTcpServer(Server):
    """This class implements a simple and mono-threaded modbus tcp server"""
    
    def __init__(self, port=502, address='localhost', timeout_in_sec=1, databank=None, print_message=False):  # 'print_message' was added by zhen.zhang on 2015-08-17
        """Constructor: initializes the server settings"""
        Server.__init__(self, databank if databank else Databank())
        self._sock = None
        self._sa = (address, port)
        self._timeout_in_sec = timeout_in_sec
        self._sockets = []
        self._print_message = print_message  # Added by zhen.zhang on 2015-08-17

    def _make_query(self):
        """Returns an instance of a Query subclass implementing the modbus TCP protocol"""
        return RtuOverTcpQuery()
    
    '''
    def _get_request_length(self, mbap):
        """Parse the mbap and returns the number of bytes to be read"""
        if len(mbap) < 6:
            raise ModbusInvalidRequestError("The mbap is only %d bytes long", len(mbap))
        (tr_id, pr_id, length) = struct.unpack(">HHH", mbap[:6])
        return length
    '''

    def _do_init(self):
        """initialize server"""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if self._timeout_in_sec:
            self._sock.settimeout(self._timeout_in_sec)
        self._sock.setblocking(0)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Added by zhen.zhang on 2015-08-17
        self._sock.bind(self._sa)
        self._sock.listen(10)
        self._sockets.append(self._sock)
        
    def _do_exit(self):
        """clean the server tasks"""
        #close the sockets
        for sock in self._sockets:
            try:
                sock.close()
                self._sockets.remove(sock)
            except Exception, msg:
                LOGGER.warning("Error while closing socket, Exception occurred: %s", msg)
        self._sock.close()
        self._sock = None    
   
    def _do_run(self):
        """called in a almost-for-ever loop by the server"""
        #check the status of every socket
        inputready, outputready, exceptready = select.select(self._sockets, [], [], 1.0)

        for sock in inputready: #handle data on each a socket
            try:
                if sock == self._sock:
                    # handle the server socket
                    client, address = self._sock.accept()
                    client.setblocking(0)
                    LOGGER.info("%s is connected with socket %d..." % (str(address), client.fileno()))
                    self._sockets.append(client)
                    call_hooks("modbus_rtu_over_tcp.RtuOverTcpServer.on_connect", (self, client, address))
                else:
                    if len(sock.recv(1, socket.MSG_PEEK)) == 0:
                        #socket is disconnected
                        LOGGER.info("%d is disconnected" % (sock.fileno()))
                        call_hooks("modbus_rtu_over_tcp.RtuOverTcpServer.on_disconnect", (self, sock))
                        sock.close()
                        self._sockets.remove(sock)
                        break
                    
                    # handle all other sockets
                    sock.settimeout(1.0)
                    request = ""
                    is_ok = True

##################### Modified by yaoming.lin on 2013-07-09 ####################

                    #read the 2 bytes of the pdu message
                    while (len(request) < 2) and is_ok: 
                        new_byte = sock.recv(1)
                        if len(new_byte) == 0:
                            is_ok = False    
                        else:
                            request += new_byte
                        
                    retval = call_hooks("modbus_rtu_over_tcp.RtuOverTcpServer.after_recv", (self, sock, request))
                    if retval <> None:
                        request = retval
                    
                    if is_ok:
                        #read the rest of the request
                        #length = self._get_request_length(request)
                        if ord(request[1]) < 7:  # Modified by yaoming.lin on 2015-08-17
                            length = 8
                        elif ord(request[1]) < 17:
                            while (len(request) < 7) and is_ok: 
                                new_byte = sock.recv(1)
                                if len(new_byte) == 0:
                                    is_ok = False    
                                else:
                                    request += new_byte                            
                            length = ord(request[6]) + 9
                        else:
                            length = 5
                        
                        while (len(request) < length) and is_ok:
                            new_byte = sock.recv(1)
                            if len(new_byte) == 0:
                                is_ok = False
                            else:
                                request += new_byte

                    if self._print_message:  # Added by zhen.zhang on 2015-08-17
                        LOGGER.info("(Socket %d) Rx: %s" % (sock.fileno(), binascii.b2a_hex(request)))  # Added by zhen.zhang on 2015-08-17


################################################################################

                    if is_ok:
                        response = ""
                        #parse the request
                        try:
                            response = self._handle(request)
                        except Exception, msg:
                            LOGGER.error("Error while handling a request, Exception occurred: %s", msg)
                        
                        #send back the response
                        if response:
                            try:
                                retval = call_hooks("modbus_rtu_over_tcp.RtuOverTcpServer.before_send", (self, sock, response))
                                if retval <> None:
                                    response = retval
                                sock.send(response)
                                if self._print_message:  # Added by zhen.zhang on 2015-08-17
                                    LOGGER.info("(Socket %d) Tx: %s" % (sock.fileno(), binascii.b2a_hex(response)))  # Added by zhen.zhang on 2015-08-17
                            except Exception, msg:
                                is_ok = False
                                LOGGER.error("Error while sending on socket %d, Exception occurred: %s", sock.fileno(), msg)
            except Exception, excpt:
                LOGGER.warning("Error while processing data on socket %d: %s", sock.fileno(), excpt)
                call_hooks("modbus_rtu_over_tcp.RtuOverTcpServer.on_error", (self, sock, excpt))
                sock.close()
                self._sockets.remove(sock)
                
