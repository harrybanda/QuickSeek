#! /usr/bin/env python
# coding: utf8

#
# This file is part of the IKPdb Debugger
# Copyright (c) 2016 by Cyril MORISSE, Audaxis
# Licence: MIT. See LICENCE at repository root
#
import socket
import sys
import os
import atexit
import signal
import json
import logging
import traceback
import types
import inspect
import threading
import multiprocessing
import types
import argparse
import datetime
import io
import ctypes
import cgi

import iksettrace3


# For now ikpdb is a singleton
ikpdb = None 
__version__ = "1.1.4"

##
# Logging System
# IKPdb has it's own logging system distinct from python logging to
# avoid collision when debugging programs which reconfigure logging
# system wide.
#
# logging is organized in domains (which corresponds to loggers)
# identified by one letter.
# IKPdb logs on these domains:
# letter: domain
# - n,N: Network 
# - b,B: Breakpoints 
# - e,E: Expression evaluation
# - x,X: Execution 
# - f,F: Frame 
# - g,G: Global debugger
#
# Logging support the same notion of level as python logging.
# Logging is invoked using this syntax:
# _logger.{{domain}}_{{level}}(*args)
# eg: _logger.x_debug("error in %s", the_error)
#
class ANSIColors(object):
    MAGENTA = '\033[95m'    
    BLUE = '\033[94m'       # debug
    GREEN = '\033[92m'      # info
    YELLOW = '\033[93m'     # warning
    RED = '\033[91m'        # error
    BOLD = '\033[1m'        # critical
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

class IKPdbLoggerError(Exception):
    pass
    
class MetaIKPdbLogger(type):
    def __getattr__(cls, name):
        domain, level_name = name.split('_')
        level = IKPdbLogger.LEVELS.get(level_name, None)
        if domain not in IKPdbLogger.DOMAINS or not level:
            raise IKPdbLoggerError("'%s' is not valid logging domain and level combination !" % name)
            
        def wrapper(*args, **kwargs):
            return cls._log(domain, level, *args, **kwargs)
        return wrapper

class IKPdbLogger(object, metaclass=MetaIKPdbLogger):
    """ IKPdb implements it's own logging system to:
    - avoid problem while debugging programs that reconfigure logging system wide.
    - allow IKPdb debugging...
    """
    
    enabled = False
    TEMPLATES = [
        "\033[1m[IKPdb-%s]\033[0m %s - \033[94mNOLOG\033[0m - %s",    # nolog    0
        "\033[1m[IKPdb-%s]\033[0m %s - \033[94mDEBUG\033[0m - %s",    # debug    1
        "\033[1m[IKPdb-%s]\033[0m %s - \033[92mINFO\033[0m - %s",     # info     2
        "\033[1m[IKPdb-%s]\033[0m %s - \033[93mWARNING\033[0m - %s",  # warning  3
        "\033[1m[IKPdb-%s]\033[0m %s - \033[91mERROR\033[0m - %s",    # error    4
        "\033[1m[IKPdb-%s]\033[0m %s - \033[91mCRITICAL\033[0m - %s", # critical 5
    ]

    # Levels
    CRITICAL = 50
    ERROR = 40
    WARNING= 30
    INFO = 20
    DEBUG = 10
    NOLOG= 0

    # Levels by name
    LEVELS = {
        "critical": 50,
        "error": 40,
        "warning": 30,
        "info": 20, 
        "debug": 10,
        "nolog": 0,
    }

    # Domains and domain's level
    DOMAINS = {
        "n": 20,
        "b": 20,
        "e": 20,
        "x": 20,
        "f": 20,
        "p": 20,
        "g": 20
    }

    @classmethod
    def setup(cls, ikpdb_log_arg):
        """ activates DEBUG logging level based on the `ikpdb_log_arg` 
        parameter string.
        
        `ikpdb_log_arg` corresponds to the `--ikpdb-log` command line argument.
           
        `ikpdb_log_arg` is composed of a serie of letters that set the `DEBUG` 
        logging level on the components of the debugger.
           
        Here are the letters and the component they activate `DEBUG` logging 
        level on:
        
            - n,N: Network 
            - b,B: Breakpoints 
            - e,E: Expression evaluation
            - x,X: Execution 
            - f,F: Frame 
            - p,P: Path and python path manipulation
            - g,G: Global debugger
        
        By default logging is disabled for all components. 
        Any `ikpdb_log_arg` value different from the letters above (eg: '9') 
        activates `INFO`  level logging on all domains.
        
        To log, use::
        
            _logger.x_debug("useful information")
    
        Where:
            - `_logger` is a reference to the IKPdbLogger class
            - `x` is the `Execution` domain
            - `debug` is the logging level
        """
        if not ikpdb_log_arg:
            return
        
        IKPdbLogger.enabled = True
        logging_configuration_string = ikpdb_log_arg.lower()
        for letter in logging_configuration_string:
            if letter in IKPdbLogger.DOMAINS:
                IKPdbLogger.DOMAINS[letter] = 10

    @classmethod
    def _log(cls, domain, level, message, *args):
        ts = datetime.datetime.now().strftime('%H:%M:%S,%f')
        if level >= IKPdbLogger.DOMAINS[domain]:
            try:
                string = message % args
            except:
                string = message+"".join([str(e) for e in args])
            print(IKPdbLogger.TEMPLATES[level//10] % (domain, ts, string,), file=sys.stderr, flush=True) 

_logger = IKPdbLogger


##
# Network Manager
#
class IKPdbConnectionError(Exception):
    pass

class IKPdbConnectionHandler(object):
    """ IKPdbConnectionHandler manages a connection with a remote client once
    it is established.
    
    IKpdb and remote client exchanges messages having this structure:
    
    ``length={{integer length of json_message_body below}}{{MAGIC_CODE}}{{json_dump_of_message_body}}``
    
    This class contains methods to receive, send and reply to such messages.
    """
    MAGIC_CODE = b"LLADpcdtbdpac"
    MESSAGE_TEMPLATE = b"length=%%i%b%%b" % MAGIC_CODE
    
    SOCKET_BUFFER_SIZE = 4096  # Maximum size of a packet received from client
    MSG_WAITALL = 0x100  # From Linux sys/socket.h
    
    def __init__(self, connection):
        self._connection = connection
        self._connection_lock = threading.Lock()
        self._received_data = b''
        self._network_loop = True

    def encode(self, obj):
        json_obj_b = json.dumps(obj).encode()
        return self.MESSAGE_TEMPLATE % (len(json_obj_b), json_obj_b,)

    def decode(self, message):
        json_obj = message.split(self.MAGIC_CODE)[1]
        obj = json.loads(json_obj)
        return obj
        
    def log_sent(self, msg):
        _logger.n_debug("Sent %s bytes >>>%s<<<", len(msg), msg)
        
    def log_received(self, msg):
        _logger.n_debug("Received %s bytes >>>%s<<<", len(msg), msg)
    
    def send(self, command, _id=None, result={}, frames=[], 
             error_messages=[], warning_messages=[], info_messages=[],
             exception=None):
        """ Build a message from parameters and send it to debugger.
        
        :param command: The command sent to the debugger client.
        :type command: str
        
        :param _id: Unique id of the sent message. Right now, it's always `None`
                    for messages by debugger to client.
        :type _id: int
        
        :param result: Used to send `exit_code` and updated `executionStatus` 
                       to debugger client.
        :type result: dict
        
        :param frames: contains the complete stack frames when debugger sends
                       the `programBreak` message.
        :type frames: list

        :param error_messages: A list of error messages the debugger client must
                               display to the user.
        :type error_messages: list of str
        
        :param warning_messages: A list of warning messages the debugger client
                                 must display to the user.
        :type warning_messages: list of str
        
        :param info_messages: A list of info messages the debugger client must
                               display to the user.
        :type info_messages: list of str

        :param exception: If debugger encounter an exception, this dict contains
                          2 keys: `type` and `info` (the later is the message).
        :type exception: dict
        """
        with self._connection_lock:
            msg = self.encode({
                '_id': _id,
                'command': command,
                'result': result,
                'commandExecStatus': 'ok',
                'frames': frames,
                'info_messages': info_messages,
                'warning_messages': warning_messages,
                'error_messages': error_messages,
                'exception': exception
            })
            if self._connection:
                send_bytes_count = self._connection.sendall(msg)
                self.log_sent(msg)
                return send_bytes_count
            raise IKPdbConnectionError("Connection lost!")

    def reply(self, obj, result, command_exec_status='ok', info_messages=[], 
              warning_messages=[], error_messages=[]):
        """Build a response from a previouslsy received command message, send it
           and return number of sent bytes.
        
        :param result: Used to send back the result of the command execution to 
                       the debugger client.
        :type result: dict

        See send() above for others parameters definition.
        """
        with self._connection_lock:
            # TODO: add a parameter to remove args from messages ?
            if True:
                del obj['args']
            obj['result'] = result
            obj['commandExecStatus'] = command_exec_status
            obj['info_messages'] = info_messages
            obj['warning_messages'] = warning_messages
            obj['error_messages'] = error_messages
            msg = self.encode(obj)
            send_bytes_count = self._connection.sendall(msg)
            self.log_sent(msg)
            return send_bytes_count

    def receive(self):
        """Waits for a message from the debugger and returns it as a dict.
        """
        # with self._connection_lock:
        while self._network_loop:
            _logger.n_debug("Enter socket.recv(%s) with self._received_data = %s", 
                            self.SOCKET_BUFFER_SIZE, 
                            self._received_data)
            try:
                # We may land here with a full packet already in self.received_data
                # In that case we must not enter recv() 
                if self.SOCKET_BUFFER_SIZE:
                    data = self._connection.recv(self.SOCKET_BUFFER_SIZE)
                else:
                    data = b''
            except socket.error as socket_err:
                return {'command': '_InternalQuit', 
                        'args':{'socket_error_number': socket_err.errno,
                                'socket_error_str': socket_err.strerror}}
            _logger.n_debug("Socket.recv(%s) => %s", self.SOCKET_BUFFER_SIZE, data)
            self._received_data += data
                
            # have we received a MAGIC_CODE
            try:
                magic_code_idx = self._received_data.index(self.MAGIC_CODE)
            except ValueError:
                continue
            
            # Have we received a length=
            try:
                length_idx = self._received_data.index(b'length=')
            except ValueError:
                continue
            
            # extract length content from received data
            json_length = int(self._received_data[length_idx + 7:magic_code_idx])
            message_length = magic_code_idx + len(self.MAGIC_CODE) + json_length
            if message_length <= len(self._received_data):
                full_message = self._received_data[:message_length]
                self._received_data = self._received_data[message_length:]
                if len(self._received_data) > 0:
                    self.SOCKET_BUFFER_SIZE = 0
                else:
                    self.SOCKET_BUFFER_SIZE = 4096
                break
            else:
                self.SOCKET_BUFFER_SIZE = message_length - len(self._received_data)

        self.log_received(full_message)
        obj = self.decode(full_message)
        return obj
        

##
# Debugger
#

class IKPdbQuit(Exception):
    """ A dummy Exception used by debugger to quit debugged program.
    """
    pass

def IKPdbRepr(t):
    """ A function that returns a type representation suitable for debugger GUI.
    :param t: anyThing
    :return: a string representation of t's type
    Note: Type representation str format is not finalized...
    """
    #if hasattr(t, '__class__'):
    #    return t.__class__.__name__
    #t_type = type(t)
    #return str(t_type).split(' ')[1][1:-2]
    return str(type(t))

class IKBreakpoint(object):
    """ IKBreakpoint implements and manages IKPdb Breakpoints. 
    
    Basically a breakpoint is described by:
    
    - `number`: a uniq breakpoint number
    - `file_name`: using a canonical file path
    - `line_number`: 1 based
    - `condition`: an optional python expression used to trigger conditional breakpoints.Basically
    - `enabled`: a flag to enable / disable the breakpoint
    
    The debugger manages Breakpoints using 3 lists maintained by IKBreakpoint:
    
     - `breakpoints_files` contains all breakpoints line numbers indexed by file_name
     - `breakpoints_by_file_and_line` contains all breakpoints indexed by (file, line)
     - `breakpoints_by_number` is an indexed list of all breakpoints.
     
    This class also maintains a `any_active_breakpoint` boolean class attribute
    that is False when there is no active breakpoint. This flag is used to 
    trigger `TURBO Mode`.
     
    :param file_name: a CANONICAL file name.
    :type file_name: str
        
    :param line_number: breakpoint's line number (1 based).
    :type line_number: int
        
    :param condition: an optional python expression used to trigger 
                      conditional breakpoints.
    :type condition: str

    :param enabled: a flag to enable / disable the breakpoint.
    :type enabled: bool
        
    """
    breakpoints_files = {}  #: list of lines indexed by canonical file names
    breakpoints_by_file_and_line = {}  #: list of breakpoints indexed by (file_name, line)
    breakpoints_by_number = []  #: list of breakpoints indexed by number.
    next_breakpoint_number = 0  #: Used to allocate next breakpoint number.
    any_active_breakpoint = False #: False when there is no active breakpoint.
    
    def __init__(self, file_name, line_number, condition=None, enabled=True):
        self.file_name = file_name    # In canonical form!
        self.line_number = line_number
        self.condition = condition
        self.enabled = enabled
        
        # Allocate number
        self.number = IKBreakpoint.next_breakpoint_number
        IKBreakpoint.next_breakpoint_number += 1
        
        # update all lists
        IKBreakpoint.breakpoints_by_number.append(self)
        IKBreakpoint.breakpoints_by_file_and_line[file_name, line_number] = self
        IKBreakpoint.breakpoints_files[file_name] = \
            IKBreakpoint.breakpoints_files.get(file_name, [])+[line_number]
        if enabled:
            IKBreakpoint.any_active_breakpoint = True            

    def clear(self):
        """ Clear a breakpoint by removing it from all lists.
        """
        del IKBreakpoint.breakpoints_by_file_and_line[self.file_name, self.line_number]
        IKBreakpoint.breakpoints_by_number[self.number] = None
        IKBreakpoint.breakpoints_files[self.file_name].remove(self.line_number)
        if len(IKBreakpoint.breakpoints_files[self.file_name]) == 0:
            del IKBreakpoint.breakpoints_files[self.file_name]
        IKBreakpoint.update_active_breakpoint_flag()

    @classmethod
    def update_active_breakpoint_flag(cls):
        """ Checks all breakpoints to find wether at least one is active and 
        update `any_active_breakpoint` accordingly.
        """
        cls.any_active_breakpoint=any([bp.enabled for bp in cls.breakpoints_by_number if bp])

    @classmethod
    def lookup_effective_breakpoint(cls, file_name, line_number, frame):
        """ Checks if there is an enabled breakpoint at given file_name and 
        line_number. Check breakpoint condition if any.
        
        :return: found, enabled and condition verified breakpoint or None
        :rtype: IKPdbBreakpoint or None
        """
        bp = cls.breakpoints_by_file_and_line.get((file_name, line_number), None)
        if not bp:
            return None
            
        if not bp.enabled:
            return None
            
        if not bp.condition:
            return bp
        try:
            value = eval(bp.condition, frame.f_globals, frame.f_locals)
            return bp if value else None
        except:
            pass
        return None

    @classmethod
    def get_breakpoints_list(cls):
        """:return: a list of all breakpoints.
        :rtype: a list of dict with this keys: `breakpoint_number`, `bp.number`,
                `file_name`, `line_number`, `condition`, `enabled`.
                
        Warning: IKPDb line numbers are 1 based so line number conversion
        must be done by clients (eg. inouk.ikpdb for Cloud9)
        """
        breakpoints_list = []
        for bp in cls.breakpoints_by_number:
            if bp:  # breakpoint #0 exists and is always None
                bp_dict = {
                    'breakpoint_number': bp.number,
                    'file_name': bp.file_name,
                    'line_number': bp.line_number,
                    'condition': bp.condition,
                    'enabled': bp.enabled,
                }
                breakpoints_list.append(bp_dict)
        return breakpoints_list

    @classmethod
    def disable_all_breakpoints(cls):
        """ Disable all breakpoints and udate `active_breakpoint_flag`.
        """
        for bp in cls.breakpoints_by_number:
            if bp:  # breakpoint #0 exists and is always None
                bp.enabled = False
        cls.update_active_breakpoint_flag()
        return

    @classmethod
    def backup_breakpoints_state(cls):
        """ Returns the state of all breakpoints in a list that can be used
        later to restore all breakpoints state"""
        all_breakpoints_state = []
        for bp in cls.breakpoints_by_number:
            if bp: 
                all_breakpoints_state.append((bp.number, 
                                              bp.enabled, 
                                              bp.condition,))
        return all_breakpoints_state

    @classmethod
    def restore_breakpoints_state(cls, breakpoints_state_list):
        """Restore the state of breakpoints given a list provided by 
        backup_breakpoints_state(). If list of breakpoint has changed 
        since backup missing or added breakpoints are ignored.
        
        breakpoints_state_list is a list of tuple. Each tuple is of form:
        (breakpoint_number, enabled, condition)
        """
        for breakpoint_state in breakpoints_state_list:
            bp = cls.breakpoints_by_number[breakpoint_state[0]]
            if bp:
                bp.enabled = breakpoint_state[1]
                bp.condition = breakpoint_state[2]
        cls.update_active_breakpoint_flag()
        return

class IKPdb(object):
    """ Main debugger class.

    :param skip: reserved for future use
    :param working_directory: allows to force debugger's Current Working 
                              Directory (CWD). `working_directory` is used for file
                              mapping between IKPdb and clients. 
                              `working_directory` is concatenated with file path
                              exchanged with debugger's client to get absolute 
                              file's paths.
    :type working_directory: str
    :param stop_at_first_statement: defines wether debugger must break at
                                    first statement. None don't break, else break.
    :type stop_at_first_statement: str
        
    Take note that, right now, IKPdb is used as singleton.
    """
    
    def __init__(self, skip=None, stop_at_first_statement=False, working_directory=None, 
                 client_working_directory=None):
        # TODO: manage skip
        self.skip = set(skip) if skip else None
        
        self.debugger_thread_ident = None
        self.file_name_cache = {}        
        
        self._CWD = working_directory or os.getcwd()
        if self._CWD and self._CWD[-1] != '/':
            self._CWD += '/'

        self._CLIENT_CWD = client_working_directory or ''
        if self._CLIENT_CWD and self._CLIENT_CWD[-1] != '/':
            self._CLIENT_CWD += '/'
        
        self.mainpyfile = ''
        self._active_breakpoint_lock = threading.Lock()
        self._active_thread_lock = threading.Lock()
        self._command_q = multiprocessing.Queue(maxsize=1)

        # tracing is disabled until required 
        self.execution_started = False
        self.tracing_enabled = False

        # stop management
        self.pending_stop = False  # True if any of frame_xxxx is set
        self.frame_stop = None # stepOver and stepInto
        self.frame_calling = None  # stepInto
        self.frame_return = None  # stepOut and stepOver
        self.frame_suspend = False  # If true, debugger will stop at next frame
        
        # last frame to dump ; allows to dump only debugged program frames         
        self.frame_beginning = None
        
        # If True, debugger breaks on first line to allow user to setup 
        # some breakpoints.
        self.stop_at_first_statement = True if stop_at_first_statement else False
        
        # Some parameters that may need to become cli options
        self.CGI_ESCAPE_EVALUATE_OUTPUT = False


    def canonic(self, file_name):
        """ returns canonical version of a file name.
        A canonical file name is an absolute, lowercase normalized path 
        to a given file.
        """
        if file_name == "<" + file_name[1:-1] + ">":
            return file_name
        c_file_name = self.file_name_cache.get(file_name)
        if not c_file_name:
            c_file_name = os.path.abspath(file_name)
            c_file_name = os.path.normcase(c_file_name)
            self.file_name_cache[file_name] = c_file_name
        return c_file_name

    def normalize_path_in(self, client_file_name):
        """Translate a (possibly incomplete) file or module name received from debugging client
        into an absolute file name.
        """
        _logger.p_debug("normalize_path_in(%s) with os.getcwd()=>%s", client_file_name, os.getcwd())
        
        # remove client CWD from file_path
        if client_file_name.startswith(self._CLIENT_CWD):
            file_name = client_file_name[len(self._CLIENT_CWD):]
        else:
            file_name = client_file_name
        
        # Try to find file using it's absolute path
        if os.path.isabs(file_name) and os.path.exists(file_name):
            _logger.p_debug("  => found absolute path: '%s'", file_name)
            return file_name
            
        # Can we find the file relatively to launch CWD (useful with buildout)
        f = os.path.join(self._CWD, file_name)  
        if  os.path.exists(f):
            _logger.p_debug("  => found path relative to self._CWD: '%s'", f)
            return f

        # Can we find file relatively to launch script
        f = os.path.join(sys.path[0], file_name)  
        if os.path.exists(f) and self.canonic(f) == self.mainpyfile:
            _logger.p_debug("  => found path relative to launch script: '%s'", f)
            return f
            
        # Try as an absolute path after adding .py extension 
        root, ext = os.path.splitext(file_name)
        if ext == '':
            f = file_name + '.py'
        if os.path.isabs(f):
            _logger.p_debug("  => found absolute path after adding .py extension: '%s'", f)
            return f
        
        # Can we find the file in system path
        for dir_name in sys.path:
            while os.path.islink(dir_name):
                dir_name = os.readlink(dir_name)
            f = os.path.join(dir_name, file_name)
            if os.path.exists(f):
                _logger.p_debug("  => found path in sys.path: '%s'", f)
                return f
        return None

    def normalize_path_out(self, path):
        """Normalizes path sent to client
        :param path: path to normalize
        :return: normalized path
        """
        if path.startswith(self._CWD):
            normalized_path = path[len(self._CWD):]
        else:
            normalized_path = path
        # For remote debugging preprend client CWD
        if self._CLIENT_CWD:
            normalized_path = os.path.join(self._CLIENT_CWD, normalized_path)
        _logger.p_debug("normalize_path_out('%s') => %s", path, normalized_path)
        return normalized_path


    def object_properties_count(self, o):
        """ returns the number of user browsable properties of an object. """
        o_type = type(o)
        if isinstance(o, (dict, list, tuple, set)):
            return len(o)
        elif isinstance(o, (type(None), bool, float, 
                            str, int, 
                            bytes, types.ModuleType, 
                            types.MethodType, types.FunctionType)):
            return 0
        else:
            # Following lines are used to debug variables members browsing
            # and counting
            # if False and str(o_type) == "<class 'socket._socketobject'>":
            #     print "@378"
            #     print dir(o)
            #     print "hasattr(o, '__dict__')=%s" % hasattr(o,'__dict__')
            #     count = 0
            #     if hasattr(o, '__dict__'):
            #         for m_name, m_value in o.__dict__.iteritems():
            #             if m_name.startswith('__'):
            #                 print "    %s=>False" % (m_name,)
            #                 continue
            #             if type(m_value) in (types.ModuleType, types.MethodType, types.FunctionType,):
            #                 print "    %s=>False" % (m_name,)
            #                 continue
            #             print "    %s=>True" % (m_name,)
            #             count +=1
            #     print "    %s => %s = %s" % (o, count, dir(o),)
            # else:
            try:
                if hasattr(o, '__dict__'):
                    count = len([m_name for m_name, m_value in o.__dict__.items()
                                  if not m_name.startswith('__') 
                                    and not type(m_value) in (types.ModuleType, 
                                                              types.MethodType, 
                                                              types.FunctionType,) ])
                else:
                    count = 0
            except:
                # Thank you werkzeug __getattr__ overloading!
                count = 0
            return count

    def extract_object_properties(self, o, limit_size=False):
        """Extracts all properties from an object (eg. f_locals, f_globals, 
        user dict, instance ...) and returns them as an array of variables.
        """
        try:
            prop_str = repr(o)[:512]
        except:
            prop_str = "Error while extracting value"

        _logger.e_debug("extract_object_properties(%s)", prop_str)
        var_list = []
        if isinstance(o, dict):
            a_var_name = None
            a_var_value = None
            for a_var_name in o:
                a_var_value = o[a_var_name]
                children_count = self.object_properties_count(a_var_value)
                v_name, v_value, v_type = self.extract_name_value_type(a_var_name, 
                                                                       a_var_value, 
                                                                       limit_size=limit_size)
                a_var_info = {
                    'id': id(a_var_value),
                    'name': v_name,
                    'type': "%s%s" % (v_type, " [%s]" % children_count if children_count else '',),
                    'value': v_value,
                    'children_count': children_count,
                }
                var_list.append(a_var_info)
                
        elif type(o) in (list, tuple, set,):
            MAX_CHILDREN_TO_RETURN = 256
            MAX_CHILDREN_MESSAGE = "Truncated by ikpdb (don't hot change me !)."
            a_var_name = None
            a_var_value = None
            do_truncate = len(o) > MAX_CHILDREN_TO_RETURN
            for idx, a_var_value in enumerate(o):
                children_count = self.object_properties_count(a_var_value)
                v_name, v_value, v_type = self.extract_name_value_type(idx, 
                                                                       a_var_value, 
                                                                       limit_size=limit_size)
                var_list.append({
                    'id': id(a_var_value),
                    'name': v_name,
                    'type': "%s%s" % (v_type, " [%s]" % children_count if children_count else '',),
                    'value': v_value,
                    'children_count': children_count,
                })
                if do_truncate and idx==MAX_CHILDREN_TO_RETURN-1:
                    var_list.append({
                        'id': None,
                        'name': str(MAX_CHILDREN_TO_RETURN),
                        'type': '',
                        'value': MAX_CHILDREN_MESSAGE,
                        'children_count': 0,
                    })
                    break
        else:
            a_var_name = None
            a_var_value = None
            if hasattr(o, '__dict__'):
                for a_var_name, a_var_value in o.__dict__.items():
                    if (not a_var_name.startswith('__') 
                        and not type(a_var_value) in (types.ModuleType, 
                                                      types.MethodType, 
                                                      types.FunctionType,)):
                        children_count = self.object_properties_count(a_var_value)
                        v_name, v_value, v_type = self.extract_name_value_type(a_var_name,
                                                                               a_var_value, 
                                                                               limit_size=limit_size)
                        var_list.append({
                            'id': id(a_var_value),
                            'name': v_name,
                            'type': "%s%s" % (v_type, " [%s]" % children_count if children_count else '',),
                            'value': v_value,
                            'children_count': children_count,
                        })
        return var_list    
    
    def extract_name_value_type(self, name, value, limit_size=False):
        """Extracts value of any object, eventually reduces it's size and
        returns name, truncated value and type (for str with size appended)
        """
        MAX_STRING_LEN_TO_RETURN = 487
        try:
            t_value = repr(value)
        except:
            t_value = "Error while extracting value"

        # convert all var names to string
        if isinstance(name, str):
            r_name = name
        else:
            r_name = repr(name)

        # truncate value to limit data flow between ikpdb and client
        if len(t_value) > MAX_STRING_LEN_TO_RETURN:
            r_value = "%s ... (truncated by ikpdb)" % (t_value[:MAX_STRING_LEN_TO_RETURN],) 
            r_name = "%s*" % r_name  # add a visual marker to truncated var's name
        else:
            r_value = t_value
            
        if isinstance(value, str):
            r_type = "%s [%s]" % (IKPdbRepr(value), len(value),)
        else:
            r_type = IKPdbRepr(value)
            
        return r_name, r_value, r_type

    def dump_frames(self, frame):
        """ dumps frames chain in a representation suitable for serialization 
           and remote (debugger) client usage.
        """
        current_thread = threading.currentThread()
        frames = []
        frame_browser = frame
        
        # Browse the frame chain as far as we can
        _logger.f_debug("dump_frames(), frame analysis:")
        spacer = ""
        while hasattr(frame_browser, 'f_back') and frame_browser.f_back != self.frame_beginning:
            spacer += "="
            _logger.f_debug("%s>frame = %s, frame.f_code = %s, frame.f_back = %s, "
                            "self.frame_beginning = %s",
                            spacer,
                            hex(id(frame_browser)),
                            frame_browser.f_code,
                            hex(id(frame_browser.f_back)),
                            hex(id(self.frame_beginning)))

            # At root frame, globals == locals so we dump only globals
            if hasattr(frame_browser.f_back, 'f_back')\
                    and frame_browser.f_back.f_back != self.frame_beginning:
                locals_vars_list = self.extract_object_properties(frame_browser.f_locals,
                                                                  limit_size=True)
            else:
                locals_vars_list = []
                                
            globals_vars_list = self.extract_object_properties(frame_browser.f_globals,
                                                               limit_size=True)
            # normalize path sent to debugging client
            file_path = self.normalize_path_out(frame_browser.f_code.co_filename)

            frame_name = "%s() [%s]" % (frame_browser.f_code.co_name, current_thread.name,)
            remote_frame = {
                'id': id(frame_browser),
                'name': frame_name,
                'line_number': frame_browser.f_lineno,  # Warning 1 based
                'file_path': file_path,
                'thread': id(current_thread),
                'f_locals': locals_vars_list + globals_vars_list
            }
            frames.append(remote_frame)
            frame_browser = frame_browser.f_back
        return frames        

    def evaluate(self, frame_id, expression, global_context=False, disable_break=False):
        """Evaluates 'expression' in the context of the frame identified by
        'frame_id' or globally.
        Breakpoints are disabled depending on 'disable_break' value.
        Returns a tuple of value and type both as str.
        Note that - depending on the CGI_ESCAPE_EVALUATE_OUTPUT attribute - value is 
        escaped.
        """
        if disable_break:
            breakpoints_backup = IKBreakpoint.backup_breakpoints_state()
            IKBreakpoint.disable_all_breakpoints()

        if frame_id and not global_context:
            eval_frame = ctypes.cast(frame_id, ctypes.py_object).value
            global_vars = eval_frame.f_globals
            local_vars = eval_frame.f_locals
        else:
            global_vars = None
            local_vars = None

        try: 
            result = eval(expression, global_vars, local_vars)
            result_type = IKPdbRepr(result)
            result_value = repr(result)
        except SyntaxError:
            # eval() failed, try with exec to handle statements
            try:
                result = exec(expression, global_vars, local_vars)
                result_type = IKPdbRepr(result)
                result_value = repr(result)
            except Exception as e:
                t, result = sys.exc_info()[:2]
                if isinstance(t, str):
                    result_type = t
                else: 
                    result_type = str(t.__name__)
                result_value = "%s: %s" % (result_type, result,)
        except:
            t, result = sys.exc_info()[:2]
            if isinstance(t, str):
                result_type = t
            else: 
                result_type = t.__name__
            result_value = "%s: %s" % (result_type, result,)

        if disable_break:
            IKBreakpoint.restore_breakpoints_state(breakpoints_backup)

        _logger.e_debug("evaluate(%s) => result_value=%s, result_type=%s, result=%s", 
                        expression, 
                        result_value, 
                        result_type, 
                        result)
        if self.CGI_ESCAPE_EVALUATE_OUTPUT:
            result_value = cgi.escape(result_value)
        
        # We must check that result is json.dump compatible so that it can be sent back to client.
        try:
            json.dumps(result_value)
        except:
            t, result = sys.exc_info()[:2]
            if isinstance(t, str):
                result_type = t
            else: 
                result_type = t.__name__
            result_value = "<plaintext>%s: IKPdb is unable to JSON encode result to send it to "\
                           "debugging client.\n"\
                           "  This typically occurs if you try to print a string that cannot be"\
                           " decoded to 'UTF-8'.\n"\
                           "  You should be able to evaluate result and inspect it's content"\
                           " by removing the print statement." % result_type
        return result_value, result_type

    def let_variable(self, frame_id, var_name, expression_value):
        """ Let a frame's var with a value by building then eval a let 
        expression with breakoints disabled.
        """
        breakpoints_backup = IKBreakpoint.backup_breakpoints_state()
        IKBreakpoint.disable_all_breakpoints()

        let_expression = "%s=%s" % (var_name, expression_value,)

        eval_frame = ctypes.cast(frame_id, ctypes.py_object).value
        global_vars = eval_frame.f_globals
        local_vars = eval_frame.f_locals
        try:
            exec(let_expression, global_vars, local_vars)
            error_message=""
        except Exception as e:
            t, result = sys.exc_info()[:2]
            if isinstance(t, str):
                result_type = t
            else: 
                result_type = str(t.__name__)
            error_message = "%s: %s" % (result_type, result,)

        IKBreakpoint.restore_breakpoints_state(breakpoints_backup)

        _logger.e_debug("let_variable(%s) => %s", 
                        let_expression, 
                        error_message or 'succeed')
        return error_message

    def setup_step_over(self, frame):
        """Setup debugger for a "stepOver"
        """
        self.frame_calling = None
        self.frame_stop = frame
        self.frame_return = frame.f_back
        self.frame_suspend = False
        self.pending_stop = True 
        return

    def setup_step_into(self, frame, pure=False):
        """Setup debugger for a "stepInto"
        """
        self.frame_calling = frame
        if pure:
            self.frame_stop = None
        else:
            self.frame_stop = frame
        self.frame_return = None
        self.frame_suspend = False
        self.pending_stop = True 
        return

    def setup_step_out(self, frame):
        """Setup debugger for a "stepOut"
        """
        self.frame_calling = None
        self.frame_stop = None
        self.frame_return = frame.f_back
        self.frame_suspend = False
        self.pending_stop = True 
        return

    def setup_suspend(self):
        """Setup debugger to "suspend" execution
        """
        self.frame_calling = None
        self.frame_stop = None
        self.frame_return = None
        self.frame_suspend = True
        self.pending_stop = True
        self.enable_tracing()
        return

    def setup_resume(self):
        """ Setup debugger to "resume" execution
        """
        self.frame_calling = None
        self.frame_stop = None
        self.frame_return = None
        self.frame_suspend = False
        self.pending_stop = False
        if not IKBreakpoint.any_active_breakpoint:
            self.disable_tracing()
        return

    def reset(self):
        """ Resets debugger status and set it to run.
        """
        import linecache
        linecache.checkcache()
        self.frame_beginning = None
        self.setup_resume()

    def should_stop_here(self, frame):
        """ Called by dispatch function to check wether debugger must stop at
        this frame.
        Note that we test 'step into' first to give a chance to 'stepOver' in
        case user click on 'stepInto' on a 'no call' line.
        """
        # TODO: Optimization => defines a set of modules / names where _tracer
        # is never registered. This will replace skip
        #if self.skip and self.is_skipped_module(frame.f_globals.get('__name__')):
        #    return False

        # step into
        if self.frame_calling and self.frame_calling==frame.f_back:
            return True
        # step over
        if frame==self.frame_stop:  # frame cannot be null
            return True
        # step out
        if frame==self.frame_return:  # frame cannot be null
            return True
        # suspend
        if self.frame_suspend:
            return True

        return False

    def should_break_here(self, frame):
        """ Check if there is a breakpoint at this frame or not.
        """
        #_logger.b_debug("should_break_here(filename=%s, lineno=%s) with breaks=%s",
        #                frame.f_code.co_filename,
        #                frame.f_lineno,
        #                IKBreakpoint.breakpoints_by_number)
        
        c_file_name = self.canonic(frame.f_code.co_filename)
        if not c_file_name in IKBreakpoint.breakpoints_files:
            return False
        bp = IKBreakpoint.lookup_effective_breakpoint(c_file_name, 
                                                      frame.f_lineno, 
                                                      frame)
        return True if bp else False

    def _line_tracer(self, frame, exc_info=False):
        """This function is called when debugger has decided that we must
        stop or break at this frame."""
        
        # next logging statement commented for performance
        _logger.f_debug("user_line() with " 
                        "threadName=%s, frame=%s, frame.f_code=%s, self.mainpyfile=%s,"
                        "self.should_break_here()=%s, self.should_stop_here()=%s\n",
                         threading.currentThread().name,
                         hex(id(frame)),
                         frame.f_code,
                         self.mainpyfile,
                         self.should_break_here(frame),
                         self.should_stop_here(frame))
                      
        # Acquire Breakpoint Lock before sending break command to remote client
        self._active_breakpoint_lock.acquire()
        frames = self.dump_frames(frame)
        exception=None
        warning_messages = []

        if exc_info:
            exception = {
                'type': IKPdbRepr(exc_info[1]),
                'info': str(exc_info[1].args[0])
            }

        if self.stop_at_first_statement:
            warning_messages = ["IKPdb stopped so that you can setup some "
                                "breakpoints before 'Resuming' execution."]
            self.stop_at_first_statement = False

        remote_client.send('programBreak', 
                           frames=frames,
                           result={'executionStatus': 'stopped'},
                           warning_messages=warning_messages,
                           exception=exception)
                           
        # Enter a loop to process commands sent by client
        while True:
            command = self._command_q.get()
            if command['cmd'] == 'resume':
                self.setup_resume()
                break
            
            elif command['cmd'] == 'stepOver':
                self.setup_step_over(frame)
                break
            
            elif command['cmd'] == 'stepInto':
                self.setup_step_into(frame)
                break
            
            elif command['cmd'] == 'stepOut':
                self.setup_step_out(frame)
                break
            
            elif command['cmd'] == 'evaluate':
                value, result_type = self.evaluate(command['frame'], 
                                                   command['expression'], 
                                                   command['global'], 
                                                   disable_break=command['disableBreak'])
                remote_client.reply(command['obj'], {'value': value, 'type': result_type})

            elif command['cmd'] == 'getProperties':
                error_messages = []
                if command.get('id', False):
                    po_value = ctypes.cast(command['id'], ctypes.py_object).value
                    result={'properties': self.extract_object_properties(po_value) or []}
                    command_exec_status = 'ok'
                else:
                    result={'properties': self.extract_object_properties(None) or []}
                    command_exec_status = 'ok'
                    
                _logger.e_debug("    => %s", result)
                remote_client.reply(command['obj'], result, 
                                    command_exec_status=command_exec_status,
                                    error_messages=error_messages)

            elif command['cmd'] == 'setVariable':
                error_messages = []
                result = {}
                command_exec_status = 'ok'
                # TODO: Rework to use id now that we are in right thread context
                err_message = self.let_variable(command['frame'], 
                                                command['name'], 
                                                command['value'])
                if err_message:
                    command_exec_status = 'error'
                    msg = "setVariable(%s=%s) failed with error: %s" % (command['name'], 
                                                                        command['value'],
                                                                        err_message)
                    error_messages = [msg]
                    _logger.e_error(msg)
                remote_client.reply(command['obj'], 
                                    result,
                                    command_exec_status=command_exec_status,
                                    error_messages=error_messages)

            else:
                _logger.x_critical("Unknown command: %s received by _line_tracer()" % resume_command)
                raise IKPdbQuit()

        self._active_breakpoint_lock.release()
        return

    def _tracer(self, frame, event, arg):
        if event == 'line':
            
            # For the sake of performande, we inline following code in
            # this method. 
            # Code of these methods is still there for reference.
            #
            #if self.should_stop_here(frame) or self.should_break_here(frame):
            #    self._line_tracer(frame)
            # return self._tracer

            # should_stop_here() inlined version
            if self.pending_stop and (
                (self.frame_calling and self.frame_calling==frame.f_back)
                        or frame==self.frame_stop
                        or frame==self.frame_return
                        or self.frame_suspend
                        or self.should_break_here(frame)):
                self._line_tracer(frame)
            
            # self.should_break_here() inlined version 
            c_file_name = self.canonic(frame.f_code.co_filename)  # TODO inline this too !!!
            if c_file_name in IKBreakpoint.breakpoints_files:
                if IKBreakpoint.lookup_effective_breakpoint(c_file_name, 
                                                            frame.f_lineno,
                                                            frame):
                    self._line_tracer(frame)
            return self._tracer
        
        if event == 'call':
            if self.frame_beginning is None:  
                # As this is First call of dispatch since reset() we setup
                # frame_beginning
                self.frame_beginning = frame.f_back
                
                # limited tracing of current thread has been enabled in _runscript
                # to allow self.frame_beginning to be set. That's done !
                #
                # Now depending on pending_stop and stop_at_first_statement 
                # we enable full tracing or disable it completely by removing 
                # the tracer.
                if self.stop_at_first_statement:
                    self.setup_step_into(frame, pure=True)
                if self.pending_stop or IKBreakpoint.any_active_breakpoint:
                    self.enable_tracing()
                else:
                    sys.settrace(None)  # we remove limited tracing
            return self._tracer
        
        # Note that event = 'return', returned value is ignored
        # TODO: Use event = 'exception' to trace exception
        return self._tracer

    def dump_tracing_state(self, context):
        """ A debug tool to dump all threads tracing state 
        """
        print("Dumping all threads Tracing state: (%s)" % context)
        print("    self.tracing_enabled=%s" % self.tracing_enabled)
        print("    self.execution_started=%s" % self.execution_started)
        print("    self.frame_beginning=%s" % self.frame_beginning)
        print("    self.debugger_thread_ident=%s" % self.debugger_thread_ident)
        for thr in threading.enumerate():
            is_current_thread = thr.ident == threading.current_thread().ident
            print("    Thread: %s, %s %s" % (thr.name, thr.ident, "<= Current*" if is_current_thread else ''))
            a_frame = sys._current_frames()[thr.ident]
            while a_frame:
                flags = []
                if a_frame == self.frame_beginning:
                    flags.append("beginning")
                if a_frame == inspect.currentframe():
                    flags.append("current")
                if flags:
                    flags_str = "**"+",".join(flags)
                else:
                    flags_str = ""
                print("        => %s, %s:%s(%s) | %s %s" % (a_frame, 
                                                            a_frame.f_code.co_filename, 
                                                            a_frame.f_lineno,
                                                            a_frame.f_code.co_name, 
                                                            a_frame.f_trace,
                                                            flags_str))
                a_frame = a_frame.f_back

    def enable_tracing(self):
        """ Enable tracing if it is disabled and debugged program is running, 
        else do nothing.
        Do this on all threads but the debugger thread.
        :return: True if tracing has been enabled, False else.
        """
        _logger.x_debug("enable_tracing()")
        #self.dump_tracing_state("before enable_tracing()")
        if not self.tracing_enabled and self.execution_started:
            # Restore or set trace function on all existing frames appart from 
            # debugger
            threading.settrace(self._tracer)  # then enable on all threads to come
            for thr in threading.enumerate():
                if thr.ident != self.debugger_thread_ident:  # skip debugger thread
                    a_frame = sys._current_frames()[thr.ident]
                    while a_frame:
                        a_frame.f_trace = self._tracer
                        a_frame = a_frame.f_back
            iksettrace3._set_trace_on(self._tracer, self.debugger_thread_ident)
            self.tracing_enabled = True
        
        #self.dump_tracing_state("after enable_tracing()")
        return self.tracing_enabled

    def disable_tracing(self):
        """ Disable tracing if it is disabled and debugged program is running, 
        else do nothing.

        :return: False if tracing has been disabled, True else.
        """
        _logger.x_debug("disable_tracing()")
        #self.dump_tracing_state("before disable_tracing()")
        if self.tracing_enabled and self.execution_started:
            threading.settrace(None)  # don't trace threads to come
            iksettrace3._set_trace_off()
            self.tracing_enabled = False
        #self.dump_tracing_state("after disable_tracing()")
        return self.tracing_enabled

    def set_breakpoint(self, file_name, line_number, condition=None, enabled=True):
        """ Create a breakpoint, register it in the class's lists and returns
        a tuple of (error_message, break_number)
        """
        c_file_name = self.canonic(file_name)
        import linecache
        line = linecache.getline(c_file_name, line_number)
        if not line:
            return "Line %s:%d does not exist." % (c_file_name, line_number), None
        bp = IKBreakpoint(c_file_name, line_number, condition, enabled)
        if self.pending_stop or IKBreakpoint.any_active_breakpoint:
            self.enable_tracing()
        else:
            self.disable_tracing()
        return None, bp.number

    def change_breakpoint_state(self, bp_number, enabled, condition=None):
        """ Change breakpoint status or `condition` expression.
        
        :param bp_number: number of breakpoint to change 
        :return: None or an error message (string)
        """
        if not (0 <= bp_number < len(IKBreakpoint.breakpoints_by_number)):
            return "Found no breakpoint numbered: %s" % bp_number
        bp = IKBreakpoint.breakpoints_by_number[bp_number]
        if not bp:
            return "Found no breakpoint numbered %s" % bp_number
        _logger.b_debug("    change_breakpoint_state(bp_number=%s, enabled=%s, "
                        "condition=%s) found %s", 
                        bp_number,
                        enabled,
                        repr(condition),
                        bp)
        bp.enabled = enabled
        bp.condition = condition  # update condition for conditional breakpoints
        IKBreakpoint.update_active_breakpoint_flag()  # force flag refresh
        if self.pending_stop or IKBreakpoint.any_active_breakpoint:
            self.enable_tracing()
        else:
            self.disable_tracing()
        return None

    def clear_breakpoint(self, breakpoint_number):
        """ Delete a breakpoint identified by it's number. 
        
        :param breakpoint_number:  index of breakpoint to delete
        :type breakpoint_number: int
        :return: an error message or None
        """
        if not (0 <= breakpoint_number < len(IKBreakpoint.breakpoints_by_number)):
            return "Found no breakpoint numbered %s" % breakpoint_number
        bp = IKBreakpoint.breakpoints_by_number[breakpoint_number]
        if not bp:
            return "Found no breakpoint numbered: %s" % breakpoint_number
        _logger.b_debug("    clear_breakpoint(breakpoint_number=%s) found: %s",
                        breakpoint_number,
                        bp)
        bp.clear()
        if self.pending_stop or IKBreakpoint.any_active_breakpoint:
            self.enable_tracing()
        else:
            self.disable_tracing()
        return None

    def _runscript(self, filename):
        """ Launchs debugged program execution using the execfile() builtin.
            
        We reset and setup the __main__ dict to allow the script to run
        in __main__ namespace. This is required for imports from __main__ to 
        run correctly.
        
        Note that this has the effect to wipe IKPdb's vars created at this point.
        """
        import __main__
        __main__.__dict__.clear()
        __main__.__dict__.update({"__name__"    : "__main__",
                                  "__file__"    : filename,
                                  "__builtins__": __builtins__,})

        self.mainpyfile = self.canonic(filename)
        #statement = 'execfile(%r)\n' % filename
        statement = "exec(compile(open('%s').read(), '%s', 'exec'))" % (filename, filename,)
        
        globals = __main__.__dict__
        locals = globals

        # When IKPdb sets tracing, a number of call and line events happens
        # BEFORE debugger even reaches user's code (and the exact sequence of
        # events depends on python version). So we take special measures to
        # avoid stopping before we reach the main script (see reset(),
        # _tracer() and _line_tracer() methods for details).
        self.reset()
        self.execution_started = True

        # Turn on limited tracing by setting trace function for 
        # current_thread only. This allow self.frame_beginning to be set at
        # first tracer "call" invocation.
        sys.settrace(self._tracer)

        try:
            exec(statement, globals, locals)
        except IKPdbQuit:
            pass
        finally:
            self.disable_tracing()        
        
    def command_loop(self, run_script_event):
        """ return 1 to exit command_loop and resume execution 
        """
        while True:
            obj = remote_client.receive()
            command = obj["command"]  # TODO: ensure we always have a command if receive returns
            args = obj.get('args', {})
        
            if command == 'getBreakpoints':
                breakpoints_list = IKBreakpoint.get_breakpoints_list()
                remote_client.reply(obj, breakpoints_list)
                _logger.b_debug("getBreakpoints(%s) => %s", args, breakpoints_list)
                
            elif command == "setBreakpoint":
                # Set a new breakpoint. If the lineno line doesn't exist for the
                # filename passed as argument, return an error message. €
                # The filename should be in canonical form, as described in the 
                # canonic() method.
                file_name = args['file_name']
                line_number = args['line_number']
                condition = args.get('condition', '')
                enabled = args.get('enabled', True)
                _logger.b_debug("setBreakpoint(file_name=%s, line_number=%s,"
                                " condition=%s, enabled=%s) with CWD=%s",
                                file_name,
                                line_number,
                                condition,
                                enabled,
                                os.getcwd())
                
                error_messages = []
                result = {}

                c_file_name = self.normalize_path_in(file_name)
                if not c_file_name:
                    err = "Failed to find file '%s'" % file_name
                    _logger.g_error("setBreakpoint error: %s", err)
                    msg = "IKPdb error: Failed to set a breakpoint at %s:%s "\
                          "(%s)." % (file_name, line_number, err)
                    error_messages = [msg]
                    command_exec_status = 'error'
                else:                        
                    err, bp_number = self.set_breakpoint(c_file_name, 
                                                         line_number, 
                                                         condition=condition,
                                                         enabled=enabled)
                    if err:
                        _logger.g_error("setBreakpoint error: %s", err)
                        msg = "IKPdb error: Failed to set a breakpoint at %s:%s "\
                              "(%s)." % (file_name, line_number, err,)
                        error_messages = [msg]
                        command_exec_status = 'error'
                    else:
                        result = {'breakpoint_number': bp_number}
                        command_exec_status = 'ok'
                remote_client.reply(obj, result, 
                                    command_exec_status=command_exec_status,
                                    error_messages=error_messages)
            
            elif command == "changeBreakpointState":
                # Allows to:
                #  - activate or deactivate breakpoint 
                #  - set or remove condition
                _logger.b_debug("changeBreakpointState(%s)", args)
                bp_number = args.get('breakpoint_number', None)
                if bp_number is None:
                    result = {}
                    msg = "changeBreakpointState() error: missing required " \
                          "breakpointNumber parameter."
                    _logger.g_error("    "+msg)
                    error_messages = [msg]
                    command_exec_status = 'error'
                else:
                    err = self.change_breakpoint_state(bp_number,
                                                       args.get('enabled', False), 
                                                       condition=args.get('condition', ''))
                    result = {}
                    error_messages = []
                    if err:
                        msg = "changeBreakpointState() error: \"%s\"" % err
                        _logger.g_error("    "+msg)
                        error_messages = [msg]
                        command_exec_status = 'error'
                    else:
                        command_exec_status = 'ok'
                remote_client.reply(obj, result, 
                                    command_exec_status=command_exec_status,
                                    error_messages=error_messages)
                _logger.b_debug("    command_exec_status => %s", command_exec_status)

            elif command == "clearBreakpoint":
                _logger.b_debug("clearBreakpoint(%s)", args)
                bp_number = args.get('breakpoint_number', None)
                if bp_number is None:
                    result = {}
                    msg = "IKPdb error: Failed to delete breakpoint (Missing "\
                          "required breakpointNumber parameter)."
                    error_messages = [msg]
                    command_exec_status = 'error'
                else:
                    err = self.clear_breakpoint(args['breakpoint_number'])
                    result = {}
                    error_messages = []
                    if err:
                        msg = "IKPdb error: Failed to delete breakpoint (%s)." % err
                        _logger.g_error(msg)
                        error_messages = [msg]
                        command_exec_status = 'error'
                    else:
                        command_exec_status = 'ok'
                remote_client.reply(obj, result, 
                                    command_exec_status=command_exec_status,
                                    error_messages=error_messages)
            
            elif command == "getProperties":
                _logger.e_debug("getProperties(%s)", args)
                self._command_q.put({
                    'cmd':'getProperties',
                    'obj': obj,
                    'id': args['id']
                })
                # reply will be done in _tracer() when result is available

            elif command == "setVariable":
                _logger.e_debug("setVariable(%s)", args)
                self._command_q.put({
                    'cmd':'setVariable',
                    'obj': obj,
                    'frame': args['frame'],
                    'name': args['name'],  # TODO: Rework plugin to send var's id
                    'value': args['value']
                })
                # reply will be done in _tracer() when result is available

            elif command == 'runScript':
                _logger.x_debug("runScript(%s)", args)
                #TODO: handle a 'stopAtEntry' arg
                run_script_event.set()
                remote_client.reply(obj, {'executionStatus': 'running'})

            elif command == 'suspend':
                _logger.x_debug("suspend(%s)", args)
                self.setup_suspend()
                # We return a running status which is True at that point. Next 
                # programBreak will change status to 'stopped'
                remote_client.reply(obj, {'executionStatus': 'running'})
                
            elif command == 'resume':
                _logger.x_debug("resume(%s)", args)
                remote_client.reply(obj, {'executionStatus': 'running'})
                self._command_q.put({'cmd':'resume'})

            elif command == 'stepOver':  # <=> Pdb n(ext)
                _logger.x_debug("stepOver(%s)", args)
                remote_client.reply(obj, {'executionStatus': 'running'})
                self._command_q.put({'cmd':'stepOver'})

            elif command == 'stepInto':  # <=> Pdb s(tep)
                _logger.x_debug("stepInto(%s)", args)
                remote_client.reply(obj, {'executionStatus': 'running'})
                self._command_q.put({'cmd':'stepInto'})

            elif command == 'stepOut':  # <=> Pdb r(eturn)
                _logger.x_debug("stepOut(%s)", args)
                remote_client.reply(obj, {'executionStatus': 'running'})
                self._command_q.put({'cmd':'stepOut'})

            elif command == 'evaluate':
                _logger.e_debug("evaluate(%s)", args)
                if self.tracing_enabled:
                    self._command_q.put({
                        'cmd':'evaluate',
                        'obj': obj,
                        'frame': args['frame'],
                        'expression': args['expression'],
                        'global': args['global'],
                        'disableBreak': args['disableBreak']
                    })
                    # reply will be done in _tracer() where result is available
                else:
                    remote_client.reply(obj, {'value': None, 'type': None})
                    
                
            elif command == '_InternalQuit':
                # '_InternalQuit' is an IKPdb internal message, generated by 
                # IKPdbConnectionHandler when a socket.error occured.
                # Usually this occurs when socket has been destroyed as 
                # debugged program sys.exit()
                # So we leave the command loop to stop the debugger thread
                # in order to allow debugged program to shutdown correctly.
                # This message must NEVER be send by remote client.
                _logger.e_debug("_InternalQuit(%s)", args)
                return
            
            else: # unrecognized command ; just log and ignored
                _logger.g_critical("Unsupported command '%s' ignored.", command)

            if IKPdbLogger.enabled:
                _logger.b_debug("Current breakpoints list [any_active_breakpoint=%s]:", 
                                IKBreakpoint.any_active_breakpoint) 
                _logger.b_debug("    IKBreakpoint.breakpoints_by_file_and_line:")
                if not IKBreakpoint.breakpoints_by_file_and_line:
                    _logger.b_debug("        <empty>") 
                for file_line, bp in list(IKBreakpoint.breakpoints_by_file_and_line.items()):
                    _logger.b_debug("        %s => #%s, enabled=%s, condition=%s, %s", 
                                    file_line,
                                    bp.number,
                                    bp.enabled,
                                    repr(bp.condition),
                                    bp)
                _logger.b_debug("    IKBreakpoint.breakpoints_files = %s", 
                                IKBreakpoint.breakpoints_files)
                _logger.b_debug("    IKBreakpoint.breakpoints_by_number = %s", 
                                IKBreakpoint.breakpoints_by_number)

        
def set_trace(a_frame=None):
    """ Breaks on the line that invoked this function or at given frame.
    User can then resume execution.
    
    To call set_trace() use:
    
    .. code-block:: python

        import ikp3db ; ikp3db.set_trace()

    :param a_frame: The frame at which to break on.
    :type a_frame: frame
    
    :return: An error message or None is everything went fine.
    :rtype: str or None

    """
    if not ikpdb:
        return "Error: IKPdb must be launched before calling ikpd.set_trace()."

    if a_frame is None:
        a_frame = sys._getframe().f_back
    ikpdb._line_tracer(a_frame)
    return None

def post_mortem(trace_back=None, exc_info=None):
    """ Breaks on a traceback and send all execution information to the debugger 
    client. If the interpreter is handling an exception at this traceback, 
    exception information is sent to _line_tracer() which will transmit it to 
    the debugging client.
    Caller can also pass an *exc_info* that will be used to extract exception
    information. If passed exc_info has precedence over traceback.

    This method is useful for integrating with systems that manage exceptions. 
    Using it, you can setup a developer mode where unhandled exceptions 
    are sent to the developer.
    
    Once user resumes execution, control is returned to caller. IKPdb is 
    just used to "pretty" display the execution environement.
    
    To call post_mortem() use:
    
    .. code-block:: python

        import ikp3db
        ...
        ikp3db.postmortem(any_traceback) 
    
    
    :param trace_back: The traceback at which to break on.
    :type trace_back: traceback
    
    :param exc_info: Complete description of the raised Exception as 
                     returned by sys.exc_info.
    :type exc_info: tuple
    
    :return: An error message or None is everything went fine.
    :rtype: str or None
    """
    if not ikpdb:
        return "Error: IKPdb must be launched before calling ikpd.post_mortem()."
    
    if exc_info:
        trace_back = exc_info[2]
    elif trace_back and not exc_info:
        if sys.exc_info()[2] == trace_back:
            exc_info = sys.exc_info()
    else:
        return "missing parameter trace_back or exc_info"

    pm_traceback = trace_back
    while pm_traceback.tb_next:
        pm_traceback = pm_traceback.tb_next      
    ikpdb._line_tracer(pm_traceback.tb_frame, exc_info=exc_info)
    _logger.g_info("Post mortem processing finished.")
    return None

##
# Signal Handler to properly close socket connection
#
SIGNALS_DICT = dict((k, v) for v, k in reversed(sorted(signal.__dict__.items()))
                if v.startswith('SIG') and not v.startswith('SIG_'))

def close_connection():
    try:
        if client_connection:
            _logger.g_debug("Closing open connection...")
            # Cf. https://docs.python.org/2/howto/sockets.html#disconnecting
            client_connection.shutdown(socket.SHUT_RDWR)
            client_connection.close()
            _logger.g_debug("Connection closed...")
    except NameError:
        pass
    
# On SIGINT, SIGTERM shutdown socket and close connection
# (SIGKILL cannot be caught)
def signal_handler(signal, frame):
    print("%s received" % SIGNALS_DICT[signal])
    close_connection()
    # Cf. http://tldp.org/LDP/abs/html/exitcodes.html
    sys.exit(128+signal)
    

##
# main
#
def main():

    parser = argparse.ArgumentParser(description="IKPdb %s - Inouk Python Debugger for CPython 2.7" % __version__,
                                     epilog="Copyright (c) 2016, 2017, 2018 by Cyril MORISSE, Audaxis")
    parser.add_argument("-ik_a","--ikpdb-address", 
                        default='127.0.0.1',
                        dest="IKPDB_ADDRESS",
                        help="Network address on which debugger runs.")
    parser.add_argument("-ik_p","--ikpdb-port",
                        type=int, 
                        default=15470,
                        dest="IKPDB_PORT",
                        help="Network port on which debugger runs.")
    parser.add_argument("-ik_l", "--ikpdb-log",
                        dest="IKPDB_LOG",
                        default='',
                        help="Logger command string.")
    parser.add_argument("-ik_w", "--ikpdb-welcome",
                        dest="IKPDB_SEND_WELCOME_MESSAGE",
                        default=True,
                        help="Send a Welcome 'start' message at client connection.")
    parser.add_argument("-ik_s", "--ikpdb-stop-at-entry",
                        dest="IKPDB_STOP_AT_ENTRY",
                        default=None,
                        help="Break on debugged program first statement.")
    parser.add_argument("-ik_cwd", "--ikpdb-working-directory",
                        dest="IKPDB_WORKING_DIRECTORY",
                        default=None,
                        help="Allows to force debugger's Current Working Directory (CWD)")
    parser.add_argument("-ik_ccwd", "--ikpdb-client-working-directory",
                        dest="IKPDB_CLIENT_WORKING_DIRECTORY",
                        default=None,
                        help="Allows to force debugger's _client_ Current Working Directory. Useful "
                             "for remote debugging.")
    parser.add_argument("script_command_args",
                        metavar="scriptfile [args]",
                        help="Debugged script followed by all his args.",
                        nargs=argparse.REMAINDER)
    cmd_line_args = parser.parse_args()
    
    _logger.setup(cmd_line_args.IKPDB_LOG)

    # We modify sys.argv to reflect command line of
    # debugged script with all IKPdb args removed
    sys.argv = cmd_line_args.script_command_args

    _logger.g_info("IKP3db %s - Inouk Python Debugger for CPython 3.6+", __version__)
    _logger.g_debug("  interpreter: '%s'", sys.executable)
    _logger.g_debug("  args: %s", cmd_line_args)
    _logger.g_debug("  starts debugging: '%s'", " ".join(sys.argv))
    _logger.g_debug("  CWD: '%s'", os.getcwd())
    if cmd_line_args.IKPDB_WORKING_DIRECTORY:
        _logger.g_debug("  Working Directory forced to: '%s'", 
                        cmd_line_args.IKPDB_WORKING_DIRECTORY)
    if cmd_line_args.IKPDB_CLIENT_WORKING_DIRECTORY:
        _logger.g_debug("  CLIENT Working Directory set to: '%s'", 
                        cmd_line_args.IKPDB_CLIENT_WORKING_DIRECTORY)

    if not sys.argv[0:]:
        print("Error: scriptfile argument is required")
        sys.exit(2)

    # By using argparse.REMAINDER, sys.argv reflects command line of
    # debugged script with all IKPdb args removed
    mainpyfile =  sys.argv[0]     # Get script filename
    _logger.g_debug("  mainpyfile = '%s'", mainpyfile)
    if not os.path.exists(mainpyfile):
        print('Error:', mainpyfile, 'does not exist')
        sys.exit(1)

    # sets up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # no longer required
    # del sys.argv[0]         # Hide "ikpdb.py" from argument list

    # Replace ikpdb's dir with script's dir in front of module search path.
    sys.path[0] = os.path.dirname(mainpyfile)

    # Note on saving/restoring sys.argv: it's a good idea when sys.argv was
    # modified by the script being debugged. It's a bad idea when it was
    # changed by the user from the command line.
    
    # Initialize IKPdb listening socket
    debug_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    debug_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # http://stackoverflow.com/questions/4465959/python-errno-98-address-already-in-use?lq=1
    debug_socket.bind((cmd_line_args.IKPDB_ADDRESS, cmd_line_args.IKPDB_PORT,))

    _logger.g_info('IKP3db listening on %s:%s', cmd_line_args.IKPDB_ADDRESS, cmd_line_args.IKPDB_PORT)
    debug_socket.listen(1)  # 1 connection max
    
    # Wait for a connection
    global client_connection
    client_connection, client_address = debug_socket.accept()
    _logger.g_info("Connected with %s:%s", client_address[0], client_address[1])  
    # TODO: Redirect sdtout and stderr to a cloud9 windows ??

    # setup remote client connection
    global remote_client
    remote_client = IKPdbConnectionHandler(client_connection)  
    
    global ikpdb
    ikpdb = IKPdb(stop_at_first_statement=cmd_line_args.IKPDB_STOP_AT_ENTRY,
                  working_directory=cmd_line_args.IKPDB_WORKING_DIRECTORY,
                  client_working_directory=cmd_line_args.IKPDB_CLIENT_WORKING_DIRECTORY)

    if cmd_line_args.IKPDB_SEND_WELCOME_MESSAGE:  
        remote_client.send("start", info_messages=["Welcome to", "IKPdb", __version__])

    # Launch debugging
    try:
        ikpdb.mainpyfile = mainpyfile
        
        run_script_event = threading.Event()
        debugger_thread = threading.Thread(target=ikpdb.command_loop,
                                           name='IKPdbCommandLoop',
                                           args=(run_script_event,))
        
        debugger_thread.start()
        ikpdb.debugger_thread_ident = debugger_thread.ident
        run_script_event.wait()  # Wait for client to run script
        ikpdb._runscript(mainpyfile)
        remote_client.send('programEnd', 
                           result={'exit_code': None, 
                                   'executionStatus': 'terminated'})
        _logger.g_info("Program terminated with no exit value.")

    except SystemExit:
        # In most cases SystemExit does not warrant a post-mortem session.
        exit_code = sys.exc_info()[1].code
        _logger.g_info("Program exited with exit code: %s.", exit_code)

        # Connection may have been closed
        try:
            remote_client.send('programEnd', 
                               result={'exit_code': exit_code, 
                                       'executionStatus': 'terminated'})
        except:
            pass
        close_connection()
        sys.exit(exit_code)
        
    except SyntaxError:
        # Python detected a syntax error while running or launching program 
        # to debug.
        traceback.print_exc()
        close_connection()
        sys.exit(1)  # 1 = General error
        
    except:
        traceback.print_exc()
        _logger.g_info("Uncaught exception. Entering post mortem debugging")
        pm_traceback = sys.exc_info()[2]
        while pm_traceback.tb_next:
            pm_traceback = pm_traceback.tb_next      
        
        ikpdb._line_tracer(pm_traceback.tb_frame, exc_info=sys.exc_info())
        
        try:
            remote_client.send('programEnd', 
                               result={'exit_code': None, 
                                       'executionStatus': 'terminated'})
        except:
            pass
        
        _logger.g_info("Post mortem debugger finished.")
        close_connection()
        debugger_thread.join()
        sys.exit(1)

    finally:
        sys.exit(0)


# When invoked as main program, invoke the debugger on a script
if __name__ == '__main__':
    import ikp3db
    ikp3db.main()
