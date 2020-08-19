#!/usr/bin/python
import sys
import signal
import os
from keystone import *

def pbold(bold_str):
    return ('\033[1m' + bold_str + '\033[0m')
def pyellow(yellow_str):
    return ('\033[93m' + yellow_str + '\033[0m')
def pred(red_str):
    return ('\033[31m' + red_str + '\033[0m')
def pblue(blue_str):
    return ('\033[96m' + blue_str + '\033[0m')
def pblaze(blaze_str):
    return ('\033[92m\033[1m' + blaze_str + '\033[0m')
def punder(underline_str):
    return ('\033[4m' + underline_str + '\033[0m')
def perror(error_str):
    print pred("Error ") + error_str    
def pinfo(info_str):
    print pyellow("Info ") + info_str
                       
BANNER = 'Blaze -- Interactive assembler that '+ pblaze('blazes ') + 'bad bytes.'

ks_asm_arch = {
    'arm'    :   [KS_ARCH_ARM, KS_MODE_ARM],
    'arm64'  :   [KS_ARCH_ARM64, KS_MODE_ARM],
    'thumb'  :   [KS_ARCH_ARM, KS_MODE_THUMB],
    'mips32' :   [KS_ARCH_MIPS, KS_MODE_MIPS32],
    'mips64' :   [KS_ARCH_MIPS, KS_MODE_MIPS64],
    'ppc32'  :   [KS_ARCH_PPC, KS_MODE_PPC32],
    'ppc64'  :   [KS_ARCH_PPC, KS_MODE_PPC64],
}

ks_endian = {
    'little': (KS_MODE_LITTLE_ENDIAN),
    'big' : (KS_MODE_BIG_ENDIAN)
}

blaze_cmds = {
    ':config' : 'Current ' + pblaze('blaze ') + 'configuration',
    ':sbb'    : 'Set blaze bytes (in decimal)',
    ':rbb'    : 'Reset blaze bytes',
    ':dbb'    : 'Display blaze bytes (in decimal)',
    ':arch'   : 'Change architecture (:arch for arch list)',
    ':endian' : 'Change endianness',
    ':help'   : 'Display \'help\' menu',
    ':quit'   : 'Quit Blaze'
}
    
class Blaze:  
    def __init__(self, arch='mips32', endian='little', syntax=0):
        self.arch = arch
        self.endianness = endian
        self.ks_syntax = syntax
        self.blaze_bytes = set()
        self.ks_encoding = ''
        self.ins_count= 0
        self.encoded_bytes = ''
        self.instruction_count = 0
        self.result = ''
        self.restart = False
        self.init = True
        
        print BANNER+' Press CTRL-C to exit.'
        print '----'*20
        print 'Enter ' + pblue(':help') + ' for list of options.'
        self.start_ks()

    def start_ks(self):
        if self.restart:
            self.ks = None
            self.restart = False
        try:
            self.ks = Ks(ks_asm_arch[self.arch][0], ks_asm_arch[self.arch][1] + ks_endian[self.endianness])
            if self.ks_syntax != 0:
                self.ks.syntax = self.ks_syntax
            if self.init:
                pinfo (("-- Default configuration: " + pbold("%s (%s-endian)" % (self.arch,self.endianness))))
                self.init = False
            else:
                pinfo ("-- Reconfigured to " + pbold("%s (%s-endian)" % (self.arch,self.endianness)))
        except KsError as e:
            perror("-- %s. (Assembler is not started)" % e)
            
    def set_blaze_bytes(self, add_list):
        try:
            if ',' in add_list:
                for byte in add_list.split(","):
                    if '-' in byte:
                        self._add_range(byte)
                    else:
                        self.blaze_bytes.add(int(byte))
            else:
                if '-' in add_list:
                    self._add_range(add_list)
                else:
                    self.blaze_bytes.add(int(add_list))
        except ValueError as e:
            perror(" -- %s. Use only one space or comma as delimiters." % e) 

    def _add_range(self, blaze_range):
        (start, end) = blaze_range.split("-")
        if start < end:
            for i in range(int(end)+1):
                self.blaze_bytes.add(i)
        else:
            perror("-- Bad range specified, bytes were not added")
            
    def encode(self, asm_code):
        if self.ks is None:
            pinfo("-- Enter valid assembler configuration.")
            return;

        try:
            self.encoded_bytes, self.instruction_count = self.ks.asm(asm_code)
            if len(self.encoded_bytes) == 0:
                self._print_unblaze(asm_code)
            else:
                idx = 2 if self.arch == "thumb" else 4
                for i in range(self.instruction_count):
                    self._blaze_bytes(self.encoded_bytes[(i*idx):(i*idx)+idx])
                    self._print_blaze(asm_code.split(";")[i].strip())                    
            self.encoded_bytes = ''
            self.instruction_count = 0
        except KsError as e:
            perror("-- %s. Enter valid instruction." % e)

    def _blaze_bytes(self, unblazed):
        if unblazed is not None and self.blaze_bytes is not None:
            for byte in unblazed:
                if byte in self.blaze_bytes:
                    self.result += pblaze(('%02x' % byte))
                else:
                    self.result += '%02x' % byte
        elif unblazed is not None and self.blaze_bytes is None:
            for byte in unblazed:
                self.result += '%02x' % byte
        else:
            perror("-- No bytes to blaze")

    def _print_blaze(self, code_str):
        print " %s\t%s" % (self.result, code_str)
        self.result = ''
        
    def _print_unblaze(self, code_str):
        pinfo("-- No encoding results for \'%s\'" % (code_str.strip()))
        self.result = ''
       
    def get_blaze_byte_string(self):
        byte_str = ''
        if len(self.blaze_bytes) != 0:
            for b in self.blaze_bytes:
                byte_str += "%d " % b
        else:
            byte_str = "No blaze bytes set"    
        return byte_str
    
    def get_supported_archs(self):
        arch_str = ''
        for a in ks_asm_arch:
            arch_str += "%s, " % a 
        return arch_str


def handler(signal_num, frame):
    print '\nCTRL-C detected. Exiting...'
    exit(0)

def process_cmd(b_inst, arglist):
    b_opt = arglist[0]
    if b_opt == ":sbb":
        if len(arglist) == 1:
            pinfo("-- Requires at least one argument [e.g. 0-5, 15, 32 (in decimal)]")
            return
        for i in range(len(arglist)-1):
            b_inst.set_blaze_bytes(arglist[i+1])
        print b_inst.get_blaze_byte_string()
    elif b_opt == ":rbb":
        b_inst.blaze_bytes=set()
    elif b_opt == ":dbb":
        pinfo("-- " + b_inst.get_blaze_byte_string())
    elif b_opt == ":arch": 
        if len(arglist) == 1:
            print "Supported architectures -- %s" % (b_inst.get_supported_archs())
            return
        if arglist[1] in ks_asm_arch:
            b_inst.arch = arglist[1]
            if len(arglist) == 3:
                b_inst.endianness = arglist[2]
            b_inst.restart = True
            b_inst.start_ks()
        else:
            pinfo("-- No changes made, %s not supported. " % punder(arglist[1]))
    elif b_opt == ":endian":
        if len(arglist) == 2:
            if arglist[1] not in ks_endian:
                perror("-- %s is not a valid endianness" % arglist[1])
                return
            if arglist[1] != b_inst.endianness:
                b_inst.endianness = arglist[1]
                b_inst.restart = True
                b_inst.start_ks()
            else:
                pinfo("-- No changes made, endianness is already set to %s" % b_inst.endianness)
        else:
            perror("-- Must specify \'little\' or \'big\'") #TWSS
    elif b_opt == ":help":
        print "    Option \t\tDescription\n    ------ \t\t--------------------------"
        for i in blaze_cmds:
            print "    %s \t\t%s"% (i, blaze_cmds[i])
        print "    {instruction}\tEnter single/multiple instruction (; delimited)"
    elif b_opt == ":config":
        bb = "blaze bytes = { %s }"%( b_inst.get_blaze_byte_string().strip())
        if "No blaze" in bb:
            bb = "no blaze bytes specified"
        pinfo("-- %s (%s-endian), %s" % (b_inst.arch,b_inst.endianness, bb))
    elif b_opt == ":quit":
        print 'Quiting '+ pblaze('blaze ') + 'now.'
        exit()
    else:
        pinfo("-- \'%s\' is an unsupported option. Try \':help\'." % b_opt)
    

if __name__ == '__main__':
    signal.signal(signal.SIGINT, handler)
    
    b = Blaze()
    while True:
        input_str = sys.stdin.readline().rstrip()
        if ":" in input_str and input_str != "":
            process_cmd(b, input_str.split(" "))
        elif input_str == 'clear':
            os.system('clear');
        elif input_str != "":
            b.encode(input_str)
        pass

