import sys
import struct
import re
import pykd

if sys.version_info >= (3, 0):
    long = int
else:
    long
    bytes = str
    range = xrange

from angrdbg import *


class WinDebugger(Debugger):
    def __init__(self):
        pass

    def _get_vmmap(self):
        maps = []
        out = pykd.dbgCommand("!address")
        pattern = re.compile("[+]*[ ]+([0-9a-f]*`[0-9a-f]*)[ ]+([0-9a-f]*`[0-9a-f]*)[ ]+([0-9a-f]*`[0-9a-f]*)[ ]+([A-Z_|]*)[ ]+([A-Z_|]*)[ ]+([A-Z_|]*)[ ]+([A-Za-z0-9_]*)(.*)")
        pattern_name = re.compile(".*\[(.*);.*")
        matches = pattern.findall(out)
        if matches:
            for (start, end, size, type, state, prot, usage, other) in matches:
                start = int(start.replace("`",""), 16)
                end = int(end.replace("`",""), 16)
                #size = int(size.replace("`",""), 16)
                mapperm = 0
                if "PAGE_EXECUTE" in prot:
                    mapperm = SEG_PROT_X
                elif "PAGE_EXECUTE_READ" in prot:
                    mapperm = SEG_PROT_X | SEG_PROT_R
                elif "PAGE_EXECUTE_READWRITE" in prot:
                    mapperm = SEG_PROT_X | SEG_PROT_R | SEG_PROT_W
                elif "PAGE_EXECUTE_WRITECOPY" in prot:
                    mapperm = SEG_PROT_X | SEG_PROT_R
                elif "PAGE_NOACCESS" in prot:
                    mapperm = 0
                elif "PAGE_READONLY" in prot:
                    mapperm = SEG_PROT_R
                elif "PAGE_READWRITE" in prot:
                    mapperm = SEG_PROT_R | SEG_PROT_W
                elif "PAGE_WRITECOPY" in prot:
                    mapperm = SEG_PROT_R
                name = pattern_name.findall(other)
                if name:
                    mapname = str(list(name)[0])
                else:
                    mapname = "__seg_0x%x__" % start
                maps += [(start, end, mapperm, mapname)]
        return maps

    # -------------------------------------
    def before_stateshot(self):
        self.vmmap = self._get_vmmap()
        base = self.image_base()
        dh = pykd.dbgCommand("!dh 0x%x" % base)
        #   1B000 [     248] address [size] of Import Address Table Directory
        pattern = re.compile("[ ]+([A-Fa-f0-9]+)[ ]+\[[ ]*([A-Fa-f0-9]+)[ ]*\] address \[size\] of Import Address Table Directory")
        matches = pattern.findall(dh)
        if matches:
            for addr, size in matches:
                self.idata = (base + int(addr, 16), base + int(addr, 16) + int(size, 16))
                break

    def after_stateshot(self, state):
        pass
    # -------------------------------------

    def is_active(self):
        return True

    # -------------------------------------
    def input_file(self):
        exeModuleName = pykd.dbgCommand("lm1m").split('\n')[0]
        exeModule = pykd.module(exeModuleName)
        return open(exeModule.image(), "rb")

    def image_base(self):
        exeModuleName = pykd.dbgCommand("lm1m").split('\n')[0]
        exeModule = pykd.module(exeModuleName)
        return exeModule.begin()

    # -------------------------------------
    def get_byte(self, addr):
        try:
            return int(pykd.loadBytes(addr, 1)[0])
        except BaseException:
            return None

    def get_word(self, addr):
        try:
            return struct.unpack(
                "<H", self.get_bytes(addr, 2))[0]
        except BaseException:
            return None

    def get_dword(self, addr):
        try:
            return struct.unpack(
                "<I", self.get_bytes(addr, 4))[0]
        except BaseException:
            return None

    def get_qword(self, addr):
        try:
            return struct.unpack("<Q", self.get_bytes(addr, 8))[0]
        except BaseException:
            return None

    def get_bytes(self, addr, size):
        try:
            return "".join(map(chr, pykd.loadBytes(addr, size)))
        except BaseException:
            return None

    def put_byte(self, addr, value):
        pykd.setByte(addr, value)

    def put_word(self, addr, value):
        pykd.setWord(addr, value)

    def put_dword(self, addr, value):
        pykd.setDWord(addr, value)

    def put_qword(self, addr, value):
        pykd.setQWord(addr, value)

    def put_bytes(self, addr, value):
        for i in range(len(value)):
            self.put_byte(addr +i, ord(value[i]))

    # -------------------------------------
    def get_reg(self, name):
        if name == "eflags":
            name = "efl"
        return int(pykd.reg(name))
    
    def set_reg(self, name, value):
        if name == "eflags":
            name = "efl"
        pykd.setReg(name, value)

    # -------------------------------------
    def step_into(self):
        pykd.dbgCommand("t")

    def run(self):
        pykd.go()

    def wait_ready(self):
        pass

    def refresh_memory(self):
        pass

    # -------------------------------------
    def seg_by_name(self, name):
        for start, end, perms, mname in self.vmmap:
            if name == mname:
                return Segment(name, start, end, perms)
        return None

    def seg_by_addr(self, addr):
        for start, end, perms, name in self.vmmap:
            if addr >= start and addr < end:
                return Segment(name, start, end, perms)
        return None

    def get_got(self):  # return tuple(start_addr, end_addr)
        s = filter(lambda x: x.name == ".got.plt", load_project().loader.main_object.sections)[0]
        return (s.vaddr, s.vaddr + s.memsize)

    def get_plt(self):  # return tuple(start_addr, end_addr)
        s = filter(lambda x: x.name == ".plt", load_project().loader.main_object.sections)[0]
        return (s.vaddr, s.vaddr + s.memsize)
    
    def get_idata(self):  # return tuple(start_addr, end_addr)
        return self.idata

    # -------------------------------------
    def resolve_name(self, name):  # return None on fail
        try:
            return pykd.getOffset(name)
        except BaseException:
            return None


register_debugger(WinDebugger())