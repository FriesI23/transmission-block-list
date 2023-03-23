# -*- coding: utf-8 -*-
import subprocess
import time
import os
import collections
import csv
import logging
import argparse
import datetime


__version__ = 'v0.1.0'

G_USERNAME = ""
G_PASSWORD = ""
G_ADDR = ""
G_BLOCKFILE_PATH = ""
G_ONLYFILE_MODE = False

G_BLOCKKEYS = ('Xunlei', 'Thunder', '-XL0012-', '-DL3760-')
G_LOGGER = logging.getLogger("__BLOCKLIST__")
G_LOGGER.setLevel(logging.WARNING)


def is_blockkeys_match(s):
    for k in G_BLOCKKEYS:
        if k in s:
            return True
    return False


class TaskStatus(object):
    SEEDING = "Seeding"
    FINISHED = "Finished"
    IDLE = "Idle"


class RemoteAPI(object):

    TASK_INFO_1 = collections.namedtuple("TaskInfo_1", ("ID", "ETA", "STATUS", "NAME"))
    USER_INFO = collections.namedtuple("UserInfo", ("IP", "FLAG", "P_DONW", "S_DOWN", "S_UP", "CLIENT"))

    def _logger(self, *msg):
        G_LOGGER.warning("[CLIENT: {} {}:***] {}".format(self.addr, self.username, ''.join((str(i) for i in msg))))

    def __init__(self, username, password, addr):
        G_LOGGER.warning("NEW CLIENT, {} {}:{}".format(addr, username, password))
        self.username = username
        self.password = password
        self.addr = addr

    @property
    def auth(self):
        if not self.username:
            return ""
        return "{}:{}".format(self.username, self.password)

    def get_active_list(self):
        """
        raw data e.g.:
            56   100%   725.3 MB  Done        37.0     0.0   11.1  Seeding      黑袍纠察队.The.Boys.S02E04.官方中字.WEBrip.720P-CS.mp4
            58    n/a       None  Unknown      0.0     0.0   None  Idle         807ecafd8688652de71a3756e33c7f3ffe5f07c9
            ...
        """
        self._logger("GET ACTIVE LIST::")
        _args = ["transmission-remote", self.addr]
        if self.auth:
            _args.extend(['--auth', self.auth])
        _args.extend(["-t", "all", "-l"])
        _out = subprocess.check_output(_args).decode('utf-8')
        _outlist = _out.splitlines()[1:-1]
        _retlist = []
        for _data in _outlist:
            _sdata = _data.split()
            if _sdata[1].lower() == 'n/a' or _sdata[2] == 'None' or _sdata[3] == 'Unknown':
                continue
            _retlist.append(self.TASK_INFO_1(_sdata[0], _sdata[4], _sdata[8], _sdata[9]))
        return _retlist

    def get_user_by_id(self, id_: int):
        """
        raw data e.g.:
            14.121.132.35         UEI           0.0      0.0     1.0  Xunlei 0.0.1.2
            ...
        """
        self._logger("GET USER BY ID:: id={}".format(id_))
        _args = ["transmission-remote", self.addr]
        if self.auth:
            _args.extend(['--auth', self.auth])
        _args.extend(["-t", str(id_), "-ip"])
        _out = subprocess.check_output(_args).decode('utf-8')
        _outlist = _out.splitlines()[1:]
        _retlist = []
        for _data in _outlist:
            _retlist.append(self.USER_INFO(*_data.split(maxsplit=5)))
        return _retlist

    def stop_task_by_id(self, id_: int):
        self._logger("STOP TASK BY ID:: id={}".format(id_))
        _args = ["transmission-remote", self.addr]
        if self.auth:
            _args.extend(['--auth', self.auth])
        _args.extend(["-t", str(id_), "--stop"])
        subprocess.call(_args)

    def start_task_by_id(self, id_: int):
        self._logger("START TASK BY ID:: id={}".format(id_))
        _args = ["transmission-remote", self.addr]
        if self.auth:
            _args.extend(['--auth', self.auth])
        _args.extend(["-t", str(id_), "--start"])
        subprocess.call(_args)

    def update_blocklist(self):
        self._logger("UPDATE BLOCKLIST::")
        _args = ["transmission-remote", self.addr]
        if self.auth:
            _args.extend(['--auth', self.auth])
        _args.append("--blocklist-update")
        subprocess.call(_args)

    def reanounce_active_list(self):
        self._logger("REANOUNCE ACTIVE LIST::")
        _args = ["transmission-remote", self.addr]
        if self.auth:
            _args.extend(['--auth', self.auth])
        _args.extend(["-t", "all", "--reannounce"])
        subprocess.call(_args)


class BlockFileHandler(object):
    """
    single line e.g.:
        14.17.29.0      - 14.17.44.255    ,   0 , Tencent Offline
        ...
    """

    HEADERS = ("IP_START", "IP_END", "UN_0", "C_FLAG")
    HEADER_TUPLE = collections.namedtuple("BlockRow", HEADERS)

    def __init__(self, blockfile_path):
        self.blockfile_path = blockfile_path
        self._blocklist = []

    def deduplication(self):
        _sorted_list = sorted(set(self._blocklist), key=self._blocklist.index)
        self._blocklist.clear()
        self._blocklist.extend(_sorted_list)

    def add_newrows(self, l):
        for i in l:
            self.add_newrow(*i)

    def add_newrow(self, *args):
        self._blocklist.append(self.HEADER_TUPLE(*args))

    def read_from_file(self):
        self._blocklist.clear()
        self._blocklist.extend(self._get_current_blocklist())

    def _get_current_blocklist(self):
        if not os.path.isfile(self.blockfile_path):
            return []
        with open(self.blockfile_path, 'r') as fp:
            retlist = []
            for i in csv.reader(fp):
                if not i or i[0].startswith('#'):
                    continue
                _ip_s, _ip_e = i[0].split('-')
                _ip_s, _ip_e = _ip_s.strip(), _ip_e.strip()
                retlist.append(self.HEADER_TUPLE(_ip_s, _ip_e, *(i.strip() for i in i[1:])))
            return retlist

    def write_to_file(self):
        with open(self.blockfile_path, 'w') as fp:
            fp.write("""# ===============================
# SCRIPTE_VERSION: {version}
# UPDATE: {date}
# ===============================
""".format(
    date=datetime.datetime.today().strftime('%c'),
    version=__version__,
))
            fp_csv = csv.writer(fp)
            for b in self._blocklist:
                _d = []
                _d.append("{} - {}".format(b.IP_START, b.IP_END))
                _d.append(b.UN_0)
                _d.append(b.C_FLAG)
                fp_csv.writerow(_d)


def upgrade_blocklist():
    _blocklist = []

    remoteAPI = RemoteAPI(G_USERNAME, G_PASSWORD, G_ADDR)
    blockFileHandler = BlockFileHandler(G_BLOCKFILE_PATH)

    task_list = remoteAPI.get_active_list()
    _need_restart_tasks = set()
    for task in task_list:
        user_list = remoteAPI.get_user_by_id(task.ID)
        for user in user_list:
            if is_blockkeys_match(user.CLIENT):
                _blocklist.append(blockFileHandler.HEADER_TUPLE(user.IP, user.IP, '0', user.CLIENT))
                _need_restart_tasks.add(task)

    blockFileHandler.read_from_file()
    blockFileHandler.add_newrows(_blocklist)
    blockFileHandler.deduplication()
    blockFileHandler.write_to_file()

    if G_ONLYFILE_MODE:
        return

    remoteAPI.update_blocklist()
    time.sleep(2)

    remoteAPI.reanounce_active_list()
    time.sleep(2)

    for task in _need_restart_tasks:
        if task.STATUS != TaskStatus.FINISHED:
            remoteAPI.stop_task_by_id(int(task.ID))
            time.sleep(1)
            remoteAPI.start_task_by_id(int(task.ID))
            time.sleep(1)
        else:
            G_LOGGER.warning(" -- SKIPPED RESTART: {}".format(task))


def parse_arg():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", default="")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("--addr", default="http://localhost:9091/transmission")
    parser.add_argument("-b", "--block-path", default=os.path.join('.', 'transmission-block.txt'))
    parser.add_argument("--onlyfile-mode", action='store_true')
    return parser


if __name__ == '__main__':
    parser = parse_arg()
    args = parser.parse_args()

    G_USERNAME = args.username
    G_PASSWORD = args.password
    G_ADDR = args.addr
    G_BLOCKFILE_PATH = os.path.abspath(args.block_path)
    G_ONLYFILE_MODE= args.onlyfile_mode

    G_LOGGER.warning("==========================================")
    G_LOGGER.warning("G_ADDR: {}".format(G_ADDR))
    G_LOGGER.warning("G_USERNAME: {}".format(G_USERNAME))
    G_LOGGER.warning("G_PASSWORD: {}".format(G_PASSWORD))
    G_LOGGER.warning("G_BLOCKFILE_PATH: {}".format(G_BLOCKFILE_PATH))
    G_LOGGER.warning("==========================================")

    upgrade_blocklist()