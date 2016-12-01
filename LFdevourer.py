import socket
import binascii
import select
from ProtocolDefine import *
from ProtocolPilot import ProtocolPilot
import time
import hashlib
import random
import sys
import multiprocessing
import subprocess
import json


PORT_START = 20102


def check_port_occupier(use_port):
    s = socket.socket()
    s.settimeout(0.5)
    return s.connect_ex(("localhost", use_port)) == 0


def create_udp_send_port():
    global PORT_START
    interactive_port = random.randint(1, 40000) + PORT_START
    while check_port_occupier(interactive_port):
        interactive_port = random.randint(1, 40000) + PORT_START
    return interactive_port


class LFdevourer(object):

    def __init__(self, peerid, fileid, fileurl, requestid, interactiveport):
        self.session_sequence_number = 0
        self.session_ack_number = 0
        self.nanotime_number = 0
        self.peer_id = peerid
        self.file_id = fileid
        self.file_url = fileurl
        self.request_id = requestid
        self.active_socket = None
        self.time_counter = 0
        self.interactive_port = interactiveport

    def ack_timer_check(self):
        if self.time_counter == 0:
            self.time_counter = time.time()
        if time.time() - self.time_counter >= 0.5:
            self.time_counter = time.time()
            return True
        else:
            return False

    def clean_ack_timer(self):
        self.time_counter = 0

    def create_udp_send_chanel(self):
        udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_sock.bind(("0.0.0.0", self.interactive_port))
        return udp_sock

    def run_devourer(self, LFIp, LFPort):
        self.active_socket = self.create_udp_send_chanel()
        self.active_socket.setblocking(False)
        single_socket_list = [self.active_socket, ]
        self.session_sequence_number += 1
        protocol_data = ProtocolPilot.create_sync_info(self)
        data_message = ProtocolPilot.generate_protocol_message(protocol_data, PROTOCOL_DCCP_SYNC)
        self.active_socket.sendto(binascii.a2b_hex(data_message), (LFIp, LFPort))
        while True:
            readable_list, writeable_list, error_list = select.select(single_socket_list, [], single_socket_list, 1)
            for r in readable_list:
                received = r.recv(2048)
                if received:
                    data_obj = ProtocolPilot.parse_dccp_packet(received)[0]
                    if data_obj is None:
                        continue
                    if data_obj.protcol_type == PROTOCOL_HEAD_DCCP:
                        if data_obj.protcol_sub_type == PROTOCOL_DCCP_SYNC:
                            pass
                        if data_obj.protcol_sub_type == PROTOCOL_DCCP_SYNACK:
                            self.session_ack_number = data_obj.protcol_seqno
                            tmp_req = ProtocolPilot.create_protocol_struct(self, PROTOCOL_CCCP_PUSH_STREAM_REQ,
                                                                           None, None, opt=1)
                            tmp_data = ProtocolPilot.create_protocol_struct(self, PROTOCOL_DCCP_DATA, None, tmp_req)
                            self.session_sequence_number += 1
                            req_data = ProtocolPilot.create_protocol_struct(self, PROTOCOL_HEAD_DCCP,
                                                                            PROTOCOL_DCCP_DATA, tmp_data, iack=1)
                            req_message = ProtocolPilot.generate_protocol_message(req_data, PROTOCOL_DCCP_DATA)
                            self.active_socket.sendto(binascii.a2b_hex(req_message), (LFIp, LFPort))
                        if data_obj.protcol_sub_type == PROTOCOL_DCCP_DATA:
                            if data_obj.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_STREAM_REQ:
                                pass
                            if data_obj.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_STREAM_RSP:
                                if data_obj.protcol_iack == 1:
                                    self.session_ack_number = data_obj.protcol_seqno
                                    self.session_sequence_number += 1
                                    ack_data = ProtocolPilot.create_ack_info(self, 1)
                                    ack_message = ProtocolPilot.generate_protocol_message(ack_data, PROTOCOL_DCCP_ACK)
                                    self.active_socket.sendto(binascii.a2b_hex(ack_message), (LFIp, LFPort))
                                if data_obj.protcol_data.protocol_data.status == 5:
                                    time.sleep(1)
                                    self.session_sequence_number += 1
                                    protocol_data = ProtocolPilot.create_sync_info(self)
                                    data_message = ProtocolPilot.generate_protocol_message(protocol_data,
                                                                                           PROTOCOL_DCCP_SYNC)
                                    self.active_socket.sendto(binascii.a2b_hex(data_message), (LFIp, LFPort))
                            if data_obj.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_PIECE_DATA:
                                self.session_ack_number = data_obj.protcol_seqno
                            if data_obj.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_STREAM_FIN:
                                self.session_ack_number = data_obj.protcol_seqno
                        if data_obj.protcol_sub_type == PROTOCOL_DCCP_ACK:
                            if data_obj.protcol_iack == 1:
                                self.session_ack_number = data_obj.protcol_seqno
                                self.session_sequence_number += 1
                                ack_data = ProtocolPilot.create_ack_info(self, 1)
                                ack_message = ProtocolPilot.generate_protocol_message(ack_data, PROTOCOL_DCCP_ACK)
                                self.active_socket.sendto(binascii.a2b_hex(ack_message), (LFIp, LFPort))
                                self.clean_ack_timer()
                        if data_obj.protcol_sub_type == PROTOCOL_DCCP_FIN:
                            pass
            if self.ack_timer_check():
                ack_data = ProtocolPilot.create_ack_info(self)
                ack_message = ProtocolPilot.generate_protocol_message(ack_data, PROTOCOL_DCCP_ACK)
                self.active_socket.sendto(binascii.a2b_hex(ack_message), (LFIp, LFPort))


def create_lf_node():
    pass


def get_lf_port(lfip):
    info_url = "http://%s:32719/ajax/login" % lfip
    out_obj = subprocess.Popen("curl %s 2>/dev/null" % info_url, shell=True, stdout=subprocess.PIPE)
    ret_msg = out_obj.stdout.read()
    if ret_msg is None or ret_msg == "":
        return 0
    json_obj = json.loads(ret_msg)
    return int(json_obj["publicPort"])


def peer_connect_lf(lfnum, fid, furl, lfip, lfport, rlist, plist, ptlist, bstart=True, interval=0):
    for i in range(lfnum):
        udp_port = create_udp_send_port()
        while udp_port in ptlist:
            udp_port = create_udp_send_port()
        ptlist.append(udp_port)
        request_id = random.randint(1000, 65000)
        while request_id in rlist:
            request_id = random.randint(1000, 65000)
        rlist.append(request_id)
        peer_id = hashlib.md5(str(request_id)).hexdigest().upper()
        lf_devourer = LFdevourer(peer_id, fid, furl, request_id, udp_port)
        p = multiprocessing.Process(target=lf_devourer.run_devourer, args=(lfip, lfport))
        p.daemon = True
        plist.append(p)
        if bstart:
            p.start()
            time.sleep(interval)


def all_peer_keep_connect(plist):
    for tmp_p in plist:
        tmp_p.join()


def peer_disconnect_lf(disnum, plist):
    for j in range(disnum):
        if len(plist) == 0:
            break
        tmp_index = random.randint(0, len(plist)-1)
        tmp_p = plist.pop(tmp_index)
        if tmp_p.is_alive():
            tmp_p.terminate()
            tmp_p.join()

if __name__ == "__main__":

    if len(sys.argv) < 4:
        print "parameter is incorrect, tool will exit..."
        exit(-1)
    lf_ip = sys.argv[1]
    lf_number = int(sys.argv[2])
    file_url = sys.argv[3]
    op_type = ""
    surge_num = 0
    stable_time = 0
    surge_time = 0
    recovery_time = 0
    if len(sys.argv) >= 8:
        op_type = sys.argv[4]
        surge_num = int(sys.argv[5])
        stable_time = int(sys.argv[6])
        surge_time = int(sys.argv[7])
        try:
            recovery_time = int(sys.argv[8])
        except:
            recovery_time = 0

    create_lf_node()

    file_id = hashlib.md5(file_url).hexdigest().upper()
    lf_port = get_lf_port(lf_ip)
    if lf_port == 0:
        print "cannot get LF port, the tool will be exit..."
        exit(-2)
    request_list = []
    process_list = []
    port_list = []

    peer_connect_lf(lf_number, file_id, file_url, lf_ip, lf_port, request_list, process_list, port_list)
    # for tmp_p in process_list:  # if process in list not running, this code will run them
    #     tmp_p.start()
    #     # time.sleep(1)
    time.sleep(stable_time)  # wait connection created, LF 15s connect 1 peer. this for jittery connection
    if op_type == "surgedown":
        # jittery connection mode count down to 0
        while True:
            peer_disconnect_lf(surge_num, process_list)
            if len(process_list) == 0:
                break
            time.sleep(surge_time)
    elif op_type == "surge":
        # jittery stable connection number
        while True:
            peer_disconnect_lf(surge_num, process_list)
            time.sleep(surge_time)
            peer_connect_lf(surge_num, file_id, file_url, lf_ip, lf_port, request_list, process_list, port_list)
            time.sleep(recovery_time)
    else:
        # stable connection mode
        all_peer_keep_connect(process_list)
