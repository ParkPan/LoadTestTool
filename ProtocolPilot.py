import struct
import binascii
import nanotime
from ProtocolDefine import *
import random


class ProtocolPilot(object):

    CS_MAGIC = 0x7973
    INT64_SYMBOL_BIT = 0x8000000000000000

    @staticmethod
    def checksum_generator(byte_data_array, array_len):
        tmp_sum = ProtocolPilot.CS_MAGIC

        for i in range(array_len):
            if i % 8 == 0:
                flag = True
            else:
                flag = False
            if flag:
                temp = 0L
                if (int(binascii.b2a_hex(byte_data_array[i]), 16) & 0x80) != 0:
                    temp |= ProtocolPilot.INT64_SYMBOL_BIT
                    temp |= ((int(binascii.b2a_hex(byte_data_array[i]), 16) & 0x7f) << 8 * (7 - (i % 8)))
                    continue
            temp |= int(binascii.b2a_hex(byte_data_array[i]), 16) << 8 * (7 - (i % 8))
            if i % 8 == 7:
                tmp_sum ^= temp
        if (array_len - 1) % 8 != 7:
            tmp_sum ^= temp

        ret_sum = ((tmp_sum >> 32) ^ tmp_sum) & 0xffffffff
        cs = ((ret_sum >> 16) ^ ret_sum) & 0xffff
        return binascii.b2a_hex(struct.pack("!H", cs))

    @staticmethod
    def generate_protocol_message(protocol_object, protocol_type):
        ret_string = protocol_object.protcol_type
        try:
            tmp_sub_type = (protocol_object.protcol_opt << 7 | protocol_object.protcol_iack << 6 |
                            protocol_object.protcol_rsv << 5) & 0xf0
        except Exception, e:
            print e.message
        tmp_sub_type |= (protocol_object.protcol_sub_type & 0x0f)
        ret_string += binascii.b2a_hex(struct.pack("!B", tmp_sub_type))
        ret_string += protocol_object.protcol_win_size
        ret_string += binascii.b2a_hex(struct.pack("!I", protocol_object.protcol_timestamp))
        ret_string += binascii.b2a_hex(struct.pack("!I", protocol_object.protcol_time_delay))
        ret_string += binascii.b2a_hex(struct.pack("!H", protocol_object.protcol_seqno))
        ret_string += binascii.b2a_hex(struct.pack("!H", protocol_object.protcol_ackno))
        if protocol_type == PROTOCOL_DCCP_SYNC:
            ret_string += protocol_object.protcol_data.data_peerid
        elif protocol_type == PROTOCOL_DCCP_SYNACK:
            pass
        elif protocol_type == PROTOCOL_DCCP_DATA:
            if protocol_object.protcol_data.data_cccp_obj.protocol_type == PROTOCOL_CCCP_PUSH_STREAM_REQ:
                ret_string += binascii.b2a_hex(struct.pack(
                    "!B", protocol_object.protcol_data.data_cccp_obj.protocol_type))
                ret_string += binascii.b2a_hex(struct.pack(
                    "!H", protocol_object.protcol_data.data_cccp_obj.protocol_data.request_id))
                ret_string += protocol_object.protcol_data.data_cccp_obj.protocol_data.peer_id
                ret_string += protocol_object.protcol_data.data_cccp_obj.protocol_data.file_id
                tmp_array = bytearray(256)
                tmp_array[:len(protocol_object.protcol_data.data_cccp_obj.protocol_data.file_url)] = \
                    protocol_object.protcol_data.data_cccp_obj.protocol_data.file_url
                ret_string += binascii.b2a_hex(str(tmp_array))
                ret_string += binascii.b2a_hex(struct.pack(
                    "!H", protocol_object.protcol_data.data_cccp_obj.protocol_data.cppc_number))
            elif protocol_object.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_STREAM_RSP:
                pass
            elif protocol_object.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_PIECE_DATA:
                pass
            elif protocol_object.protcol_data.protocol_type == PROTOCOL_CCCP_PUSH_STREAM_FIN:
                ret_string += binascii.b2a_hex(struct.pack(
                    "!B", protocol_object.protcol_data.data_cccp_obj.protocol_type))
                ret_string += binascii.b2a_hex(struct.pack(
                    "!H", protocol_object.protcol_data.data_cccp_obj.protocol_data.request_id))
                ret_string += protocol_object.protcol_data.data_cccp_obj.protocol_data.file_id
                ret_string += binascii.b2a_hex(struct.pack(
                    "!B", protocol_object.protcol_data.data_cccp_obj.protocol_data.status))
        elif protocol_type == PROTOCOL_DCCP_ACK:
            ret_string += binascii.b2a_hex(struct.pack("!B", protocol_object.protcol_data.data_whyack))
        elif protocol_type == PROTOCOL_DCCP_FIN:
            ret_string += binascii.b2a_hex(struct.pack("!B", protocol_object.protcol_data.data_code))
        tmp_bytearray = bytes(binascii.a2b_hex(ret_string))
        ret_string += ProtocolPilot.checksum_generator(tmp_bytearray, len(tmp_bytearray))
        return ret_string

    @staticmethod
    def parse_dccp_packet(packet_data):
        data_bytes = bytes(packet_data)
        protocol_type = binascii.b2a_hex(data_bytes[0])
        if protocol_type == PROTOCOL_HEAD_DCCP:
            protocol_data = PROTOCOL_DCCP_HEAD_STRUCT()
            protocol_data.protcol_type = PROTOCOL_HEAD_DCCP
            protocol_data.protcol_opt = (int(binascii.b2a_hex(data_bytes[1]), 16) & 0x80) >> 7
            protocol_data.protcol_iack = (int(binascii.b2a_hex(data_bytes[1]), 16) & 0x40) >> 6
            protocol_data.protcol_rsv = (int(binascii.b2a_hex(data_bytes[1]), 16) & 0x30) >> 4
            protocol_data.protcol_sub_type = int(binascii.b2a_hex(data_bytes[1]), 16) & 0x0f
            protocol_data.protcol_win_size = binascii.b2a_hex(data_bytes[2:4])
            protocol_data.protcol_timestamp = long(binascii.b2a_hex(data_bytes[4:8]), 16)
            protocol_data.protcol_time_delay = long(binascii.b2a_hex(data_bytes[8:12]), 16)
            protocol_data.protcol_seqno = int(binascii.b2a_hex(data_bytes[12:14]), 16)
            protocol_data.protcol_ackno = int(binascii.b2a_hex(data_bytes[14:16]), 16)
            if protocol_data.protcol_sub_type == PROTOCOL_DCCP_SYNC:
                return protocol_data, binascii.b2a_hex(data_bytes[-2:])
            elif protocol_data.protcol_sub_type == PROTOCOL_DCCP_SYNACK:
                temp_data = PROTOCOL_DCCP_SYNACK_STRUCT()
                temp_data.data_peerid = binascii.b2a_hex(data_bytes[16:32])
                temp_data.data_code = int(binascii.b2a_hex(data_bytes[32:33]), 16)
                tmp_chksum = binascii.b2a_hex(data_bytes[33:])
                protocol_data.protcol_data = temp_data
                return protocol_data, tmp_chksum
            elif protocol_data.protcol_sub_type == PROTOCOL_DCCP_DATA:
                temp_sub_type = int(binascii.b2a_hex(data_bytes[16]), 16) & 0x3f
                cccp_data = PROTOCOL_CCCP_HEAD_STRURCT()
                cccp_data.protocol_type = temp_sub_type
                if temp_sub_type == PROTOCOL_CCCP_PUSH_STREAM_REQ:
                    return protocol_data, binascii.b2a_hex(data_bytes[-2:])
                elif temp_sub_type == PROTOCOL_CCCP_PUSH_STREAM_RSP:
                    cccp_data.protocol_data = PROTOCOL_CCCP_PUSH_STREAM_RSP_STRUCT()
                    cccp_data.protocol_data.request_id = int(binascii.b2a_hex(data_bytes[17:19]), 16)
                    cccp_data.protocol_data.status = int(binascii.b2a_hex(data_bytes[19]), 16)
                    tmp_chksum = binascii.b2a_hex(data_bytes[20:])
                    protocol_data.protcol_data = cccp_data
                    return protocol_data, tmp_chksum
                elif temp_sub_type == PROTOCOL_CCCP_PUSH_PIECE_DATA:
                    cccp_data.protocol_data = PROTOCOL_CCCP_PUSH_PIECE_DATA_STRUCT()
                    tmp_chksum = binascii.b2a_hex(data_bytes[-2:])
                    protocol_data.protcol_data = cccp_data
                    return protocol_data, tmp_chksum
                elif temp_sub_type == PROTOCOL_CCCP_PUSH_STREAM_FIN:
                    cccp_data.protocol_data = PROTOCOL_CCCP_PUSH_STREAM_FIN_STRUCT()
                    cccp_data.protocol_data.request_id = int(binascii.b2a_hex(data_bytes[17:19]), 16)
                    cccp_data.protocol_data.file_id = binascii.b2a_hex(data_bytes[19:35])
                    cccp_data.protocol_data.status = int(binascii.b2a_hex(data_bytes[35]), 16)
                    tmp_chksum = binascii.b2a_hex(data_bytes[36:])
                    protocol_data.protcol_data = cccp_data
                    return protocol_data, tmp_chksum
            elif protocol_data.protcol_sub_type == PROTOCOL_DCCP_ACK:
                temp_data = PROTOCOL_DCCP_ACK_STRUCT()
                temp_data.data_whyack = int(binascii.b2a_hex(data_bytes[17:18]), 16)
                tmp_chksum = binascii.b2a_hex(data_bytes[18:])
                protocol_data.protcol_data = temp_data
                return protocol_data, tmp_chksum
            elif protocol_data.protcol_sub_type == PROTOCOL_DCCP_FIN:
                temp_data = PROTOCOL_DCCP_FIN_STRUCT()
                temp_data.data_code = int(binascii.b2a_hex(data_bytes[17:18]), 16)
                tmp_chksum = binascii.b2a_hex(data_bytes[18:])
                protocol_data.protcol_data = temp_data
                return protocol_data, tmp_chksum
        return None, None

    @staticmethod
    def create_protocol_struct(info_obj, protocol_head, protocol_type, data_obj, **additions):
        if protocol_head == PROTOCOL_HEAD_DCCP:
            protocol_data = PROTOCOL_DCCP_HEAD_STRUCT()
            protocol_data.protcol_type = protocol_head
            if "opt" in additions.keys():
                protocol_data.protcol_opt = additions["opt"]
            else:
                protocol_data.protcol_opt = 0
            if "iack" in additions.keys():
                protocol_data.protcol_iack = additions["iack"]
            else:
                protocol_data.protcol_iack = 0
            protocol_data.protcol_rsv = 0
            protocol_data.protcol_sub_type = protocol_type
            protocol_data.protcol_win_size = "ffff"
            protocol_data.protcol_timestamp = (nanotime.now().nanoseconds() / 1000) & 0xffffffff
            if "delay" in additions.keys():
                protocol_data.protcol_time_delay = additions["delay"]
            else:
                protocol_data.protcol_time_delay = protocol_data.protcol_timestamp - info_obj.nanotime_number
            info_obj.nanotime_number = protocol_data.protcol_timestamp
            protocol_data.protcol_seqno = info_obj.session_sequence_number
            protocol_data.protcol_ackno = info_obj.session_ack_number
            protocol_data.protcol_data = data_obj
            return protocol_data
        elif protocol_head == PROTOCOL_DCCP_SYNC:
            protocol_data = PROTOCOL_DCCP_SYNC_STRUCT()
            protocol_data.data_peerid = info_obj.peer_id
            return protocol_data
        elif protocol_head == PROTOCOL_DCCP_SYNACK:
            pass
        elif protocol_head == PROTOCOL_DCCP_DATA:
            protocol_data = PROTOCOL_DCCP_DATA_STRUCT()
            protocol_data.data_cccp_obj = data_obj
            return protocol_data
        elif protocol_head == PROTOCOL_DCCP_ACK:
            protocol_data = PROTOCOL_DCCP_ACK_STRUCT()
            if "whyack" in additions.keys():
                protocol_data.data_whyack = additions["whyack"]
            else:
                protocol_data.data_whyack = 5
            return protocol_data
        elif protocol_head == PROTOCOL_DCCP_FIN:
            protocol_data = PROTOCOL_DCCP_FIN_STRUCT()
            protocol_data.data_code = 0
            return protocol_data
        elif protocol_head == PROTOCOL_CCCP_PUSH_STREAM_REQ:
            protocol_data = PROTOCOL_CCCP_HEAD_STRURCT()
            protocol_data.protocol_type = PROTOCOL_CCCP_PUSH_STREAM_REQ
            protocol_data.protocol_data = PROTCOL_CCCP_PUSH_STREAM_REQ_STRUCT()
            protocol_data.protocol_data.request_id = info_obj.request_id
            protocol_data.protocol_data.peer_id = info_obj.peer_id
            protocol_data.protocol_data.file_id = info_obj.file_id
            protocol_data.protocol_data.file_url = info_obj.file_url
            protocol_data.protocol_data.cppc_number = 1
            return protocol_data
        elif protocol_head == PROTOCOL_CCCP_PUSH_STREAM_RSP:
            pass
        elif protocol_head == PROTOCOL_CCCP_PUSH_PIECE_DATA:
            pass
        elif protocol_head == PROTOCOL_CCCP_PUSH_STREAM_FIN:
            protocol_data = PROTOCOL_CCCP_HEAD_STRURCT()
            protocol_data.protocol_type = PROTOCOL_CCCP_PUSH_STREAM_FIN
            protocol_data.protocol_data = PROTOCOL_CCCP_PUSH_STREAM_FIN_STRUCT()
            protocol_data.protocol_data.request_id = info_obj.request_id
            protocol_data.protocol_data.file_id = info_obj.file_id
            protocol_data.protocol_data.status = 0
            return protocol_data
        else:
            return None

    @staticmethod
    def create_ack_info(info_obj, wack=5):
        tmp_ack = ProtocolPilot.create_protocol_struct(info_obj, PROTOCOL_DCCP_ACK, None, None, whyack=wack)
        protocol_data = ProtocolPilot.create_protocol_struct(info_obj, PROTOCOL_HEAD_DCCP, PROTOCOL_DCCP_ACK, tmp_ack,
                                                             delay=random.randint(1, 99))
        return protocol_data

    @staticmethod
    def create_sync_info(info_obj):
        tmp_sync = ProtocolPilot.create_protocol_struct(info_obj, PROTOCOL_DCCP_SYNC, None, None)
        protocol_data = ProtocolPilot.create_protocol_struct(info_obj, PROTOCOL_HEAD_DCCP, PROTOCOL_DCCP_SYNC, tmp_sync,
                                                             opt=0, iack=0, delay=0)
        return protocol_data
