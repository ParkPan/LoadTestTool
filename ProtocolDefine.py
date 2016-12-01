PROTOCOL_HEAD_DCCP = "d1"

PROTOCOL_DCCP_SYNC = 1
PROTOCOL_DCCP_SYNACK = 2
PROTOCOL_DCCP_DATA = 3
PROTOCOL_DCCP_ACK = 4
PROTOCOL_DCCP_FIN = 5

PROTOCOL_CCCP_PUSH_STREAM_REQ = 20
PROTOCOL_CCCP_PUSH_STREAM_RSP = 21
PROTOCOL_CCCP_PUSH_PIECE_DATA = 22
PROTOCOL_CCCP_PUSH_STREAM_FIN = 23


class PROTOCOL_DCCP_HEAD_STRUCT():
    def __init__(self):
        self.protcol_type = ""
        self.protcol_opt = 0
        self.protcol_iack = 0
        self.protcol_rsv = 0
        self.protcol_sub_type = 0
        self.protcol_win_size = ""
        self.protcol_timestamp = 0
        self.protcol_time_delay = 0
        self.protcol_seqno = 0
        self.protcol_ackno = 0
        self.protcol_data = None


class PROTOCOL_DCCP_SYNC_STRUCT():
    def __init__(self):
        self.data_peerid = ""


class PROTOCOL_DCCP_SYNACK_STRUCT():
    def __init__(self):
        self.data_peerid = ""
        self.data_code = 0


class PROTOCOL_DCCP_DATA_STRUCT():
    def __init__(self):
        self.data_cccp_obj = None


class PROTOCOL_DCCP_ACK_STRUCT():
    def __init__(self):
        self.data_whyack = 0


class PROTOCOL_DCCP_FIN_STRUCT():
    def __init__(self):
        self.data_code = 0


class PROTOCOL_CCCP_HEAD_STRURCT():
    def __init__(self):
        self.protocol_type = 0
        self.protocol_data = None


class PROTCOL_CCCP_PUSH_STREAM_REQ_STRUCT():
    def __init__(self):
        self.request_id = 0
        self.peer_id = ""
        self.file_id = ""
        self.file_url = ""
        self.cppc_number = 0


class PROTOCOL_CCCP_PUSH_STREAM_RSP_STRUCT():
    def __init__(self):
        self.request_id = 0
        self.status = 0


class PROTOCOL_CCCP_PUSH_PIECE_DATA_STRUCT():
    def __init__(self):
        self.request_id = 0
        self.chuck_id = 0
        self.piece_index = 0
        self.piece_data = 0


class PROTOCOL_CCCP_PUSH_STREAM_FIN_STRUCT():
    def __init__(self):
        self.request_id = 0
        self.file_id = ""
        self.status = 0
