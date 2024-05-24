from bitarray import bitarray
from binascii import unhexlify, hexlify

# Permute binary string according to p_table
def permute_bits(bit_arr: bitarray, p_table: list) -> bitarray:
    res = bitarray()
    for x in p_table:
        res += str(bit_arr[x-1])
    return res

# Shift string n positions to left
def shift_left(bit_arr: bitarray, n):
    bit_arr = bit_arr[n:]+bit_arr[:n]
    return bit_arr

def split_half(bit_arr: bitarray):
        mid_index = len(bit_arr)>>1
        left, right = bit_arr[:mid_index], bit_arr[mid_index:]
        return left, right

def hexify(bit_arr: bitarray):
    hx = hex(int(bit_arr.to01(), 2))
    return hx[2:]  

class DES:
    # Class for DES Encryption and Decryption
    def __init__(self, key, configs=None) -> None:
        print(" === INIT DES")
        self.key = key
        self.subkeys = []

        self.init_perm_tables(pc1_file=configs['PC1-table'], pc2_file=configs['PC2-table'], ip_file=configs['IP-table'],
                              e_select_file=configs['E-Select-table'], p_file=configs['P-table'], ip_inv_file=configs['IP-inv-table'])
        self._init_s_boxs(s_file=configs['S-tables'])
        self._gen_subkeys()
        
        print(" === INIT DES -> [DONE]")
    
    # Encrypt message
    def encrypt(self, message):
        msg_bits = bitarray()
        msg_bits.frombytes(message.encode('utf-8'))
        encrypted_message = bitarray()
        for i, block in enumerate(self._get_blocks(msg_bits=msg_bits)):
            enc = self._encode_block(block, range(0, 16))
            encrypted_message += enc
        # TODO: Change ENCODED to hexadecimal format
        return hexify(encrypted_message)
    
    # TODO: Make sure UTF-8 is supported
    def decrypt(self, encrypted_message):
        msg_bits = bitarray()
        msg_bits.frombytes(unhexlify(encrypted_message))
        decrypted_message = bitarray()
        for _, block in enumerate(self._get_blocks(msg_bits=msg_bits)):
            enc = self._encode_block(block, range(15, -1, -1))
            decrypted_message += enc
        message = int(decrypted_message.to01(), 2).to_bytes((len(decrypted_message) + 7) // 8, byteorder='big')
        print(message)
        return message.decode('utf-8')
    
    # Encrypt a 64bit block of message
    def _encode_block(self, block: bitarray, key_range: range):
        ip_message = permute_bits(block, self._IP_table)
        L, R = split_half(ip_message)
        for i in key_range:
            L, R = R, L ^ self.f(L, self.subkeys[i])
        ENCODED = R + L
        ENCODED = permute_bits(ENCODED, self._IP_inv_table)
        return ENCODED
            
    def f(self, sub_block: bitarray, subkey: bitarray):
        # Expand 32 -> 48 bits
        e_block = permute_bits(sub_block, self._E_select_table)
        # XOR with K - 48 bits
        e_block = subkey ^ e_block
        # Substitute S-box 48 -> 32
        s_block = bitarray()
        for i in range(0, len(e_block)//6):
            e_word = e_block[i*6: (i+1)*6]
            s_word = self.S(i, e_word)
            s_block = s_block + s_word
        # Permute using P-Table
        s_block = permute_bits(s_block, self._P_table)
        # return 32bits
        return s_block
    
    def S(self, i, block6: bitarray):
        l1 = block6[0] >> 1
        l6 = block6[-1]
        y = int(block6[1:5].to01(), 2)
        x = l1 + l6
        res = bin(self.S_box[i][x][y])[2:]
        
        bres = bitarray()
        bres.frombytes(bytes(res, 'utf-8'))
        
        return bres      

    def _get_blocks(self, msg_bits: bitarray):
        index = 0
        if len(msg_bits)%64 > 0:
            diff = 64 - (len(msg_bits)%64)
            ext_bitarr = bitarray(diff)
            msg_bits += ext_bitarr

        while index+64 <= len(msg_bits):
            yield msg_bits[index:index+64]
            index += 64
        
    def _gen_subkeys(self) -> None:
        # Generate 16 subkeys
        self.subkeys = []
        key = bitarray()
        key.frombytes(self.key)
        permuted_key = permute_bits(key, self._PC1_table)
        # ! OK
        C, D = split_half(permuted_key)
        
        _shift_list = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        
        indx = 1
        for s in _shift_list:
            C = shift_left(C, s)
            D = shift_left(D, s)
            # print(f"C{indx}: {C.to01()}")
            # print(f"D{indx}: {D.to01()}")
            # print()
            sub_key = permute_bits(C+D, self._PC2_table)
            self.subkeys.append(sub_key)
            # print(f"K{indx}: {' '.join(sub_key.to01()[i:i+6] for i in range(0, len(sub_key), 6))}")
            indx += 1
    
    # Instantiate S-Tables
    def _init_s_boxs(self, s_file=None):
        self.S_box = []
        if s_file is None:
            print("S-Tables not provided")
            return False
        with open(s_file) as f:
            for i in range(8):
                if i>0:
                    f.readline()
                S = []
                for _ in range(4):
                    row = list(map(int, f.readline().split()))
                    S.append(row)
                self.S_box.append(S)
        return True
    
    def init_perm_tables(self, pc1_file=None, pc2_file=None, ip_file=None, e_select_file=None, p_file=None, ip_inv_file=None):
        terminate = False
        if pc1_file is None:
            terminate = True
            print("PC-1 table not provided")
        if pc2_file is None:
            terminate = True
            print("PC-2 table not provided")
        if ip_file is None:
            terminate = True
            print("IP table not provided")
        if ip_inv_file is None:
            terminate = True
            print("IP Inverse table not provided")
        if e_select_file is None:
            terminate = True
            print("E-Selection table not provided")
        if p_file is None:
            terminate = True
            print("P table not provided")
        if terminate:
            return False
        
        def fl(l):
            return ' '.join(l)
            
        with open(pc1_file) as f:
            s = f.readlines()
            self._PC1_table = list(map(int, fl(s).split()))
            # print(f"PC1: {len(self._PC1_table)}")
        with open(pc2_file) as f:
            s = f.readlines()
            self._PC2_table = list(map(int, fl(s).split()))
            # print(f"PC1: {len(self._PC2_table)}")
        with open(ip_file) as f:
            s = f.readlines()
            self._IP_table = list(map(int, fl(s).split()))
            # print(f"PC1: {len(self._IP_table)}")
        with open(ip_inv_file) as f:
            s = f.readlines()
            self._IP_inv_table = list(map(int, fl(s).split()))
            # print(f"PC1: {len(self._IP_inv_table)}")
        with open(e_select_file) as f:
            s = f.readlines()
            self._E_select_table = list(map(int, fl(s).split()))
            # print(f"PC1: {len(self._E_select_table)}")
        with open(p_file) as f:
            s = f.readlines()
            self._P_table = list(map(int, fl(s).split()))
            # print(f"PC1: {len(self._P_table)}")
        

def main(message=None):
    # key = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0" # 64 bits
    # key = b"\x12\x34\x56\xbc\xde\xf0\x78\x9a" # 64 bits
    # key = b"\x63\x34\x57\x79\x9B\xBC\xDF\xF1"
    key = b"\x72\x73\x74\x76\x77\x4a\x67\x68"
    print(key.decode('ASCII'))
    
    if message is None:
        # message = "abcdefghijklmnopqrstuv12"
        # message = "aaaaaaaaaaabbbbbbbbbbbbbb"
        # message = "Hello world! How are you?!"
        message = "aaaaaaaabbbbbbbb"
    
    configs = {
        'PC1-table': './configs/PC-1.table',
        'PC2-table': './configs/PC-2.table',
        'IP-table':  './configs/IP.table',
        'IP-inv-table': './configs/IP_INV.table',
        'E-Select-table': './configs/E-Selection.table',
        'P-table': './configs/P.table',
        'S-tables': './configs/S.tables',
    }
    
    des = DES(key=key, configs=configs)
    
    print("\n===============")
    print(f"Actual Message: {len(message)}", message, 'x')
    print("---------------")
    
    enc_msg = des.encrypt(message=message)
    print('\n==================')
    print("Encrypted Message: ", enc_msg)
    print('------------------')
    
    dec_msg = des.decrypt(encrypted_message=enc_msg)
    for i in range(len(dec_msg)):
        if ord(dec_msg[i]) == 0:
            dec_msg = dec_msg[:i]
            break
    print("\n==================")
    print(f"Decrypted Message: {len(dec_msg)}", dec_msg, 'x')
    print("------------------")

    # print("\n=============")
    # print("Message diff: ", end='')
    # for i in range(len(message)):
    #     if message[i] == dec_msg[i]:
    #         print(message[i], end='')
    #     else:
    #         print('-', end='')
    # print("\n-------------")
    
    b1 = bitarray()
    b1.frombytes(message.encode('utf-8'))
    b2 = bitarray()
    b2.frombytes(dec_msg.encode('utf-8'))
    b101 = b1.to01()
    b201 = b2.to01()
    
    # for i in range(0, len(b201), 64):
    #     print(b101[i:i+64])
    #     print(b201[i:i+64])
    
    for x in range(64):
        if b101[x] != b201[x]:
            print(x, end=' ')
    
    # for x in message:
    #     print(f"{hexlify(x.encode('utf-8'))}", end=' ')
    # print()
    # for x in dec_msg:
    #     print(f"{hexlify(x.encode('utf-8'))}", end=' ')