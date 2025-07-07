from sage.all import *
from sage.groups.generic import discrete_log
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import rdpcap
from Crypto.Cipher import ChaCha20
import hashlib
import base64
import time

pcap = rdpcap("capture.pcapng")
raw_data_client = b''
raw_data_server = b''
raw_data_all = b''

client_ip = "192.168.56.101"
server_ip = "192.168.56.103"
client_port = 49848
server_port = 31337

for pkt in pcap:
    if IP in pkt and TCP in pkt:
        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Разделение трафика на трафик от клиента и сервера
        if ((ip_layer.src == client_ip and ip_layer.dst == server_ip and tcp_layer.sport == client_port and tcp_layer.dport == server_port)):
            if Raw in pkt:
                raw_data_client += pkt[Raw].load

        if (ip_layer.dst == client_ip and ip_layer.src == server_ip and tcp_layer.dport == client_port and tcp_layer.sport == server_port):
            # извлекаем полезные данные, если есть
            if Raw in pkt:
                raw_data_server += pkt[Raw].load

        # Единый трафик для расшифровки
        if Raw in pkt:
            raw_data_all += pkt[Raw].load

xor_key = 0x133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337

client_x_enc = int.from_bytes(raw_data_client[0:48], byteorder='big')
client_y_enc = int.from_bytes(raw_data_client[48:96], byteorder='big')
client_x = client_x_enc ^ xor_key
client_y = client_y_enc ^ xor_key

print("Client coordinates")
print("X_enc\t",hex(client_x_xor))
print("Y_enc\t",hex(client_y_xor))
print("X\t",hex(client_x))
print("Y\t",hex(client_y))


server_x_enc = int.from_bytes(raw_data_server[0:48], byteorder='big')
server_y_enc = int.from_bytes(raw_data_server[48:96], byteorder='big')
server_x = server_x_enc ^ xor_key
server_y = server_y_enc ^ xor_key

print("")
print("Server coordinates")
print("X_enc\t",hex(server_x_xor))
print("Y_enc\t",hex(server_y_xor))
print("X\t",hex(server_x))
print("Y\t",hex(server_y))

# Параметры конечного поля и эллиптической кривой
prime_field_modulus_q = 0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd

curve_param_A = 0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f
curve_param_B = 0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380

G_x = 0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8
G_y = 0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182

# Создание конечного поля и эллиптической кривой
F = GF(prime_field_modulus_q)
E = EllipticCurve(F, [curve_param_A, curve_param_B])

# Создание базовой точки генератора
G = E.point((G_x, G_y))

order = G.order()
factors = order.factor()

print("")
factor_str = "n = " + " * ".join([f"{p}^{e}" for p, e in factors])
print(factor_str)
print("")

Q_cli = E.point((client_x, client_y))
Q_ser = E.point((server_x, server_y))
d_cli_i_mass = []
d_ser_i_mass = []
moduli_list  = []

start = time.time()
for p, e in factors[:-1]:
    _factor = p ** e
    n_i = order//_factor
    G_i = G*n_i
    Q_cli_i = Q_cli*n_i
    Q_ser_i = Q_ser*n_i

    d_cli_i = discrete_log(Q_cli_i, G_i, operation='+', ord=_factor) # +
    d_ser_i = discrete_log(Q_ser_i, G_i, operation='+', ord=_factor) # +
    #d_cli_i = discrete_log_lambda(Q_cli_i, G_i, (0,_factor), '+') # +
    #d_i = G_i.discrete_log(Q_i) # +-
    moduli_list .append(_factor)
    d_cli_i_mass.append(d_cli_i)
    d_ser_i_mass.append(d_ser_i)
    #print(f"Finished processing p^e = {p}^{e}")

d_cli_small = int(crt(d_cli_i_mass, moduli_list))
d_ser_small = int(crt(d_ser_i_mass, moduli_list))
print(f"Computed d_cli_small {d_cli_small}")
print(f"Computed d_ser_small {d_ser_small}")

found_client_key = False
found_server_key = False
p_1_7 = Factorization(factors[:-1]).value()
for k in range(1, 2**16):
    if not found_client_key:
        d_cli = d_cli_small + k * p_1_7
        if Q_cli == d_cli * G:
            print(f"Found client secret key {d_cli}")
            print(f"Iteration {k}")
            found_client_key = True

    if not found_server_key:
        d_ser = d_ser_small + k * p_1_7
        if Q_ser == d_ser * G:
            print(f"Found server secret key {d_ser}")
            print(f"Iteration {k}")
            found_server_key = True

    if found_client_key and found_server_key:
        break

end = time.time()
print("Execution time:", end - start, "seconds")

S = d_cli * d_ser * G
S_x = S[0]
print(f"Shared secret x coordinate {hex(S_x)}")

shared_secret_hash = hashlib.sha512(int(S_x).to_bytes(48, 'big')).digest()
print(f"Hash {shared_secret_hash.hex()}")

key = hash[:32]
print(f"Key {key.hex()}")

iv = hash[32:40]
print(f"IV {iv.hex()}")

cipher = ChaCha20.new(key=key, nonce=iv)
decrypt_text = cipher.decrypt(raw_data_all[192:])
print(decrypt_text)

lines_decrypt_text = decrypt_text.decode().split('\x00')
flag_text = base64.b64decode(lines_decrypt_text[-3])
print(flag_text)

start = time.time()
p_7 = Factorization(factors[-1:]).value()
d_cli_small = (G*p_7).discrete_log(Q_cli*p_7)
d_ser_small = (G*p_7).discrete_log(Q_ser*p_7)
print(f"Computed d_cli_small {d_cli_small}")
print(f"Computed d_ser_small {d_ser_small}")

found_client_key = False
found_server_key = False
p_1_7 = Factorization(factors[:-1]).value()
for k in range(1, 2**16):
    if not found_client_key:
        d_cli = d_cli_small + k * p_1_7
        if Q_cli == d_cli * G:
            print(f"Found client secret key {d_cli}")
            print(f"Iteration {k}")
            found_client_key = True

    if not found_server_key:
        d_ser = d_ser_small + k * p_1_7
        if Q_ser == d_ser * G:
            print(f"Found server secret key {d_ser}")
            print(f"Iteration {k}")
            found_server_key = True

    if found_client_key and found_server_key:
        break

end = time.time()
print("Execution time:", end - start, "seconds")