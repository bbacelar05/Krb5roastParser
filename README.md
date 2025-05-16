
# 🔐 krb5_roast_parser_multi.py

## 🎯 Objetivo

Este script foi desenvolvido para **extrair e formatar hashes Kerberos TGS-REP** de um arquivo `.pcap` (captura de tráfego), gerando os hashes no formato exato que o **Hashcat** exige para ataques de força bruta ou dicionário.

Ele é ideal para testes de segurança (pentest) em ambientes que utilizam **Active Directory**, onde é possível capturar pacotes Kerberos contendo tickets TGS de contas de serviço ou de usuários.

---

## ⚙️ O que o script faz

- 📡 Usa o **TShark** para analisar um arquivo `.pcap` e localizar pacotes Kerberos do tipo `TGS-REP` (msg_type 13)
- 🧱 Extrai os campos: usuário (`CNameString`), realm, SPN (`SNameString`), etype e cipher
- 🛠 Corrige problemas comuns:
  - Substitui `\` por `/` no SPN
  - Remove dados extras no campo `cipher` (quando há vírgula)
- 🧾 Gera os hashes no formato suportado pelo **Hashcat**, nos seguintes modos:
  - `-m 13100` → RC4-HMAC (etype 23)
  - `-m 19600` → AES128-CTS-HMAC-SHA1-96 (etype 17)
  - `-m 19700` → AES256-CTS-HMAC-SHA1-96 (etype 18)

---

## 📦 Pré-requisitos

- Python 3
- TShark (`apt install tshark`)
- Um arquivo `.pcap` com tráfego Kerberos
- Wordlist (ex: `rockyou.txt`) se for usar com Hashcat

---

## ▶️ Como executar

```bash
python3 krb5_roast_parser_multi.py <arquivo.pcap> tgs_rep
```

Exemplo:

```bash
python3 krb5_roast_parser_multi.py attack_capture.pcap tgs_rep
```

Arquivos gerados:

- `hashes_13100.txt` → Hashcat `-m 13100`
- `hashes_19600.txt` → Hashcat `-m 19600`
- `hashes_19700.txt` → Hashcat `-m 19700`

---

## 🔓 Como atacar com Hashcat

```bash
hashcat -m 13100 hashes_13100.txt <wordlist>.txt --force
```

Substitua o modo `-m` e o arquivo conforme o tipo de hash gerado.

---

## 📁 Exemplo de hash gerado

```
$krb5tgs$23$*usuario$METAL10.IND.BR$host/servidor.local*$8d2a7b825c8f8c9b462a3cd3a48688cf$edea6eda28...
```

---

## 🧠 Observações

- O script **não descriptografa** o hash, apenas gera no formato adequado
- Pode ser usado com `tgsrepcrack`, `john`, `kerbrute` ou `hashcat`

---

## 👨‍💻 Autor

Customizado para análises forenses e testes de penetração em ambientes que usam Kerberos.

---

