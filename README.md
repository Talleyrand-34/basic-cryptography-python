# basic-cryptography-python

Coursework for **SSI** (Seguridade de Sistemas Informáticos). Small, self-contained Python CLIs implementing classical ciphers, a Kasiski attack, symmetric block ciphers and hash functions, one directory per práctica.

## Layout

| Path | Implements |
| --- | --- |
| `p1/monoalfabeto/monoalfabeto.py` | **Playfair** cipher (5×5 matrix from a key, `J`→`I`, `X` padding). Encrypt/decrypt from args, from a file, or interactively. |
| `p1/vigenere/vigenere.py` | **Vigenère** cipher over `A–Z` (non-letters passed through). Same CLI shape as above. |
| `p1/kasiski/kasiski.py` | **Kasiski attack** on Vigenère: repeated trigrams → distances → GCDs → key length, then per-subtext Caesar frequency analysis against Spanish letter frequencies, printing the 10 most likely keys and their decryptions. Imports the local copy of `vigenere.py`. |
| `p1/rc4/rc4.py` | **RC4** stream cipher (KSA + PRGA written out by hand), with a per-character trace of plaintext byte / keystream byte / XOR result. |
| `p1/cipher/cipher.py` | **AES-256** and **DES** file encryption in **ECB** and **CBC** via PyCryptodome, PKCS#7 padding, random key/IV generation, IV attached to the file or kept separate, and execution timing. |
| `p1/cipher/test.py` | Ad-hoc check: AES-256-CBC of `secreto.txt` with a fixed key/IV. |
| `p2/hash.py` | **MD5 / SHA-1 / SHA-256** of a string or of a file (read in 8 KB chunks). |

`p1/Memoria.pdf` is the práctica 1 report (source: the Typst project linked in `p1/cipher/link`). `p2/pgp/` is empty.

## Running

Playfair and Vigenère share the same flags (`-E`/`-D` for text on the command line, `-e`/`-d` for files, `--key`); with no flags they drop into a small interactive prompt. File mode writes to `./out-mono/<enc|dec>-out-N.txt`, numbering tracked in `counter.json`.

```bash
cd p1/monoalfabeto
python monoalfabeto.py -E HELLOWORLD --key MONAR
python monoalfabeto.py -e plaintext.txt --key MONAR

cd ../vigenere
python vigenere.py -E "ATTACK AT DAWN" --key ARMOG
python vigenere.py -D KKFOQK AK PRJN --key ARMOG
```

Kasiski takes a single ciphertext file (uppercase, no spaces) and prints the intermediate analysis plus the candidate keys:

```bash
cd p1/kasiski
python kasiski.py cifrado.txt
```

RC4 takes a hex key and reads the text to encrypt from stdin (`exit` to finish); `-d` decrypts a hex-encoded input:

```bash
cd p1/rc4
python rc4.py -k 0102030405
python rc4.py -k 0102030405 -d
```

AES/DES file encryption. Keys and IVs are hex; a 32-byte key is required for AES, 8 bytes for DES. In CBC the IV is prepended to the output file unless `--no-attach-iv`/`--iv-file` is used, and decryption reads it back from the file when `--iv` is not given:

```bash
cd p1/cipher
python cipher.py encrypt AES CBC secreto.txt secreto.enc          # random key + IV, printed
python cipher.py decrypt AES CBC secreto.enc recover.txt --key <hexkey>
python cipher.py encrypt DES ECB secreto.txt secreto.enc --key 0011223344556677
```

Hashes:

```bash
cd p2
python hash.py -t "Hola Mundo" -a md5
python hash.py -f documento.txt -a sha256 -v   # sha256 is the default
```

## Dependencies

Python 3 with the standard library only, except `p1/cipher/` which needs PyCryptodome:

```bash
pip install pycryptodome
```
