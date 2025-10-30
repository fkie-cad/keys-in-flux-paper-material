# Debugging Ubuntu based Binaries

In order to make the hooking easier we install debug informations as well.

## Get Debug Symbols
```bash
$ sudo apt install ubuntu-dbgsym-keyring
$ echo "Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: $(lsb_release -cs) $(lsb_release -cs)-updates $(lsb_release -cs)-proposed 
Components: main restricted universe multiverse
Signed-by: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg" | \
sudo tee -a /etc/apt/sources.list.d/ddebs.sources
Types: deb
URIs: http://ddebs.ubuntu.com/
Suites: noble noble-updates noble-proposed 
Components: main restricted universe multiverse
Signed-by: /usr/share/keyrings/ubuntu-dbgsym-keyring.gpg

$ sudo apt update
OK:1 https://ppa.launchpadcontent.net/neovim-ppa/unstable/ubuntu noble InRelease
OK:2 http://ddebs.ubuntu.com noble InRelease                                
OK:3 http://ddebs.ubuntu.com noble-updates InRelease                        
Holen:4 http://ddebs.ubuntu.com noble-proposed InRelease [41.4 kB]
OK:5 http://ports.ubuntu.com/ubuntu-ports noble InRelease
Holen:6 http://ddebs.ubuntu.com noble-proposed/main arm64 Packages [75.7 kB]
OK:7 http://ports.ubuntu.com/ubuntu-ports noble-updates InRelease
Holen:8 http://ddebs.ubuntu.com noble-proposed/universe arm64 Packages [32.2 kB]
OK:9 http://ports.ubuntu.com/ubuntu-ports noble-backports InRelease
OK:10 http://ports.ubuntu.com/ubuntu-ports noble-security InRelease
Es wurden 75.7 kB in 1 s geholt (142 kB/s).
Paketlisten werden gelesen… Fertig
Abhängigkeitsbaum wird aufgebaut… Fertig
Statusinformationen werden eingelesen… Fertig
sudo apt install debian-goodies
```
```bash
$ ps -A  | grep -i charon
3347165 ?        00:00:00 charon
3378015 ?        00:00:00 charon
3379478 ?        00:00:00 charon
$ sudo find-dbgsym-packages 3379478
libaudit1-dbgsym libbrotli1-dbgsym libcap-ng0-dbgsym libcap2-dbgsym libcharon-extauth-plugins-dbgsym libcharon-extra-plugins-dbgsym libcom-err2-dbgsym libcurl4t64-dbgsym libffi8-dbgsym libgcrypt20-dbgsym libgmp10-dbgsym libgnutls30t64-dbgsym libgpg-error0-dbgsym libhogweed6t64-dbgsym libidn2-0-dbgsym libip4tc2-dbgsym libkeyutils1-dbgsym libkrb5-dbg libldap2-dbgsym liblz4-1-dbgsym liblzma5-dbgsym libnettle8t64-dbgsym libnghttp2-14-dbgsym libp11-kit0-dbgsym libpam0g-dbgsym libpsl5t64-dbgsym librtmp1-dbgsym libsasl2-2-dbgsym libssh-4-dbgsym libssl3t64-dbgsym libstrongswan-dbgsym libstrongswan-extra-plugins-dbgsym libstrongswan-standard-plugins-dbgsym libsystemd0-dbgsym libtasn1-6-dbgsym libtss2-mu-4.0.1-0t64-dbgsym libtss2-sys1t64-dbgsym libunistring5-dbgsym libzstd1-dbgsym strongswan-charon-dbgsym strongswan-libcharon-dbgsym strongswan-starter-dbgsym strongswan-swanctl-dbgsym zlib1g-dbgsym
```

```bash
$ sudo apt install libcap-ng0-dbgsym libcap2-dbgsym libcharon-extauth-plugins-dbgsym libcharon-extra-plugins-dbgsym libcom-err2-dbgsym libgcrypt20-dbgsym libgmp10-dbgsym libgnutls30t64-dbgsym libkeyutils1-dbgsym libkrb5-dbg liblzma5-dbgsym libnettle8t64-dbgsym libnghttp2-14-dbgsym libp11-kit0-dbgsym libpam0g-dbgsym libpsl5t64-dbgsym librtmp1-dbgsym libsasl2-2-dbgsym libssh-4-dbgsym libssl3t64-dbgsym libstrongswan-dbgsym libstrongswan-extra-plugins-dbgsym libstrongswan-standard-plugins-dbgsym libtasn1-6-dbgsym libtss2-mu-4.0.1-0t64-dbgsym libtss2-sys1t64-dbgsym libunistring5-dbgsym libzstd1-dbgsym strongswan-charon-dbgsym strongswan-libcharon-dbgsym strongswan-starter-dbgsym strongswan-swanctl-dbgsym zlib1g-dbgsym
```

## LLDB libStrongSwan

```bash
(lldb) script import lldb as L; t=L.debugger.GetSelectedTarget(); print("\n".join([ (m.GetFileSpec().GetDirectory() or "") + "/" + (m.GetFileSpec().GetFilename() or "") for i in range(t.GetNumModules()) for m in [t.GetModuleAtIndex(i)] if any(k in (((m.GetFileSpec().GetDirectory() or "") + "/" + (m.GetFileSpec().GetFilename() or "")).lower()) for k in ("strongswan","libstrongswan","ipsec","charon")) ]))
/usr/lib/ipsec/charon
/usr/lib/ipsec/libstrongswan.so.0
/usr/lib/ipsec/libcharon.so.0
/usr/lib/ipsec/plugins/libstrongswan-test-vectors.so
/usr/lib/ipsec/plugins/libstrongswan-ldap.so
/usr/lib/ipsec/plugins/libstrongswan-pkcs11.so
/usr/lib/ipsec/plugins/libstrongswan-tpm.so
/usr/lib/ipsec/libtpmtss.so.0
/usr/lib/ipsec/plugins/libstrongswan-aes.so
/usr/lib/ipsec/plugins/libstrongswan-rc2.so
/usr/lib/ipsec/plugins/libstrongswan-sha2.so
/usr/lib/ipsec/plugins/libstrongswan-sha1.so
/usr/lib/ipsec/plugins/libstrongswan-md5.so
/usr/lib/ipsec/plugins/libstrongswan-mgf1.so
/usr/lib/ipsec/plugins/libstrongswan-random.so
/usr/lib/ipsec/plugins/libstrongswan-nonce.so
/usr/lib/ipsec/plugins/libstrongswan-x509.so
/usr/lib/ipsec/plugins/libstrongswan-revocation.so
/usr/lib/ipsec/plugins/libstrongswan-constraints.so
/usr/lib/ipsec/plugins/libstrongswan-pubkey.so
/usr/lib/ipsec/plugins/libstrongswan-pkcs1.so
/usr/lib/ipsec/plugins/libstrongswan-pkcs7.so
/usr/lib/ipsec/plugins/libstrongswan-pkcs12.so
/usr/lib/ipsec/plugins/libstrongswan-pgp.so
/usr/lib/ipsec/plugins/libstrongswan-dnskey.so
/usr/lib/ipsec/plugins/libstrongswan-sshkey.so
/usr/lib/ipsec/plugins/libstrongswan-pem.so
/usr/lib/ipsec/plugins/libstrongswan-openssl.so
/usr/lib/ipsec/plugins/libstrongswan-gcrypt.so
/usr/lib/ipsec/plugins/libstrongswan-pkcs8.so
/usr/lib/ipsec/plugins/libstrongswan-af-alg.so
/usr/lib/ipsec/plugins/libstrongswan-fips-prf.so
/usr/lib/ipsec/plugins/libstrongswan-gmp.so
/usr/lib/ipsec/plugins/libstrongswan-curve25519.so
/usr/lib/ipsec/plugins/libstrongswan-agent.so
/usr/lib/ipsec/plugins/libstrongswan-chapoly.so
/usr/lib/ipsec/plugins/libstrongswan-xcbc.so
/usr/lib/ipsec/plugins/libstrongswan-cmac.so
/usr/lib/ipsec/plugins/libstrongswan-hmac.so
/usr/lib/ipsec/plugins/libstrongswan-kdf.so
/usr/lib/ipsec/plugins/libstrongswan-ctr.so
/usr/lib/ipsec/plugins/libstrongswan-ccm.so
/usr/lib/ipsec/plugins/libstrongswan-gcm.so
/usr/lib/ipsec/plugins/libstrongswan-ntru.so
/usr/lib/ipsec/plugins/libstrongswan-drbg.so
/usr/lib/ipsec/plugins/libstrongswan-curl.so
/usr/lib/ipsec/plugins/libstrongswan-attr.so
/usr/lib/ipsec/plugins/libstrongswan-kernel-netlink.so
/usr/lib/ipsec/plugins/libstrongswan-resolve.so
/usr/lib/ipsec/plugins/libstrongswan-socket-default.so
/usr/lib/ipsec/plugins/libstrongswan-connmark.so
/usr/lib/ipsec/plugins/libstrongswan-forecast.so
/usr/lib/ipsec/plugins/libstrongswan-farp.so
/usr/lib/ipsec/plugins/libstrongswan-stroke.so
/usr/lib/ipsec/plugins/libstrongswan-vici.so
/usr/lib/ipsec/plugins/libstrongswan-updown.so
/usr/lib/ipsec/plugins/libstrongswan-eap-identity.so
/usr/lib/ipsec/plugins/libstrongswan-eap-aka.so
/usr/lib/ipsec/libsimaka.so.0
/usr/lib/ipsec/plugins/libstrongswan-eap-md5.so
/usr/lib/ipsec/plugins/libstrongswan-eap-gtc.so
/usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so
/usr/lib/ipsec/plugins/libstrongswan-eap-dynamic.so
/usr/lib/ipsec/plugins/libstrongswan-eap-radius.so
/usr/lib/ipsec/libradius.so.0
/usr/lib/ipsec/plugins/libstrongswan-eap-tls.so
/usr/lib/ipsec/libtls.so.0
/usr/lib/ipsec/plugins/libstrongswan-eap-ttls.so
/usr/lib/ipsec/plugins/libstrongswan-eap-peap.so
/usr/lib/ipsec/plugins/libstrongswan-eap-tnc.so
/usr/lib/ipsec/libtnccs.so.0
/usr/lib/ipsec/plugins/libstrongswan-xauth-generic.so
/usr/lib/ipsec/plugins/libstrongswan-xauth-eap.so
/usr/lib/ipsec/plugins/libstrongswan-xauth-pam.so
/usr/lib/ipsec/plugins/libstrongswan-tnc-tnccs.so
/usr/lib/ipsec/plugins/libstrongswan-dhcp.so
/usr/lib/ipsec/plugins/libstrongswan-ha.so
/usr/lib/ipsec/plugins/libstrongswan-lookip.so
/usr/lib/ipsec/plugins/libstrongswan-error-notify.so
/usr/lib/ipsec/plugins/libstrongswan-certexpire.so
/usr/lib/ipsec/plugins/libstrongswan-led.so
/usr/lib/ipsec/plugins/libstrongswan-addrblock.so
/usr/lib/ipsec/plugins/libstrongswan-unity.so
/usr/lib/ipsec/plugins/libstrongswan-counters.so
```


Next we want to 

```bash
(lldb) breakpoint set --name prf_plus
Breakpoint 6: no locations (pending).
WARNING:  Unable to resolve breakpoint to any actual locations.
(lldb) breakpoint set --name create_kdf
Breakpoint 7: where = libstrongswan.so.0`create_kdf, address = 0x0000fcee4e555200
# alternativly: breakpoint set --name create_kdf --shlib usr/lib/ipsec/libstrongswan.so.0
(lldb) breakpoint set --name ike_derived_keys 
Breakpoint 8: where = libcharon.so.0`ike_derived_keys, address = 0x0000fcee4e46cf14
(lldb) breakpoint set --name set_aead_keys
Breakpoint 9: where = libcharon.so.0`derive_ike_keys + 1872, address = 0x0000fcee4e4a3490
(lldb) breakpoint set --name chunk_split
Breakpoint 3: where = libstrongswan.so.0`chunk_split, address = 0x0000efc1ac2f4ee0
```


 Run our debugging script:
```bash
command script import /tmp/lldb_chunk_split.py
command script import /media/psf/tls-haze/keylifespan/ipsec/setup/strongswan/lldb_debug/lldb_chunk_split.py


(lldb) command script import /media/psf/tls-haze/keylifespan/ipsec/setup/strongswan/lldb_debug/lldb_chunk_split.py
Commands installed: install_chunk_split_bp, set_chunk_split_log, chunk_split_args
(lldb) install_chunk_split_bp 
Installed chunk_split entry breakpoint id=2 (will auto-set return breakpoint).
[2025-09-23 16:04:15] Installed chunk_split entry breakpoint id=2.
```


Instead of installing it directly we can also invoke lldb with this script:
```bash
 x0 = 0xf4b564002410
    -> 0xf4b564002410 : 67 78 a8 7a fb 6c c6 fe e8 c4 b9 de 9e 68 3d 33 ee b6 95 d5 e0 50 51 73 88 49 b0 aa 57 81 5b e4 2c 58 9d 89 84 64 8d 88 cb 16 b3 81 82 59 2d 89 02 d3 4c b5 96 af 25 17 f7 03 9a 22 3c 19 c2 70  |gx.z.l.......h=3.....PQs.I..W.[.,X...d.......Y-...L...%...."<..p|
 x1 = 0xe0
 x2 = 0xf4b589f68a38
    -> 0xf4b589f68a38 : 61 6d 6d 6d 6d 61 61 00 53 6b 5f 64 20 73 65 63 72 65 74 20 25 42 00 00 53 6b 5f 61 69 20 73 65 63 72 65 74 20 25 42 00 53 6b 5f 61 72 20 73 65 63 72 65 74 20 25 42 00 53 6b 5f 65 69 20 73 65  |ammmmaa.Sk_d secret %B..Sk_ai secret %B.Sk_ar secret %B.Sk_ei se|


...
=== register args (x0..x7) ===
 x0 = 0xf4b5540037a0
    -> 0xf4b5540037a0 : 4e e8 62 47 ef c2 b6 c2 91 db fc 5a 7b 00 b0 de d1 36 2e 67 c5 e1 8b 61 75 03 bd a0 ec e1 23 97 2b 49 3a b2 e2 06 4b 1f 42 a2 c3 a4 49 4e 6a 49 4a 00 77 21 67 68 e7 45 c1 dc e9 55 cb 03 da 34  |N.bG.......Z{....6.g...au.....#.+I:...K.B...INjIJ.w!gh.E...U...4|
 x1 = 0x80
 x2 = 0xf4b589f68df8
    -> 0xf4b589f68df8 : 61 61 61 61 00 00 00 00 65 6e 63 72 79 70 74 69 6f 6e 20 69 6e 69 74 69 61 74 6f 72 20 6b 65 79 20 25 42 00 00 00 00 00 65 6e 63 72 79 70 74 69 6f 6e 20 72 65 73 70 6f 6e 64 65 72 20 6b 65 79  |aaaa....encryption initiator key %B.....encryption responder key|


 --> ESP-Key

(lldb) install_chunk_split_bp
Installed chunk_split entry breakpoint id=2 (auto return bp).
[2025-09-27 17:54:00] Installed chunk_split entry breakpoint id=2.
(lldb) set_chunk_split_log '/tmp/chunk-split-19421.log'
Log template set to: '/tmp/chunk-split-19421_{pid}_{time}.log'
Effective path now : '/tmp/chunk-split-19421_19421_1758988440.log'
(lldb) continue


[2025-09-27 17:54:45] [KEYMAT] @0xf4b560008780 len=0xe0 (224 bytes) fmt='ammmmaa'
0x0000f4b560008780  37 d2 d8 3d 50 32 0a 4a 31 60 cf 42 32 bf b6 92  |7..=P2.J1`.B2...|
0x0000f4b560008790  2c b8 5f 8b 2b 19 6e 20 84 6a 23 0c 80 98 34 f9  |,._.+.n .j#...4.|
0x0000f4b5600087a0  bd 70 3e 0d 95 72 bf 37 d5 ff a1 4d 1c 82 94 8f  |.p>..r.7...M....|
0x0000f4b5600087b0  68 ef 47 17 71 fc 20 63 24 9f 81 44 23 70 73 83  |h.G.q. c$..D#ps.|
0x0000f4b5600087c0  6d 60 b0 48 b2 f5 09 eb c6 ea fc d8 8e 50 32 75  |m`.H.........P2u|
0x0000f4b5600087d0  49 0f 98 ba e3 43 5e 43 64 2d a8 b3 c4 29 26 fe  |I....C^Cd-...)&.|
0x0000f4b5600087e0  ce 1c 53 77 ea 47 6c 2b 3d fb f8 5b 8b e5 c9 3e  |..Sw.Gl+=..[...>|
0x0000f4b5600087f0  12 85 9c 99 a0 82 15 1b 6a 86 0d bf ad 6b 81 71  |........j....k.q|
0x0000f4b560008800  ae 89 ac 75 26 01 51 b3 82 05 77 2d 50 ac 51 06  |...u&.Q...w-P.Q.|
0x0000f4b560008810  db 48 2a ca 69 28 3b c7 d0 dd bc d5 32 2a 4c 01  |.H*.i(;.....2*L.|
0x0000f4b560008820  09 f8 97 7e 9f 26 8f c1 21 d5 22 9c 7d 34 bf a4  |...~.&..!.".}4..|
0x0000f4b560008830  4b c2 a5 9b ee 24 7a 3a 27 8c 3f 86 e7 e6 95 9b  |K....$z:'.?.....|
0x0000f4b560008840  e5 64 4d fd 10 b9 81 00 ce 23 e3 72 1d 00 d6 e5  |.dM......#.r....|
0x0000f4b560008850  21 69 77 9f ab b3 bf f2 9d 34 34 8e cd b6 ca 8d  |!iw......44.....|
[2025-09-27 17:54:45] [KEYMAT SPLIT] IKE SA
Total: 0xe0 bytes
  SK_d   (0x20): 37d2d83d50320a4a3160cf4232bfb6922cb85f8b2b196e20846a230c809834f9
  SK_ai  (0x20): bd703e0d9572bf37d5ffa14d1c82948f68ef471771fc2063249f814423707383
  SK_ar  (0x20): 6d60b048b2f509ebc6eafcd88e503275490f98bae3435e43642da8b3c42926fe
  SK_ei  (0x20): ce1c5377ea476c2b3dfbf85b8be5c93e12859c99a082151b6a860dbfad6b8171
  SK_er  (0x20): ae89ac75260151b38205772d50ac5106db482aca69283bc7d0ddbcd5322a4c01
  SK_pi  (0x20): 09f8977e9f268fc121d5229c7d34bfa44bc2a59bee247a3a278c3f86e7e6959b
  SK_pr  (0x20): e5644dfd10b98100ce23e3721d00d6e52169779fabb3bff29d34348ecdb6ca8d
[2025-09-27 17:54:45] Return breakpoint set at 0xf4b589f233cc (id=4). Continuing.
```

Other ideas for hooking:
- chunk_split (https://github.com/strongswan/strongswan/blob/ac0272cad12f0b3dbe5432111d034fa7b6192f82/src/libcharon/sa/ikev2/keymat_v2.c#L423C2-L423C13)
- ike_derived_keys ()
- set_aead_keys (https://github.com/strongswan/strongswan/blob/ac0272cad12f0b3dbe5432111d034fa7b6192f82/src/libcharon/sa/ikev2/keymat_v2.c#L217)



## Kernel Memory Dump using DRGN


### Install drgn

```bash
$ python3 -m venv env/
$ source env/bin/activate
(env) $ pip3 install drgn
(env) $ sudo apt-get update
(env) $ sudo apt-get install -y build-essential pkg-config python3-dev libelf-dev libdw-dev zlib1g-dev libzstd-dev libbpf-dev linux-headers-$(uname -r)
(env) $ pip3 install --no-binary=:all: drgn
```

### Install Debug Symbols of running kernel

- Ubuntu Preperations
- More infos at: https://drgn.readthedocs.io/en/latest/getting_debugging_symbols.html?fbclid=IwY2xjawNB4FlleHRuA2FlbQIxMQABHuskVEUVrA7TYOhtPnJ6aBg1to6hmpfEhTXOj6E9p-Fcwb7qJUS-G9NgA-ze_aem_cuU126vwp2mLm2kDwYgG0g#id7

```bash
sudo apt install libdebuginfod-common
source /etc/profile.d/debuginfod.sh
sudo apt install linux-image-$(uname -r)-dbgsym
```

### Dump XFRM State

Now we have everything in order to run the kernel dump
```bash
sudo NETNS_FILE=/var/run/netns/left "$(python3 -c 'import sys; print(sys.executable)')" ./dump_xfrm_drgn.py
missing debugging symbols for tls
missing debugging symbols for ib_core
missing debugging symbols for tcp_diag
missing debugging symbols for inet_diag
missing debugging symbols for authenc
... missing 93 more
[*] Selecting net via NETNS_FILE=/var/run/netns/left
[✓] Resolved struct net at 18446462600572511232 (ns.inum=4026532323)
[*] Output dir: /tmp/xfrm-dump-4026532323-20250925-165315
[*] States via state_bydst (mask=7, link=byspi)
[*] Policies via policy_byidx (mask=7, link=byidx)
[✓] Dump complete -> /tmp/xfrm-dump-4026532323-20250925-165315 (states=2, policies=3)

```
