
# NIST ExaBGPsec 
ExaBGPsec uses NIST SRxCrypto library to facilitate cryptographic calculations
which is able to deal with X.509 objects for BGPSec path validation. 
This software is based on [Exabgp](https://github.com/Exa-Networks/exabgp) BGP implementation and added codes for implementing
BGPSec protocol ([RFC 8205](https://tools.ietf.org/html/rfc8205)).


## Project Status
Active development



## Getting Started

Recommendation for running </br>
You need a working python environment. 
* python version > 3.5


### Prerequisites
GoBGPsec requires to use this crypto library for signing and validation when the BGPSec operation starts.
* Need to install SRxCryptoAPI library first  
* Need SRxCryptoAPI library >= v3.0

Download NIST SRx software from the link below. 
```bash
git clone https://github.com/usnistgov/NIST-BGP-SRx.git
```

And then build with buildBGP-SRx.sh script.
It will install automatically all the packages.
```bash
./buildBGP-SRx.sh
```
or you might install individual modules, for example, only install SRxCryptoAPI library with
following command.
```
cd srx-crypto-api
./configure --prefix=<Dir/to/install> CFLAGS="-O0 -g"
```
<br>
For more information such as key generation for signing and etc,
please refer to [NIST SRxCryptoAPI](https://github.com/usnistgov/NIST-BGP-SRx/tree/master/srx-crypto-api) page.
<br>


### Running Exabgpsec
To run Exabgpsec, simply use exabgp command with a configuration file 
```
$ env exabgp.daemon.user=root exabgp <config_file>
```
or if exabgp is not already in PATH envrironment to execute, go to the root directory of 
this software where you downloaded, and execute the command below.
```
$ env exabgp.daemon.user=root /path_to_exabgpsec/sbin/exabgp <config_file>
```
</br></br>

### BGPSec Configuration
[ExaBGPsec Configuration](README_bgpsec.md)
</br></br>

### Quick Functional Test / Demo
exabgpsec start 
```bash
# env exabgp.daemon.user=root exabgp /etc/exabgp.conf
04:41:30 | 1      | welcome       | Thank you for using ExaBGP
04:41:30 | 1      | version       | bgpsec-4.1.2-6701eaedb6c01f0f9d37d5efc742710964a99eb9
04:41:30 | 1      | interpreter   | 3.6.8 (default, Apr  2 2020, 13:34:55)  [GCC 4.8.5 20150623 (Red Hat 4.8.5-39)]
04:41:30 | 1      | os            | Linux 110a6db220f8 3.10.0-1062.1.1.el7.x86_64 #1 SMP Fri Sep 13 22:55:44 UTC 2019 x86_64
04:41:30 | 1      | installation  | /root/exabgp
04:41:30 | 1      | configuration | performing reload of exabgp bgpsec-4.1.2-6701eaedb6c01f0f9d37d5efc742710964a99eb9
04:41:30 | 1      | reactor       | loaded new configuration successfully
04:41:30 | 1      | reactor       | connected to peer-1 with outgoing-1 172.37.0.2-172.37.0.3
[SRxCryptoAPI - INFO] Preset local wrapper for all methods!
[SRxCryptoAPI - INFO] Use crypto configuration located in //etc//srxcryptoapi.conf
[SRxCryptoAPI - INFO] Use configuration file "//etc//srxcryptoapi.conf"
[SRxCryptoAPI - INFO] - debug type: not configured! use value 6
[SRxCryptoAPI - INFO] - key_volt="/var/lib/bgpsec-keys/"
[SRxCryptoAPI - INFO] - key_ext_private="der"
[SRxCryptoAPI - INFO] - key_ext_public="cert"
[SRxCryptoAPI - INFO] - library_name="libSRxBGPSecOpenSSL.so"
[SRxCryptoAPI - INFO] - init_value="PUB:/var/lib/bgpsec-keys/ski-list.txt;PRIV:/var/lib/bgpsec-keys/priv-ski-list.txt"
[SRxCryptoAPI - INFO] - method_init="init"
[SRxCryptoAPI - INFO] - method_release="release"
[SRxCryptoAPI - INFO] - method_freeHashMessage="freeHashMessage"
[SRxCryptoAPI - INFO] - method_freeSignature="freeSignature"
[SRxCryptoAPI - INFO] - method_getDebugLevel="getDebugLevel"
[SRxCryptoAPI - INFO] - method_setDebugLevel="setDebugLevel"
[SRxCryptoAPI - INFO] - method_isAlgorithmSupported="isAlgorithmSupported"
[SRxCryptoAPI - INFO] - method_sign="sign"
[SRxCryptoAPI - INFO] - method_validate="validate"
[SRxCryptoAPI - INFO] - method_registerPrivateKey="registerPrivateKey"
[SRxCryptoAPI - INFO] - method_unregisterPrivateKey="unregisterPrivateKey"
[SRxCryptoAPI - INFO] - method_registerPublicKey="registerPublicKey"
[SRxCryptoAPI - INFO] - method_unregisterPublicKey="unregisterPublicKey"
[SRxCryptoAPI - INFO] - method_cleanKeys="cleanKeys"
[SRxCryptoAPI - INFO] - method_cleanPrivateKeys="cleanPrivateKeys"
[SRxCryptoAPI - INFO] Linking "init" to "init"!
[SRxCryptoAPI - INFO] Linking "release" to "release"!
[SRxCryptoAPI - INFO] Linking "freeHashMessage" to "freeHashMessage"!
[SRxCryptoAPI - INFO] Linking "freeSignature" to "freeSignature"!
[SRxCryptoAPI - INFO] Linking "setDebugLevel" to "setDebugLevel"!
[SRxCryptoAPI - INFO] Linking "getDebugLevel" to "getDebugLevel"!
[SRxCryptoAPI - INFO] Linking "isAlgorithmSupported" to "isAlgorithmSupported"!
[SRxCryptoAPI - INFO] Linking "sign" to "sign"!
[SRxCryptoAPI - INFO] Linking "validate" to "validate"!
[SRxCryptoAPI - INFO] Linking "registerPublicKey" to "registerPublicKey"!
[SRxCryptoAPI - INFO] Linking "unregisterPublicKey" to "unregisterPublicKey"!
[SRxCryptoAPI - INFO] Linking "registerPrivateKey" to "registerPrivateKey"!
[SRxCryptoAPI - INFO] Linking "unregisterPrivateKey" to "unregisterPrivateKey"!
[SRxCryptoAPI - INFO] Linking "cleanKeys" to "cleanKeys"!
[SRxCryptoAPI - INFO] Linking "cleanPrivateKeys" to "cleanPrivateKeys"!
[SRxCryptoAPI - INFO] Initiate library initialization using 'PUB:/var/lib/bgpsec-keys/ski-list.txt;PRIV:/var/lib/bgpsec-keys/priv-ski-list.txt'
+--------------------------------------------------------------+
| API: libBGPSec_OpenSSL.so                                    |
| WARNING: This API provides a reference implementation for    |
| BGPSec crypto processing. The key storage provided with this |
| API does not provide a 'secure' key storage which protects   |
| against malicious side attacks. Also it is not meant to be   |
| a FIBS certified key storage.                                |
| This API uses open source OpenSSL functions and checks, keys |
| for their correctness and once done, uses it repeatedly!     |
+--------------------------------------------------------------+
[SRxCryptoAPI - INFO] The internal key initialized storage holds (11 private and 5 public keys)!
srxCryptoInit return value 1 (API_SUCCESS:1 or API_FAILURE:0)
```
</br></br>
</br></br>

## With Docker
**TBD**
</br></br>


## Authors & Main Contributors
Kyehwan Lee (kyehwanl@nist.gov)
</br></br>


## Contact
Kyehwan Lee (kyehwanl@nist.gov)
</br></br>



## Copyright

### DISCLAIMER
Exabgpsec was developed for applying BGPSec Routing software, NIST BGP-SRx
into ExaBGP by employees of the Federal Government in the course of their 
official duties. NIST BGP-SRx is an open source BGPSec implementation for 
supporting RPKI and BGPSec protocol specification in RFC. 
Additional information can be found at [BGP Secure Routing Extension (BGP‑SRx) Prototype](https://www.nist.gov/services-resources/software/bgp-secure-routing-extension-bgp-srx-prototype)


NIST assumes no responsibility whatsoever for its use by other parties,
and makes no guarantees, expressed or implied, about its quality,
reliability, or any other characteristic.

This software might use libraries that are under original license of
ExaBGP or other licenses. Please refer to the licenses of all libraries 
required by this software.



