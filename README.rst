=========
zeroTLS
=========

Minimalistic TLS 1.2 client, that is good enough to connect to most web hosts. Requires no runtime memory
allocations.

It is also a continuation of my work on tinyTLS. Not all the features of tinyTLS are supported, but zeroTLS
does not leak memory (by design) and does not have as much potential of RCE exploits.


NOTICE
--------

**This project is WORK-IN-PROGRESS**. It's definitely not secure.


Requirements
--------------

In order to build zeroTLS you need:

* CMake version 3.0 or higher.
* Any C++11 compiler.
* *optional* Node.js version 0.10 or higher.


Use cases
-----------

It's important to understand that zeroTLS does not fit every purpose. zeroTLS is designed to be small and fit many 
devices and platforms, which can't use other implementations reliably.

* It's not designed for web browsers as it isn't going to support every cipher suite and extension.
* It's not designed for server, because it lacks server components and does not even try to mitigate 
  server-specific exploits.
* It's not for 10yr future-proof designs as it lacks modularity, allowing you to reconfigure it easily.
* It's not going to set speed records, because that typically means taking up more space.

There are many lightweight cryptographic libraries available, even with TLS support, even targeting microcontroller applications. But TLS libraries are rarely optimized for RAM usage. There are many examples of TLS libraries claiming to work with only 1KB of memory. Upon further inspection you figure out that this is only "static" memory and undetermined amount of memory will be allocated in the runtime. Or sometimes claim of 1KB turnes out to be true for only the most stripped-down configurations -- only for PSK mode with no server authentication. That is of little value, considering that most HTTPS server software does not implement PSK. 

zeroTLS takes no shortcuts:

* Tested agains real HTTPS deployments,
* Only uses one static memory allocation,
* ... which contains no pointers and can be moved by GC,
* Able to fetch results from popular search engines with no more than 4KB,
* Still has more room for improvement.

Supported ciphers
~~~~~~~~~~~~~~~~~~~

zeroTLS implements only a required minimum: TLS_RSA_WITH_AES_128_CBC_SHA. 

Eventually i want to include ECDHE, based on x25519, and AES128-GCM.

Certificate validation
~~~~~~~~~~~~~~~~~~~~~~~~

Currently none. Basic constraints and DNS name in AltSubjectName extension are checked but all the signatures are left unverified.
