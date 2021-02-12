#
# tinyTLS / zeroTLS project
# 
# Copyright 2015-2020 Nesterov A.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
# http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

add_definitions(-DTINYTLS_DEBUG)

add_library(zerotls STATIC
	intutils.h

	simd_ssse3.h

	# AES implementation
	aes/aes_tables.h
	aes/rijndael.cpp
	aes/rijndael.h

	# GHASH implementation
	#gcm/ghash_cmul1.h  # Historic, will not be used
	gcm/ghash_cmul2.h

	# SHA hashes
	hash/hash.h
	hash/hmac.cpp
	hash/md5.cpp
	hash/sha1.cpp
	hash/sha256.cpp
	hash/sha512.cpp

	pkcs1/bigint.cpp
	pkcs1/bigint.h
	pkcs1/pkcs1.cpp
	pkcs1/pkcs1.h

	aes_hmac_sha.cpp
	aes_hmac_sha.h

	aes128_gcm.cpp
	aes128_gcm.h

	cipherstate.h

	prf.cpp

	context.h
	random.h

	signature.cpp
	signature.h

	x509.h
	x509.cpp
	
	tls.cpp
	tls.h
	
	debug.cpp
	
	handshake.cpp
)