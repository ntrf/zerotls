/*
tinyTLS / zeroTLS project

Copyright 2015-2020 Nesterov A.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef SIGNATURE_H_
#define SIGNATURE_H_

enum
{
	SIGTYPE_UNKNOWN = 0,

	PKCS1_RSAES,

	// special value for TLS 1.0 client certificate verify
	// payload is not prefixed with algorithm identifier
	// and is exactly 36 bytes
	PKCS1_SSA_TLSVERIFY,

	PKCS1_SSA_MD5,

	PKCS1_SSA_SHA1,
	PKCS1_SSA_SHA256,
	PKCS1_SSA_SHA384,
	PKCS1_SSA_SHA512,

	// the first trusted signature type
	// everything bellow will fail to validate
	PKCS1_SSA_TRUSTED = PKCS1_SSA_SHA256
};

int GetSignatureAlgorithmType(const uint8_t * oid, uint32_t length);
int GetSignatureSize(int sigtype);
int ComputeSignatureHash(int sigtype, const uint8_t * data, unsigned length, uint32_t * hash);

#endif