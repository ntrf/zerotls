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

#ifndef X509_H_
#define X509_H_

#include <stdint.h>

#include "pkcs1/pkcs1.h"

/* Certificate usage */
enum
{
	CERTUSAGE_KEY_AGREEMENT = (1 << 0),
	CERTUSAGE_KEY_ENCRYPTION = (1 << 1),
	CERTUSAGE_DATA_ENCRYPTION = (1 << 2),
	CERTUSAGE_SIGNATURE = (1 << 3),
	CERTUSAGE_CA = (1 << 12),

	CERT_DOMAIN_MATCH = (1 << 13),
};

struct CertificateInfo{
	uint8_t keyType;
	uint8_t signType;
	uint16_t restricted;

	int32_t chainLength;

	BinarySlice publicKey;
	BinarySlice signature;

	BinarySlice issuer;
	BinarySlice subject;

	uint32_t payloadOffset;
	uint32_t payloadLength;
};

//extract public key form X.509 certificate
int ExtractCertificateInfo(CertificateInfo * out, int length, const uint8_t * source, const char * hostname = NULL);

int Extract_PKCS1_RSA_PublicKeyComponents(PKCS1_RSA_PublicKey * out, int length, const uint8_t * source);
#if 0
int Extract_PKCS1_RSA_PrivateKeyComponents(PKCS1_RSA_PrivateKey * out, int length, const uint8_t * source);

int VerifyCertificateChain(TinyTLSContext * ctx, const BinarySlice * certs, CertificateInfo * cert_storage, size_t count);
#endif

#endif