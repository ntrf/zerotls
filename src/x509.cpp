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

/* X.509 v3 Certificate handling
 * Module implements ASN.1 parsing, extraction of certificate data,
 * certificate chain validation.
 * Based on infromation from RFC 5280 (http://tools.ietf.org/html/rfc5280)
 */
#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "signature.h"
#include "x509.h"

//#include "internal.h"

//#include "pkcs1/pkcs1.h"

//using namespace TinyTLS;

#ifdef TINYTLS_DEBUG
extern void printASN1(int length, const uint8_t * source);
extern void printASN1(const struct ASNElement & el);
#endif

#define OID_FIRST(A, B) ((A) * 40 + (B))

enum {
	TAG_BOOLEAN = 0x01,
	TAG_INTEGER = 0x02,
	TAG_BIT_STRING = 0x03,
	TAG_OCTET_STRING = 0x04,
	TAG_NULL = 0x05,
	TAG_OBJECT_IDENTIFIER = 0x06,
	TAG_SEQUENCE = 0x10,
	TAG_SET = 0x11,
	TAG_PrintableString = 0x13,
	TAG_T61String = 0x14,
	TAG_IA5String = 0x16,
	TAG_UTCTime = 0x17
};

enum
{
	TAG_MAX_LENGTH = 0x10000,
	TAG_MAX_ID = 0x10000,
};

struct Tag{
	short scope;
	short tag;
	int length;
};

static int parseObjId(short & ret, const uint8_t * & stream, const uint8_t * end)
{
	uint8_t h;
	uint32_t t = 0;
	do {
		if (stream >= end) return 0;
		t = (t << 7) | ((h = *stream++) & 0x7f);
		if (t > TAG_MAX_ID) return 0;
	} while (h & 0x80);

	ret = t;

	return 1;
}

static int parseInteger(int length, const uint8_t * & stream)
{
	int l = 0; // negative values
	for (int k = length <= 4 ? length : 4; k != 0; --k) {
		l = (l << 8) | (*stream++);
	}
	return l;
}

static Tag parseTag(const uint8_t * & stream, const uint8_t * end)
{
	Tag tag;

	// invalid length
	tag.length = 0;
	tag.tag = 0;
	tag.scope = 0;

	if (stream >= end)
		return tag;

	uint8_t h = *stream++;
	tag.scope = (h >> 5) & 7;
	h &= 0x1f;
	if(h == 0x1f) {
		if (parseObjId(tag.tag, stream, end) <= 0)
			return tag;
	} else {
		tag.tag = h;
	}

	if (stream >= end)
		return tag;

	h = *stream++;
	if (h < 0x80) {
		tag.length = h;
		return tag;
	} else {
		h -= 0x80;
		if (h > 4)
			return tag;

		if (stream + (size_t)h > end) // check length is not overflowing
			return tag;

		tag.length = parseInteger(h, stream);
		return tag;
	}
}

struct ASNElement
{
	const uint8_t * ptr;
	const uint8_t * lim;

	ASNElement() : ptr(0), lim(0) {}
	ASNElement(const uint8_t * p, const uint8_t * limit) : ptr(p), lim(limit) {}

	Tag tag() const
	{
		const uint8_t * s = ptr;
		return parseTag(s, lim);
	}

	ASNElement next() const
	{
		const uint8_t * s = ptr;
		Tag tag = parseTag(s, lim);
		
		return ASNElement(s + tag.length, lim);
	}

	ASNElement next(int n) const
	{
		const uint8_t * s = ptr;
		for(;n > 0; --n)
		{
			Tag tag = parseTag(s, lim);
			if (tag.length > TAG_MAX_LENGTH) {
				s = lim;
				break;
			}

			s += tag.length;
		}
		
		return ASNElement(s, lim);
	}

	ASNElement firstChild() const
	{
		const uint8_t * s = ptr;
		Tag tag = parseTag(s, lim);

		return ASNElement(s, s + tag.length);
	}
	ASNElement child(int n) const
	{
		const uint8_t * s = ptr;
		Tag tag = parseTag(s, lim);
		const uint8_t * se = ptr + tag.length;

		for(;n > 0; --n)
		{
			tag = parseTag(s, se);
			s += tag.length;
		}
		
		return ASNElement(s, s + tag.length);
	}

	unsigned length()
	{
		const uint8_t * s = ptr;
		Tag t = parseTag(s, lim);
		if(t.tag == TAG_BIT_STRING)
			t.length -= 1;
		return t.length;
	}
	void extract(uint8_t * buf)
	{
		const uint8_t * s = ptr;
		Tag t = parseTag(s, lim);
		if(t.tag == TAG_BIT_STRING) 
			t.length -= 1, s += 1;
		memcpy(buf, s, t.length);
	}

	const uint8_t * access(size_t & len) const
	{
		const uint8_t * s = ptr;
		Tag t = parseTag(s, lim);
		if (t.tag == TAG_BIT_STRING)
			t.length -= 1, s += 1;
		len = t.length;
		return s;
	}

	void accessSlice(BinarySlice & slice) const
	{
		const uint8_t * s = ptr;
		Tag t = parseTag(s, lim);
		if (t.tag == TAG_BIT_STRING)
			t.length -= 1, s += 1;
		slice.length = t.length;
		slice.data = s;
	}

	int compare(const uint8_t * data, size_t len) const
	{
		const uint8_t * s = ptr;
		Tag t = parseTag(s, lim);
		if (t.tag == TAG_BIT_STRING)
			t.length -= 1, s += 1;
		if (len != t.length) return (int)(t.length - len);
		return memcmp(s, data, len);
	}

	int getInt() const
	{
		const uint8_t * s = ptr;
		Tag t = parseTag(s, lim);
		return parseInteger(t.length, s);
	}
	
	inline ASNElement begin() const { return firstChild(); }
	inline ASNElement end() const { return next(); }

	bool operator == (const ASNElement & b) const { return ptr == b.ptr; }
	bool operator != (const ASNElement & b) const { return ptr != b.ptr; }
	bool operator < (const ASNElement & b) const { return ptr < b.ptr; }
	bool operator <= (const ASNElement & b) const { return ptr <= b.ptr; }
};

//-------------------------------------------------------------------

// ### check for non-rsa algorithms
int ExtractAlgorithmId(ASNElement & el)
{
	// SEQUENCE
	//   OBJID --algoid
	//   NULL --params

	ASNElement oid = el.firstChild();
	size_t length = 0;
	const uint8_t * data = oid.access(length);

	return GetSignatureAlgorithmType(data, length);
}
//-------------------------------------------------------------------

// 2.5.4 - prefix
//  .3 - [CN] common name
//
//  .4 - surname
//  .5 - serial number
//  .6 - [C] country
//  .7 - [L] locality name
//  .8 - [ST] state
//  .10 - [O] organization
//  .11 - [OU] org. unit
//  .46 - dn qualifier
//  .65 - pseudonym

static const uint8_t RdnCommonName[] = {OID_FIRST(2, 5), 4, 3};

#if 0
// ### RDN normalization
struct OID_To_RFC2253
{
	unsigned int id;
	const uint8_t * abbr;
};

#define ATTR_ID(A,B,C,D) (OID_FIRST(A,B) | ((C) << 8) | ((D) << 16))
static const OID_To_RFC2253 RecognizededFields[] = {
	{ATTR_ID(2, 5, 4, 3), "CN"}, // common name (e.g., "Susan Housley"),
	{ATTR_ID(2, 5, 4, 5), NULL}, // serial number.
	{ATTR_ID(2, 5, 4, 6), "C"}, // country,
	{ATTR_ID(2, 5, 4, 7), "L"}, // locality, (optional)
	{ATTR_ID(2, 5, 4, 8), "ST"}, // state or province name,
	{ATTR_ID(2, 5, 4, 10), "O"}, // organization,
	{ATTR_ID(2, 5, 4, 11), "OU"}, // organizational-unit,
	{ATTR_ID(2, 5, 4, 46), NULL}, // distinguished name qualifier,

	{0, NULL}
};

int ExtractDistinguishedName(Binary & dn, ASNElement & root)
{
	//SEQUENCE / length=73
	//  SET / length=11
	//    SEQUENCE / length=9
	//      OBJID / length=3 / value=2.5.4.6      -- key
	//      STRING / length=2 / value=US          -- value
	//  SET / length=19
	//    SEQUENCE / length=17
	//      OBJID / length=3 / value=2.5.4.10
	//      STRING / length=10 / value=Google Inc
	//  SET / length=37
	//    SEQUENCE / length=35
	//      OBJID / length=3 / value=2.5.4.3
	//      STRING / length=28 / value=Google Internet Authority G2

	// DN is equal if each RDN is equal
	// RDN is equal if Attrib set is equal
	//  - sorted by attrib name
	//  - sorted by value
	// Attribute is equal if strings with normalized spaces
	//  {replace inner blocks of spaces with two spaces,
	//   replace outer blocks of spaces with single space}
	// , lower-cased, mapped with simplified character encoding,
	// encoded as utf-8 are equal as well.
	//
	// Usualy only one Attribute present in each RDN

	const unsigned recognizedNum = sizeof(RecognizededFields) / sizeof(RecognizededFields[0]);

	if (root.tag().tag != TAG_SEQUENCE) {
		return 0;
	}

	ASNElement * attrib_list = new ASNElement[recognizedNum];
	memset(attrib_list, 0, sizeof(ASNElement)* recognizedNum);

	ASNElement rdn = root.begin();
	ASNElement rdn_end = root.end();

	for (; rdn != rdn_end; rdn = rdn.next()) {
		if (rdn.tag().tag == TAG_SET) { // SET of attributes inside
			ASNElement attrib = rdn.begin();
			ASNElement attrib_end = rdn.end();
			for (; attrib != attrib_end; attrib = attrib.next()) {
				if (attrib.tag().tag != TAG_SEQUENCE)
					continue;
				ASNElement field = attrib.firstChild();
				ASNElement value = field.next();
				
				for (unsigned i = 0; i < recognizedNum; ++i) {
					
				}
			}
			
		}
	}
}

#endif

static const uint8_t ExtAuthorityKeyIdentifier[] = {OID_FIRST(2, 5), 29, 35};
static const uint8_t ExtSubjectKeyIdentifier[] = {OID_FIRST(2, 5), 29, 14};
static const uint8_t ExtKeyUsage[] = {OID_FIRST(2, 5), 29, 15};
static const uint8_t ExtSubjectAltNames[] = {OID_FIRST(2, 5), 29, 17};
static const uint8_t ExtBasicContraints[] = {OID_FIRST(2, 5), 29, 19};

// ### handle decoding errors
int ExtractCertificateInfo(CertificateInfo * out, int length, const uint8_t * source, const char * hostname)
{
	//SEQUENCE                      :root
	//  SEQUENCE                    :cert
	//    TAG 0
	//      INTEGER -- version == 2
	//    INTEGER
	//    SEQUENCE --signature algorithm
	//    SEQUENCE --issuer         :issuer
	//    SEQUENCE --validity
	//    SEQUENCE --subject        :subject
	//    SEQUENCE                  :pubKey
	//      SEQUENCE  --key type    :pubKeyAlgo
	//      BITSTRING --public key  :pubKeyData
	//    ...
	//    TAG 3      -- extensions
	//      SEQUENCE
	//  SEQUENCE                    :signAlgo
	//  BITSTRING --signature       :signature

	//printASN1(length, source);

	ASNElement root(source, source + length);
	ASNElement cert = root.firstChild();

	ASNElement uniq = cert.firstChild();
	if (uniq.tag().tag == 0 && uniq.tag().scope == 0x5) {
		//parse version
		ASNElement version = uniq.firstChild();
		Tag vertag = version.tag();
		if (vertag.length == 0 || vertag.length > 4 || vertag.tag != TAG_INTEGER || vertag.scope != 0)
			return -1;

		int v = version.getInt();
		if (v < 2) return -1;

		uniq = uniq.next();
	} else {
		return -1;
	}

	ASNElement issuer = uniq.next(2);
	ASNElement subject = uniq.next(4);

	ASNElement pubKey = uniq.next(5);
	ASNElement pubKeyAlgo = pubKey.firstChild();
	ASNElement pubKeyData = pubKeyAlgo.next();

	ASNElement extensions = pubKey.next();

	// check extensions presence
	do {
		if (extensions == cert.end()) {
			break;
		}
		Tag tag = extensions.tag();
		if (tag.scope == 0x5 && tag.tag == 0x03) {
			extensions = extensions.firstChild();
			break;
		}
	} while(true);

	ASNElement signAlgo = cert.next();
	ASNElement signature = signAlgo.next();

	out->keyType = ExtractAlgorithmId(pubKeyAlgo);
	out->signType = ExtractAlgorithmId(signAlgo);

	out->publicKey.data = pubKeyData.access(out->publicKey.length);
	out->signature.data = signature.access(out->signature.length);

	out->payloadOffset = (uint32_t)(cert.ptr - source);
	out->payloadLength = (uint32_t)(signAlgo.ptr - cert.ptr);

	out->restricted = 0;
	out->chainLength = -1;

	if (extensions != cert.end()) {
		ASNElement end = extensions.next();
		ASNElement current = extensions.firstChild();
		for (; current != end; current = current.next()) {
			ASNElement type = current.firstChild();
			if (type.tag().tag != TAG_OBJECT_IDENTIFIER)
				break;

			ASNElement value = type.next();
			if (value.tag().tag == TAG_BOOLEAN) {
				value = value.next();
			}
	
			Tag vtag = value.tag();
			if (vtag.tag != TAG_OCTET_STRING || vtag.length <= 0)
				continue;

			// 2.5.29.19 (CA limits)
			if (type.compare(ExtBasicContraints, sizeof(ExtBasicContraints)) == 0) {
				// SEQUENCE
				//   BOOLEAN isCA DEFAULT false
				//   INTEGER chainLimit (0 .. MAX) OPTIONAL
				ASNElement parent = value.firstChild();
				ASNElement end = value.end();
				ASNElement isca = parent.firstChild();
				if (isca < end) {
					int _isca = isca.getInt();

					if (_isca != 0) {
						int limit = INT32_MAX; // no limit by default
						out->restricted |= CERTUSAGE_CA;

						ASNElement chainlimit = isca.next();
						if (chainlimit < end) {
							limit = chainlimit.getInt();
						}
						out->chainLength = (limit < INT16_MAX) ? limit : INT16_MAX;
					}
				}
			} else if (type.compare(ExtSubjectAltNames, sizeof(ExtSubjectAltNames)) == 0 && !!hostname) {
				// SEQUENCE
				//   [2]
				//     IA5String

				ASNElement list = value.firstChild();
				ASNElement end = list.end();

				ASNElement entry = list.firstChild();

				size_t hnlen = hostname ? strlen(hostname) : 0;
				
				for (; entry != end; entry = entry.next()) {
					Tag t = entry.tag();
					// EXPLICIT [2] - DnsName
					if (t.scope != 0x4 || t.tag != 2)
						continue;
					 
					size_t vlen = 0;

					const uint8_t * val = entry.access(vlen);
					if (val[0] == '*' && val[1] == '.') {
						// DNS wildcard
						if ((vlen - 2) == hnlen) {
							vlen -= 1;
							val += 1;
						}
						if (memcmp(val + 1, hostname + (hnlen - vlen + 1), vlen - 1) == 0) {
							out->restricted |= CERT_DOMAIN_MATCH;
							break;
						}
					} else {
						if (vlen == hnlen && memcmp(val, hostname, vlen) == 0) {
							out->restricted |= CERT_DOMAIN_MATCH;
							break;
						}
					}
				}
			} else if (type.compare(ExtAuthorityKeyIdentifier, sizeof(ExtAuthorityKeyIdentifier)) == 0) {
				// SEQUENCE
				//   [0]
				//     OCTET STRING keyIdentifier
				ASNElement list = value.firstChild();
				ASNElement end = list.end();

				ASNElement entry = list.firstChild();
				for (; entry != end; entry = entry.next()) {
					Tag t = entry.tag();

					// EXPLICIT [0] -- keyIdentifier
					if (t.scope != 0x4 || t.tag != 0)
						continue;
					
					issuer = entry;
				}
			} else if (type.compare(ExtSubjectKeyIdentifier, sizeof(ExtSubjectKeyIdentifier)) == 0) {
				// OCTET STRING keyIdentifier
				ASNElement entry = value.firstChild();
				subject = entry;
			}
		}
	}

	out->issuer.data = issuer.access(out->issuer.length);
	out->subject.data = subject.access(out->subject.length);

	return 1;
}


int Extract_PKCS1_RSA_PublicKeyComponents(PKCS1_RSA_PublicKey * out, int length, const uint8_t * source)
{
//  RSAPublicKey ::= SEQUENCE {
//     modulus INTEGER, -- n
//     publicExponent INTEGER -- e }

	ASNElement root(source, source + length);
	ASNElement modulus = root.firstChild();
	ASNElement exponent = modulus.next();

	modulus.accessSlice(out->modulus);
	exponent.accessSlice(out->exponent);

	return 1;
}

#if 0
int Extract_PKCS1_RSA_PrivateKeyComponents(PKCS1_RSA_PrivateKey * out, int length, const uint8_t * source)
{
//  RSAPrivateKey ::= SEQUENCE {
//     version Version,
//     modulus INTEGER, -- n
//     publicExponent INTEGER, -- e
//     privateExponent INTEGER, -- d
//     prime1 INTEGER, -- p
//     prime2 INTEGER, -- q
//     exponent1 INTEGER, -- d mod (p-1)
//     exponent2 INTEGER, -- d mod (q-1)
//     coefficient INTEGER -- (inverse of q) mod p }

	ASNElement root(source, source + length);
	ASNElement version = root.firstChild();
	ASNElement modulus = version.next();
	ASNElement pub_exponent = modulus.next();
	ASNElement priv_exponent = pub_exponent.next();

	if (version.getInt() != 0) return 0;

	out->modulus.alloc(modulus.length());
	modulus.extract(out->modulus.data);

	out->pub_exp.alloc(pub_exponent.length());
	pub_exponent.extract(out->pub_exp.data);

	out->priv_exp.alloc(priv_exponent.length());
	priv_exponent.extract(out->priv_exp.data);

	return 1;
}

//### verify issuer certificate has valid date
int VerifyCertificateChain(TinyTLSContext * ctx, const BinarySlice * certs, CertificateInfo * cert_storage, size_t count)
{
	uint32_t current = 0;
	int32_t chain_len = -1;
	uint32_t next;

	for (size_t i = 0; i < count; ++i) {
		if (ExtractCertificateInfo(&cert_storage[i], certs[i].length, certs[i].data, ctx->HostName) < 0)
			return -1;

		//cert_storage[i].subject
	}

	// first certificate MUST belong to this domain
	if (!(cert_storage[0].restricted & CERT_DOMAIN_MATCH)) {
		return 0;
	}

	// trust anything if we don't have certificate storage
	// used for debugging
	//### this is probably a bad idea
	if (!ctx->certificate_strogate)
		return 1;

	int trusted = 0;
	BinarySlice * issuer = 0;

	CertificateInfo * issuer_cert;
	CertificateInfo trusted_cert;

	for (;;) {
		// limit chain length to stop loop
		if (chain_len > TINYTLS_MAX_CERT_CHAIN_LENGTH) return 0;

		// if selected certificate is not allowed to sign as long certificate chain as it 
		// did - the whole chain is declared invalid
		if (cert_storage[current].chainLength < chain_len) return 0;

		issuer = &cert_storage[current].issuer;

		issuer_cert = NULL;
		next = ~0;

		// ask for trusted certificate form pkix library
		{
			const uint8_t * externCertData;
			uint32_t externCertLen;

			if (ctx->certificate_strogate)
				trusted = ctx->certificate_strogate->AskCertificate(issuer->data, issuer->length, &externCertData, &externCertLen);

			if (trusted < 0)
				return 0; //presented issuer is untrusted
			if (trusted > 0) {
				if (ExtractCertificateInfo(&trusted_cert, externCertLen, externCertData) < 0)
					return -1;
				issuer_cert = &trusted_cert;
			}
		}

		if (!issuer_cert) {
			for (uint32_t i = 0; i < count; ++i) {
				if (current == i)
					continue;

				if (issuer->length != cert_storage[i].subject.length)
					continue;

				//### implement normalization 
				if (memcmp(issuer->data, cert_storage[i].subject.data, issuer->length) != 0)
					continue;

				issuer_cert = &cert_storage[i];
				next = i;
				break;
			}
		}

		// no certificate given - connection is untrusted!
		if (!issuer_cert)
			return 0;

		// non-CA certifiact in cahin
		if ((issuer_cert->restricted & CERTUSAGE_CA) == 0)
			return 0;

		// check validity
		// make sure we don't have unknown or weak signature algorithms
		if (cert_storage[current].signType < PKCS1_SSA_TRUSTED) {
			//fprintf("Unable to verify signature! - UNKNOWN ALGORITHM\n");
			return -1;
		} else {
			PKCS1_RSA_PublicKey pubkey;
			if (!Extract_PKCS1_RSA_PublicKeyComponents(&pubkey, issuer_cert->publicKey.length, issuer_cert->publicKey.data))
				return -1;

			uint32_t PayloadLen = cert_storage[current].payloadLength;
			const uint8_t * PayloadData = certs[current].data + cert_storage[current].payloadOffset;

			// Needs context now!
			int result = VerifyRSASignature(&ctx->mr_ctx,
				cert_storage[current].signature,
				cert_storage[current].signature.length & (~3U),
				pubkey,
				cert_storage[current].signType,
				PayloadData,
				PayloadLen);

			// signature does not match - fail certificate check
			if (result != 1)
				return 0;
		}

		// if we used builtin certificate - return as trusted
		if (trusted > 0) {
			return 1;
		}

		// overflow condition
		if (next > count)
			return 0;

		++chain_len;
		current = next;
	}
	// UNREACHABLE
}
#endif

#ifdef TINYTLS_DEBUG
extern void PrintHex(const unsigned char *buf, unsigned int size, int shift);
extern void PrintOct(const unsigned char *buf, unsigned int size, int shift);

static void printIndent(int n)
{
	for(int i = n; i > 0; --i)
		putc(' ', stdout);
}

static void printBlock(int length, const uint8_t * & stream, int indent)
{
	const uint8_t * end = stream + length;
	const uint8_t * next;

	while(stream < end) {
		Tag tag = parseTag(stream, end);

		printIndent(indent);

		next = stream + tag.length;

		if (tag.scope & 1) { //bit 6: contents could be parsed as ASN.1
			if (tag.tag == 16)
				printf("SEQUENCE / length=%d\n", tag.length);
			else if (tag.tag == 17)
				printf("SET / length=%d\n", tag.length);
			else
				printf("TAG %d / length=%d\n", tag.tag, tag.length);

			printBlock(tag.length, stream, indent + 2);
		} else if (tag.tag == 1) {
			int value = parseInteger(tag.length, stream);
			printf("BOOLEAN / length=%d / value=%d\n", tag.length, value);
		} else if (tag.tag == 2) {
			int value = parseInteger(tag.length, stream);
			printf("INTEGER / length=%d / value=%d\n", tag.length, value);
		} else if (tag.tag == 3) {
			uint8_t v = *stream++;
			printf("BIT STRING / length=%d / bits=%d\n", tag.length, (tag.length << 3) + ((8 - v) & 7));
		} else if (tag.tag == 4) {
			printf("OCTET STRING / length=%d /\n", tag.length);
			PrintHex(stream, tag.length, 0);
/*			const uint8_t * ve = stream + tag.length;
			while (stream < ve) {
				uint8_t v = *stream++;
				if (v > 0x20 && v < 0x7f)
					putc((char)v, stdout);
				else
					putc('.', stdout);
			}*/
			printf("\n");
		} else if (tag.tag == 5) {
			int value = parseInteger(tag.length, stream);
			printf("NULL / length=%d\n", tag.length);
		} else if (tag.tag == 6) {
			printf("OBJID / length=%d", tag.length);

			const uint8_t * ve = stream + tag.length;
			const uint8_t v = *stream++;

			printf(" / value=%d.%d", v / 40, v % 40);
			while (stream < ve) {
				short v = 0;
				if (parseObjId(v, stream, ve))
					printf(".%d", v);
				else
					printf(".?");
			}
			printf("\n");
		} else if (tag.tag == 12) {
			printf("UTF8-STRING / length=%d / value=", tag.length);

			const uint8_t * ve = stream + tag.length;
			while (stream < ve) {
				uint8_t v = *stream++;
				putc((char)v, stdout);
			}
			printf("\n");
		} else if (tag.tag == 19) {
			printf("STRING / length=%d / value=", tag.length);

			const uint8_t * ve = stream + tag.length;
			while (stream < ve) {
				uint8_t v = *stream++;
				putc((char)v, stdout);
			}
			printf("\n");
		} else if (tag.tag == 20) {
			printf("T.61-STRING / length=%d / value=", tag.length);

			const uint8_t * ve = stream + tag.length;
			while (stream < ve) {
				uint8_t v = *stream++;
				putc((char)v, stdout);
			}
			printf("\n");
		} else {
			printf("TAG %d / length=%d\n", tag.tag, tag.length);
		}


		stream = next;
	}
}

void printASN1(const ASNElement & el)
{
	ASNElement n = el.next();
	printASN1(n.ptr - el.ptr, el.ptr);
}

void printASN1(int length, const uint8_t * source)
{
	const uint8_t * stream = source;

	printBlock(length, stream, 2);

	printf("Data left in stream: %d\n", length - (stream - source));
}
#endif

#if 0

void LoadCert(Binary & b, const char * filename)
{
	FILE * fs = fopen(filename, "rb");
	
	if (!fs) return;

	fseek(fs, 0, SEEK_END);
	int filelen = ftell(fs);
	fseek(fs, 0, SEEK_SET);

	b.alloc(filelen);
	b.length = filelen;

	fread(b.data, 1, filelen, fs);

	fclose(fs);
}

const uint8_t testIssuer[] = 
"\060\141\061\013\060\011\006\003\125\004\006\023\002\125\123\061"
"\025\060\023\006\003\125\004\012\023\014\104\151\147\151\103\145"
"\162\164\040\111\156\143\061\031\060\027\006\003\125\004\013\023"
"\020\167\167\167\056\144\151\147\151\143\145\162\164\056\143\157"
"\155\061\040\060\036\006\003\125\004\003\023\027\104\151\147\151"
"\103\145\162\164\040\107\154\157\142\141\154\040\122\157\157\164"
"\040\103\101";

const uint8_t testCertificate[] =
"\060\202\003\257\060\202\002\227\240\003\002\001\002\002\020\010"
"\073\340\126\220\102\106\261\241\165\152\311\131\221\307\112\060"
"\015\006\011\052\206\110\206\367\015\001\001\005\005\000\060\141"
"\061\013\060\011\006\003\125\004\006\023\002\125\123\061\025\060"
"\023\006\003\125\004\012\023\014\104\151\147\151\103\145\162\164"
"\040\111\156\143\061\031\060\027\006\003\125\004\013\023\020\167"
"\167\167\056\144\151\147\151\143\145\162\164\056\143\157\155\061"
"\040\060\036\006\003\125\004\003\023\027\104\151\147\151\103\145"
"\162\164\040\107\154\157\142\141\154\040\122\157\157\164\040\103"
"\101\060\036\027\015\060\066\061\061\061\060\060\060\060\060\060"
"\060\132\027\015\063\061\061\061\061\060\060\060\060\060\060\060"
"\132\060\141\061\013\060\011\006\003\125\004\006\023\002\125\123"
"\061\025\060\023\006\003\125\004\012\023\014\104\151\147\151\103"
"\145\162\164\040\111\156\143\061\031\060\027\006\003\125\004\013"
"\023\020\167\167\167\056\144\151\147\151\143\145\162\164\056\143"
"\157\155\061\040\060\036\006\003\125\004\003\023\027\104\151\147"
"\151\103\145\162\164\040\107\154\157\142\141\154\040\122\157\157"
"\164\040\103\101\060\202\001\042\060\015\006\011\052\206\110\206"
"\367\015\001\001\001\005\000\003\202\001\017\000\060\202\001\012"
"\002\202\001\001\000\342\073\341\021\162\336\250\244\323\243\127"
"\252\120\242\217\013\167\220\311\242\245\356\022\316\226\133\001"
"\011\040\314\001\223\247\116\060\267\123\367\103\304\151\000\127"
"\235\342\215\042\335\207\006\100\000\201\011\316\316\033\203\277"
"\337\315\073\161\106\342\326\146\307\005\263\166\047\026\217\173"
"\236\036\225\175\356\267\110\243\010\332\326\257\172\014\071\006"
"\145\177\112\135\037\274\027\370\253\276\356\050\327\164\177\172"
"\170\231\131\205\150\156\134\043\062\113\277\116\300\350\132\155"
"\343\160\277\167\020\277\374\001\366\205\331\250\104\020\130\062"
"\251\165\030\325\321\242\276\107\342\047\152\364\232\063\370\111"
"\010\140\213\324\137\264\072\204\277\241\252\112\114\175\076\317"
"\117\137\154\166\136\240\113\067\221\236\334\042\346\155\316\024"
"\032\216\152\313\376\315\263\024\144\027\307\133\051\236\062\277"
"\362\356\372\323\013\102\324\253\267\101\062\332\014\324\357\370"
"\201\325\273\215\130\077\265\033\350\111\050\242\160\332\061\004"
"\335\367\262\026\362\114\012\116\007\250\355\112\075\136\265\177"
"\243\220\303\257\047\002\003\001\000\001\243\143\060\141\060\016"
"\006\003\125\035\017\001\001\377\004\004\003\002\001\206\060\017"
"\006\003\125\035\023\001\001\377\004\005\060\003\001\001\377\060"
"\035\006\003\125\035\016\004\026\004\024\003\336\120\065\126\321"
"\114\273\146\360\243\342\033\033\303\227\262\075\321\125\060\037"
"\006\003\125\035\043\004\030\060\026\200\024\003\336\120\065\126"
"\321\114\273\146\360\243\342\033\033\303\227\262\075\321\125\060"
"\015\006\011\052\206\110\206\367\015\001\001\005\005\000\003\202"
"\001\001\000\313\234\067\252\110\023\022\012\372\335\104\234\117"
"\122\260\364\337\256\004\365\171\171\010\243\044\030\374\113\053"
"\204\300\055\271\325\307\376\364\301\037\130\313\270\155\234\172"
"\164\347\230\051\253\021\265\343\160\240\241\315\114\210\231\223"
"\214\221\160\342\253\017\034\276\223\251\377\143\325\344\007\140"
"\323\243\277\235\133\011\361\325\216\343\123\364\216\143\372\077"
"\247\333\264\146\337\142\146\326\321\156\101\215\362\055\265\352"
"\167\112\237\235\130\342\053\131\300\100\043\355\055\050\202\105"
"\076\171\124\222\046\230\340\200\110\250\067\357\360\326\171\140"
"\026\336\254\350\016\315\156\254\104\027\070\057\111\332\341\105"
"\076\052\271\066\123\317\072\120\006\367\056\350\304\127\111\154"
"\141\041\030\325\004\255\170\074\054\072\200\153\247\353\257\025"
"\024\351\330\211\301\271\070\154\342\221\154\212\377\144\271\167"
"\045\127\060\300\033\044\243\341\334\351\337\107\174\265\264\044"
"\010\005\060\354\055\275\013\277\105\277\120\271\251\363\353\230"
"\001\022\255\310\210\306\230\064\137\215\012\074\306\351\325\225"
"\225\155\336";

class TestCertificateStorage : public TinyTLSCertificateStorage
{
public:
	void Destroy() { }

	int AskCertificate(const uint8_t * issuer, uint32_t issuerLen, const uint8_t ** certificate, uint32_t * certificateLen)
	{
		if (issuerLen == sizeof(testIssuer) - 1 && memcmp(issuer, testIssuer, issuerLen) == 0) {
			*certificate = testCertificate;
			*certificateLen = sizeof(testCertificate);
			// Trusted certificate
			return 1;
		}
		return 0; // Unknown certificate
	}
};

// This test is broken by changed context structure
void main()
{
	TestCertificateStorage * storage = new TestCertificateStorage;

	Binary certs[3];
	LoadCert(certs[0], "certs/reddit.com.der");
	LoadCert(certs[1], "certs/DigiCertSHA2SecureServerCA.der");
	LoadCert(certs[2], "certs/DigiCertGlobalRootCA.der");

	CertificateInfo * parsedCerts = new CertificateInfo[3];

	int ret = 0;

	ret = VerifyCertificateChain(NULL, certs, parsedCerts, 2);

	delete [] parsedCerts;

	if(ret > 0) {
		printf("Certificate chain verified\n");
	} else {
		printf("Certificate chain is NOT VERIFIED\n");
	}
}

#endif
