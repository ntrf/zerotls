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

#include <stdint.h>
#include <stdlib.h>

#include <stdio.h>

const char * hexBlock(const uint8_t * value, size_t len)
{
	char * x = new char[len * 2 + 1];

	x[len * 2] = 0;

	for (size_t i = 0; i < len; ++i) {
		size_t l = i * 2;

		uint8_t a = (value[i] >> 4) & 0xf;
		uint8_t b = (value[i] & 0xf);

		x[l] = (a >= 10) ? ('a' + (a - 10)) : ('0' + a);
		x[l + 1] = (b >= 10) ? ('a' + (b - 10)) : ('0' + b);
	}
	return x;
}

void writeKeyLogClientRandom(const uint8_t * random, const uint8_t * master)
{
#if defined(_CRT_INSECURE_DEPRECATE) && defined(_MSC_VER)
	FILE * sslKeyLog = NULL;
	if (fopen_s(&sslKeyLog, "sslKeyLog.txt", "at") != 0)
		return;
#else
	FILE * sslKeyLog = fopen("sslKeyLog.txt", "at");
#endif

	if (!sslKeyLog) return;

	//fprintf(sslKeyLog, "RSA %s %s\n", hexBlock(),

	auto p1 = hexBlock(random, 32);
	auto p2 = hexBlock(master, 48);

	fprintf(sslKeyLog, "CLIENT_RANDOM %s %s\n", p1, p2);
	fflush(sslKeyLog);
	
	fclose(sslKeyLog);

	delete [] p1;
	delete [] p2;
}

void PrintHex(const uint8_t *buf, size_t size, int shift)
{
	int addr = 0;

	while (size > 0) {
		printf("\t%08X  ", addr + shift);

		for (int i = 0; (i < 16) && (size > 0); ++i, ++addr, --size) printf("%02X ", buf[addr]);
		printf("\n");
	}
}

void PrintOct(const uint8_t *buf, size_t size, int shift)
{
	int addr = 0;

	while (size > 0) {
		printf("\t%08X  ", addr + shift);

		for (int i = 0; (i < 16) && (size > 0); ++i, ++addr, --size) printf("%03o ", buf[addr]);
		printf("\n");
	}
}
