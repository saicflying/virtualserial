#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <termios.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "logger.h"
#include "license.h"

#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

extern char* StrSHA256(const char* str, long long length, char* sha256){
	char *pp, *ppend;
	uint32_t l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
	H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
	H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
	uint32_t K[64] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	};
	l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));
	if (!(pp = (char*)malloc((unsigned long)l))) return 0;
	for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
	for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
	*((uint32_t*)(pp + l - 4)) = length << 3;
	*((uint32_t*)(pp + l - 8)) = length >> 29;
	for (ppend = pp + l; pp < ppend; pp += 64){
		for (i = 0; i < 16; W[i] = ((uint32_t*)pp)[i], i++);
		for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
		A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
		for (i = 0; i < 64; i++){
			T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
			T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
			H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
		}
		H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
	}
	free(pp - l);
	sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
	return sha256;
}

typedef struct sha1context
{
	uint32_t message_digest[5]; /* message digest (output)          */

	uint32_t length_low;        /* message length in bits           */
	uint32_t length_high;       /* message length in bits           */

	unsigned char message_block[64]; /* 512-bit message blocks      */
	int message_block_index;    /* index into message block array   */

	int computed;               /* is the digest computed?          */
	int corrupted;              /* is the message digest corruped?  */
} sha1context;

#define sha1circularshift(bits,word) \
	((((word) << (bits)) & 0xffffffff) | \
	 ((word) >> (32-(bits))))

/* Function prototypes */
void sha1processmessageblock(sha1context *);
void sha1padmessage(sha1context *);

void sha1reset(sha1context *context)
{
	context->length_low             = 0;
	context->length_high            = 0;
	context->message_block_index    = 0;

	context->message_digest[0]      = 0x67452301;
	context->message_digest[1]      = 0xefcdab89;
	context->message_digest[2]      = 0x98badcfe;
	context->message_digest[3]      = 0x10325476;
	context->message_digest[4]      = 0xc3d2e1f0;

	context->computed   = 0;
	context->corrupted  = 0;
}

int sha1result(sha1context *context)
{

	if (context->corrupted)
	{
		return 0;
	}

	if (!context->computed)
	{
		sha1padmessage(context);
		context->computed = 1;
	}

	return 1;
}

void sha1input(     sha1context         *context,
		const unsigned char *message_array,
		unsigned            length)
{
	if (!length)
	{
		return;
	}

	if (context->computed || context->corrupted)
	{
		context->corrupted = 1;
		return;
	}

	while(length-- && !context->corrupted)
	{
		context->message_block[context->message_block_index++] =
			(*message_array & 0xff);

		context->length_low += 8;
		/* force it to 32 bits */
		context->length_low &= 0xffffffff;
		if (context->length_low == 0)
		{
			context->length_high++;
			/* force it to 32 bits */
			context->length_high &= 0xffffffff;
			if (context->length_high == 0)
			{
				/* message is too long */
				context->corrupted = 1;
			}
		}

		if (context->message_block_index == 64)
		{
			sha1processmessageblock(context);
		}

		message_array++;
	}
}

void sha1processmessageblock(sha1context *context)
{
	const unsigned k[] =            /* constants defined in sha-1   */      
	{
		0x5a827999,
		0x6ed9eba1,
		0x8f1bbcdc,
		0xca62c1d6
	};
	int         t;                  /* loop counter                 */
	unsigned    temp;               /* temporary word value         */
	unsigned    w[80];              /* word sequence                */
	unsigned    a, b, c, d, e;      /* word buffers                 */

	/*
	 *      *  initialize the first 16 words in the array w
	 *           */
	for(t = 0; t < 16; t++)
	{
		w[t] = ((unsigned) context->message_block[t * 4]) << 24;
		w[t] |= ((unsigned) context->message_block[t * 4 + 1]) << 16;
		w[t] |= ((unsigned) context->message_block[t * 4 + 2]) << 8;
		w[t] |= ((unsigned) context->message_block[t * 4 + 3]);
	}

	for(t = 16; t < 80; t++)
	{
		w[t] = sha1circularshift(1,w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]);
	}

	a = context->message_digest[0];
	b = context->message_digest[1];
	c = context->message_digest[2];
	d = context->message_digest[3];
	e = context->message_digest[4];

	for(t = 0; t < 20; t++)
	{
		temp =  sha1circularshift(5,a) +
			((b & c) | ((~b) & d)) + e + w[t] + k[0];
		temp &= 0xffffffff;
		e = d;
		d = c;
		c = sha1circularshift(30,b);
		b = a;
		a = temp;
	}

	for(t = 20; t < 40; t++)
	{
		temp = sha1circularshift(5,a) + (b ^ c ^ d) + e + w[t] + k[1];
		temp &= 0xffffffff;
		e = d;
		d = c;
		c = sha1circularshift(30,b);
		b = a;
		a = temp;
	}

	for(t = 40; t < 60; t++)
	{
		temp = sha1circularshift(5,a) +
			((b & c) | (b & d) | (c & d)) + e + w[t] + k[2];
		temp &= 0xffffffff;
		e = d;
		d = c;
		c = sha1circularshift(30,b);
		b = a;
		a = temp;
	}

	for(t = 60; t < 80; t++)
	{
		temp = sha1circularshift(5,a) + (b ^ c ^ d) + e + w[t] + k[3];
		temp &= 0xffffffff;
		e = d;
		d = c;
		c = sha1circularshift(30,b);
		b = a;
		a = temp;
	}

	context->message_digest[0] =
		(context->message_digest[0] + a) & 0xffffffff;
	context->message_digest[1] =
		(context->message_digest[1] + b) & 0xffffffff;
	context->message_digest[2] =
		(context->message_digest[2] + c) & 0xffffffff;
	context->message_digest[3] =
		(context->message_digest[3] + d) & 0xffffffff;
	context->message_digest[4] =
		(context->message_digest[4] + e) & 0xffffffff;

	context->message_block_index = 0;
}

void sha1padmessage(sha1context *context)
{
	/*
	 *      *  check to see if the current message block is too small to hold
	 *           *  the initial padding bits and length.  if so, we will pad the
	 *                *  block, process it, and then continue padding into a second
	 *                     *  block.
	 *                          */
	if (context->message_block_index > 55)
	{
		context->message_block[context->message_block_index++] = 0x80;
		while(context->message_block_index < 64)
		{
			context->message_block[context->message_block_index++] = 0;
		}

		sha1processmessageblock(context);

		while(context->message_block_index < 56)
		{
			context->message_block[context->message_block_index++] = 0;
		}
	}
	else
	{
		context->message_block[context->message_block_index++] = 0x80;
		while(context->message_block_index < 56)
		{
			context->message_block[context->message_block_index++] = 0;
		}
	}

	/*
	 *      *  store the message length as the last 8 octets
	 *           */
	context->message_block[56] = (context->length_high >> 24) & 0xff;
	context->message_block[57] = (context->length_high >> 16) & 0xff;
	context->message_block[58] = (context->length_high >> 8) & 0xff;
	context->message_block[59] = (context->length_high) & 0xff;
	context->message_block[60] = (context->length_low >> 24) & 0xff;
	context->message_block[61] = (context->length_low >> 16) & 0xff;
	context->message_block[62] = (context->length_low >> 8) & 0xff;
	context->message_block[63] = (context->length_low) & 0xff;

	sha1processmessageblock(context);
}

int strsha1(char * buf, int len, char * obuf)
{
	struct sha1context sha;
	sha1reset(&sha);
	sha1input(&sha, (const unsigned char *) buf, len);

	if (!sha1result(&sha))
		return -1;
	else
	{
		snprintf(obuf, 41, "%08X%08X%08X%08X%08X", sha.message_digest[0],
				sha.message_digest[1],sha.message_digest[2],sha.message_digest[3],sha.message_digest[4]);
		/* it's a bug, but don't fix to make compatible */
		obuf[39] = '\0';
	}
	return 0;
}

void print_identity(identity_t * id)
{
	int i;
	printf("cpu: %s:%s\n", id->cpu_vendorid, id->cpu_deviceid);
	printf("serialnumber:%d\n", id->serialnumber);
	printf("netnumber:%d\n", id->netnumber);
	for(i = 0; i < id->netnumber; i++) {
		printf("mac%d:%s\n", i, id->macaddr[i]);
	}
}

int maccmp(const void *mac1, const void *mac2) {
	return memcmp(mac1, mac2, 18);
}

int find_identity(identity_t * id, char *sha256)
{
	FILE *fp;
	DIR * dir;
	struct dirent *ent;
	char buf[512], *ptmp;
	int i;
#ifdef __ARM_ARCH
	int len, off;
	char *pcur;
#endif
	memset(id, 0, sizeof(identity_t));
	/* get identity */		
	snprintf(id->mysignature, sizeof(id->mysignature), "wang long's software with copyright");
#ifndef __ARM_ARCH
	fp = fopen("/sys/bus/pci/devices/0000:00:00.0/vendor", "r");
	if (fp == NULL) {
		return -1;
	}
	fgets(id->cpu_vendorid, 7, fp);
	fclose(fp);
	id->cpu_vendorid[6] = '\0';
	fp = fopen("/sys/bus/pci/devices/0000:00:00.0/device", "r");
	if (fp == NULL) {
		return -1;
	}
	fgets(id->cpu_deviceid, 7, fp);
	fclose(fp);

	id->cpu_deviceid[6] = '\0';
#else
	pcur = id->cpu_vendorid;
	off = 0;
	fp = fopen("/proc/cpuinfo", "r");	
	if (fp == NULL) {
		return -1;
	}
	while (fgets(buf, sizeof(buf), fp)) {
		if (strstr(buf, "CPU implementer") ||
		strstr(buf, "CPU architecture") ||
		strstr(buf, "CPU variant") ||
		strstr(buf, "CPU part") ||
		strstr(buf, "CPU revision")) {
			ptmp = strchr(buf, ':');	
		} else {
			continue;
		}
		
		if (strstr(buf, "CPU part")) {
			if (off < 7) {
				pcur[off] = '\0';	
			}
			pcur = id->cpu_deviceid;
			off = 0;
		}

		if (ptmp) {
			ptmp++;		
			while (*ptmp == ' ' || *ptmp == '\t') 
				ptmp++;
			if (*ptmp == '0' && *(ptmp+1) == 'x') {
				ptmp+=2;
			}
			len = strlen(ptmp);
			if (len < 6 - off) {
				memcpy(pcur + off, ptmp, len);	
				off += len;
			}
		}
	}
	if (off < 7) {
		pcur[off] = '\0';	
	}
	fclose(fp);
#endif
	dir = opendir("/sys/class/net/");
	if (NULL == dir) {
		return -1;
	}
	id->netnumber = 0;
	while (ent = readdir(dir)) {
		if (ent->d_name[0] != '.') {
			if (memcmp(ent->d_name, "eth", 3)) {
				continue;
			}
			snprintf(buf, sizeof(buf), "/sys/class/net/%s/address", ent->d_name);
			fp = fopen(buf, "r");
			if (fp == NULL) {
				closedir(dir);
				return -1;
			}
			fgets(id->macaddr[id->netnumber], 18, fp);
			if (memcmp(id->macaddr[id->netnumber], "00:00:00:00:00:00", 17)) {
				id->netnumber++;
			}
			fclose(fp);
		}
	}
	closedir(dir);
	qsort(id->macaddr, id->netnumber, 18, maccmp);

	memset(sha256, 0, 64);
	ptmp = StrSHA256((char *)id, sizeof(identity_t), sha256);
	if (ptmp == NULL) {
		return -2;
	}
	return 0;
}

void rsa_decrypt(uint16_t *cw, int clength, char *mw)
{ 
	int n;
	int d;
	int i=0, j=-1;
	int64_t temint = 0;
	d = 19097;
	n = 46031;
	for ( i=0; i< clength / 4; ++i )
	{
		mw[i] = 0;
		temint = cw[i];

		if( d != 0 )
		{
			for( j=1; j<d; j++ )
			{
				temint = (int64_t)( temint * cw[i] ) % n;
			}
		}
		else
		{
			temint = 1;
		}

		mw[i] = (char)temint;
	}
}

#ifdef TEST
int main(int argc, char * argv[])
{
	identity_t id;
	char sha256[64];
	find_identity(&id, sha256);
	print_identity(&id);
	return 0;
}
#endif
