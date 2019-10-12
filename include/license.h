#ifndef SOE_LIC_HEADER
#define SOE_LIC_HEADER

typedef union _identity_s {
	struct {
		char mysignature[64];
		char cpu_vendorid[7]; 
		char cpu_deviceid[7]; 
		
		int serialnumber; 	
		int netnumber;
		char macaddr[16][18];
	};
	char pad[512];
}identity_t;

int find_identity(identity_t * id, char *sha256);
int strsha1(char * buf, int len, char * obuf);
void rsa_decrypt(uint16_t *cw, int clength, char *mw);
#endif

