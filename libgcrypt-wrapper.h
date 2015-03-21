

// AES crypt the size of outData should equal to inData's size
#define THROWFAIL(x) goto x

// flags
#define eAD_INSECUREMEMORY (1 << 0)
#define eAD_ENCRYPT (1 << 1)
#define eAD_DECRYPT (1 << 2)

struct RSA_key_t;

int easyAESData(void *inData, size_t inDataSize, void *outData, void *key, size_t keySize, void *iv, size_t ivSize, int flags);
int easyPrtSexp(gcry_sexp_t gs);
int easyRSAGenkey(RSA_key_t *key,int nbits);
gcry_sexp_t easyRSAGetKeySexp(RSA_key_t *sec,RSA_key_t *pub);
xmlNodePtr easyXMLSearchChild(xmlNodePtr parent,xmlChar *name);
xmlNodePtr easyXMLSearchSibling(xmlNodePtr node,xmlChar *name);

#define eRSKTF_SEC 0
#define eRSKTF_PUB 1
int easyRSASaveKeyToFile(RSA_key_t *key,const char *fn,int which);
int easyRSAReadKeyFromFile(RSA_key_t *key,const char *fn);

#define eRC_ENCRYPT 1 << 0
#define eRC_DECRYPT 1 << 1
int easyRSACrypt(void *in,size_t inSize,void **out,size_t *outSize,RSA_key_t *key,int flags);
int easyRSASign();
int easyRSAVerify();