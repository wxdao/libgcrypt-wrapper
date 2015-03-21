#include "libgcrypt-wrapper.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <cstdlib>
#include <vector>
#include <gcrypt.h>
#include <libxml/tree.h>
#include <libxml/parser.h>

using namespace std;
#define prt(x) cout<<x<<endl;
#ifdef DEBUG
void prthex(void *b,size_t sz)
{
  for(int i = 0;i <sz;++i)
    {
      printf("%02X",*(unsigned char*)(b + i));
    }
  printf("\n");
}

char *prthexbuf(void *b,size_t sz)
{
  char *buf = (char*)malloc(sz*2 + 1);
  memset(buf,0,sz*2+1);
  for(int i = 0;i < sz;++i)
    {
      sprintf(buf + i*2,"%02X",*(unsigned char*)(b + i));
    }
  //sprintf(buf + sz*2 +1,"\n");
  return buf;
}

void *hextobyte(const char *hexstr)
{
  void *data = malloc(strlen(hexstr)/2);
  memset(data,0,strlen(hexstr)/2);
  const char *pos = hexstr;
  for(int i = 0;i < strlen(hexstr)/2;++i)
    {
      sscanf(pos + i*2,"%2hhx",data + i);
    }
  return data;
}
#endif

// ----------functions


int easyAESData(void *inData, size_t inDataSize, void *outData, void *key, size_t keySize, void *iv, size_t ivSize, int flags)
{
  // set up
  gcry_cipher_hd_t h;
  int err;
  if(flags & eAD_INSECUREMEMORY)
    {
      err = gcry_cipher_open(&h,GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
    }
  else
    {
      err=gcry_cipher_open(&h,GCRY_CIPHER_AES256,GCRY_CIPHER_MODE_CFB, 0);
    }
  if (err)
    THROWFAIL(open_fail);
  // set iv
  void *IV;
  IV = malloc(16);
  memset(IV, 8, 16);
  if (iv)
    {
      memmove(IV, iv, ivSize > 16 ? 16 : ivSize);
    }
  else
    {
      memmove(IV, "5sjrcifls4lsiden", 16);
    }
  err = gcry_cipher_setiv(h, IV, 16);
  if (err)
    THROWFAIL(setiv_fail);
  free(IV);
  // set key
  void *KEY;
  if (flags & eAD_INSECUREMEMORY)
    {
      KEY = gcry_malloc_secure(32);
    }
  else
    {
      KEY = gcry_malloc(32);
    }
  memset(KEY, 8, 32);
  memmove(KEY, key, keySize > 32 ? 32 : keySize);
  err = gcry_cipher_setkey(h, KEY, 32);
  gcry_free(KEY);
  // crypt
  memset(outData, 0, inDataSize);
  if (flags & eAD_ENCRYPT)	// encrypt
    {
      err = gcry_cipher_encrypt(h, outData, inDataSize, inData, inDataSize);
    }
  else if (flags & eAD_DECRYPT)	// decrypt
    {
      err = gcry_cipher_decrypt(h, outData, inDataSize, inData, inDataSize);
    }
  else						// wtf
    {
      gcry_cipher_close(h);
      return 10;
    }
  if(err)
    THROWFAIL(crypt_fail);

  gcry_cipher_close(h);
  return 0;

open_fail:
  return 1;

setiv_fail:
  free(IV);
  gcry_cipher_close(h);
  return 3;

crypt_fail:
  gcry_cipher_close(h);
  return 5;
}
//---
//public key crypto
struct RSA_key_t
{
  long nbits;
  void *n;
  size_t n_size;
  void *e;
  size_t e_size;
  void *d;
  size_t d_size;
  void *p;
  size_t p_size;
  void *q;
  size_t q_size;
  void *u;
  size_t u_size;
  void free_pub()
  {
    gcry_free(n);
    gcry_free(e);
  }
  void free_sec()
  {
    gcry_free(n);
    gcry_free(e);
    gcry_free(d);
    gcry_free(p);
    gcry_free(q);
    gcry_free(u);
  }

};

int easyPrtSexp(gcry_sexp_t gs)
{
  size_t sz = gcry_sexp_sprint(gs,GCRYSEXP_FMT_ADVANCED,0,0);
  char cc[sz];
  gcry_sexp_sprint(gs,GCRYSEXP_FMT_ADVANCED,cc,sz);
  prt(cc);
}

int easyRSAGenkey(RSA_key_t *key,int nbits)
{
  gcry_sexp_t gen_info;
  gcry_sexp_t skey;

  int h = 0;
  h = gcry_sexp_build(&gen_info,&h,"(genkey (rsa (nbits %d)))",nbits);
  if(h)
    {
      return 1;
    }
  int err = gcry_pk_genkey(&skey,gen_info);
  gcry_sexp_release(gen_info);
  if(err)
    {
      return 1;
    }
  gcry_sexp_t tmp;

  tmp = gcry_sexp_find_token(skey,"n",1);
  key->n = gcry_sexp_nth_buffer(tmp,1,&(key->n_size));
  easyPrtSexp(tmp);
  prthex(key->n,key->n_size);
  prthex("nihao",5);
  gcry_sexp_release(tmp);

  tmp = gcry_sexp_find_token(skey,"e",1);
  key->e = gcry_sexp_nth_buffer(tmp,1,&(key->e_size));
  gcry_sexp_release(tmp);

  tmp = gcry_sexp_find_token(skey,"d",1);
  key->d = gcry_sexp_nth_buffer(tmp,1,&(key->d_size));
  gcry_sexp_release(tmp);

  tmp = gcry_sexp_find_token(skey,"p",1);
  key->p = gcry_sexp_nth_buffer(tmp,1,&(key->p_size));
  gcry_sexp_release(tmp);

  tmp = gcry_sexp_find_token(skey,"q",1);
  key->q = gcry_sexp_nth_buffer(tmp,1,&(key->q_size));
  gcry_sexp_release(tmp);

  tmp = gcry_sexp_find_token(skey,"u",1);
  key->u = gcry_sexp_nth_buffer(tmp,1,&(key->u_size));
  gcry_sexp_release(tmp);

  gcry_sexp_release(skey);
  key->nbits = nbits;

  return 0;

}

gcry_sexp_t easyRSAGetKeySexp(RSA_key_t *sec,RSA_key_t *pub)
{
  gcry_sexp_t out;
  if(sec)
    {
      gcry_sexp_build(&out,0,"(private-key (rsa (n %b)(e %b)(d %b)(p %b)(q %b)(u %b)))",sec->n_size,sec->n,sec->e_size,sec->e,sec->d_size,sec->d,sec->p_size,sec->p,sec->q_size,sec->q,sec->u_size,sec->u);
    }
  else if(pub)
    {
      gcry_sexp_build(&out,0,"(public-key (rsa (n %b)(e %b)))",pub->n_size,pub->n,pub->e_size,pub->e);
    }
  else
    {
      return 0;
    }
  return out;
}

xmlNodePtr easyXMLSearchChild(xmlNodePtr parent,xmlChar *name)
{
  xmlNodePtr child = xmlFirstElementChild(parent);
  if(child == 0)
    return 0;
  while(!xmlStrEqual(child->name,name))
    {
      child = xmlNextElementSibling(child);
      if(child == 0)
        return 0;
    }
  return child;
}

xmlNodePtr easyXMLSearchSibling(xmlNodePtr node,xmlChar *name)
{
  node = xmlNextElementSibling(node);
  if(node == 0)
    return 0;
  while(!xmlStrEqual(node->name,name))
    {
      node = xmlNextElementSibling(node);
      if(node == 0)
        return 0;
    }
  return node;
}

int easyRSASaveKeyToFile(RSA_key_t *key,const char *fn,int which)
{
  xmlDocPtr doc = xmlNewDoc("1.0");
  xmlNodePtr root = xmlNewDocNode(doc,0,"WTPki",0);
  xmlDocSetRootElement(doc,root);
  xmlNewProp(root,"ver","1a");
  xmlNodePtr key_node = xmlNewChild(root,0,"KeyData",0);

  char scm[30] = {0};
  sprintf(scm,"nbits : %d",key->nbits);
  xmlNodePtr cm = xmlNewComment(scm);
  xmlAddChild(key_node,cm);

  xmlNewProp(key_node,"algo","rsa");

  if(which)
    {
      key_node = xmlNewChild(key_node,0,"PublicKey",0);
    }
  else
    {
      key_node = xmlNewChild(key_node,0,"PrivateKey",0);
    }

  vector<char *> tmps;
  char *tmp;

  tmp = prthexbuf(key->n,key->n_size);
  xmlNewChild(key_node,0,"n",tmp);
  tmps.push_back(tmp);

  tmp = prthexbuf(key->e,key->e_size);
  xmlNewChild(key_node,0,"e",tmp);
  tmps.push_back(tmp);

  if(!which)
    {
      tmp = prthexbuf(key->d,key->d_size);
      xmlNewChild(key_node,0,"d",tmp);
      tmps.push_back(tmp);

      tmp = prthexbuf(key->p,key->p_size);
      xmlNewChild(key_node,0,"p",tmp);
      tmps.push_back(tmp);

      tmp = prthexbuf(key->q,key->q_size);
      xmlNewChild(key_node,0,"q",tmp);
      tmps.push_back(tmp);

      tmp = prthexbuf(key->u,key->u_size);
      xmlNewChild(key_node,0,"u",tmp);
      tmps.push_back(tmp);

    }

  int err = xmlSaveFormatFile(fn,doc,1);
  xmlFreeDoc(doc);
  for(char *i : tmps)
    {
      free(i);
    }
  return err;
}

int easyRSAReadKeyFromFile(RSA_key_t *key,const char *fn)
{
  xmlDocPtr doc = xmlReadFile(fn,0,XML_PARSE_HUGE);
  if(doc == 0)
    return 1;
  xmlNodePtr root = xmlDocGetRootElement(doc);
  xmlNodePtr key_node;
  if(root == 0)
    THROWFAIL(xml_fail);

  key_node = easyXMLSearchChild(root,"KeyData");
  if(key_node == 0)
    THROWFAIL(xml_fail);
  prt(key_node->name);

  key_node = easyXMLSearchChild(key_node,"PrivateKey");
  xmlNodePtr cnt;
  xmlChar *cnts;
  if(key_node)
    {
      cnt = easyXMLSearchChild(key_node,"n");
      if(!cnt)
        THROWFAIL(xml_fail);
      prt(cnt->name);
      cnts = xmlNodeGetContent(cnt);
      key->n = hextobyte(cnts);
      key->n_size = strlen(cnts)/2;
      xmlFree(cnts);

      cnt = easyXMLSearchChild(key_node,"e");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->e = hextobyte(cnts);
      key->e_size = strlen(cnts)/2;
      xmlFree(cnts);

      cnt = easyXMLSearchChild(key_node,"d");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->d = hextobyte(cnts);
      key->d_size = strlen(cnts)/2;
      xmlFree(cnts);

      cnt = easyXMLSearchChild(key_node,"p");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->p = hextobyte(cnts);
      key->p_size = strlen(cnts)/2;
      xmlFree(cnts);

      cnt = easyXMLSearchChild(key_node,"q");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->q = hextobyte(cnts);
      key->q_size = strlen(cnts)/2;
      xmlFree(cnts);

      cnt = easyXMLSearchChild(key_node,"u");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->u = hextobyte(cnts);
      key->u_size = strlen(cnts)/2;
      xmlFree(cnts);
    }
  else
    {
      key_node = easyXMLSearchChild(key_node,"PublicKey");
      if(key_node == 0)
        THROWFAIL(xml_fail);
      cnt = easyXMLSearchChild(key_node,"n");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->n = hextobyte(cnts);
      key->n_size = strlen(cnts)/2;
      xmlFree(cnts);

      cnt = easyXMLSearchChild(key_node,"e");
      if(!cnt)
        THROWFAIL(xml_fail);
      cnts = xmlNodeGetContent(cnt);
      key->e = hextobyte(cnts);
      key->e_size = strlen(cnts)/2;
      xmlFree(cnts);
    }
  xmlFreeDoc(doc);
  return 0;
xml_fail:
  prt("!");
  xmlFreeDoc(doc);
  return 2;
}



int easyRSACrypt(void *in,size_t inSize,void **out,size_t *outSize,RSA_key_t *key,int flags)
{
  int err;
  err = 0;
  gcry_sexp_t data;
  gcry_sexp_t val;
  gcry_sexp_t skey;
  gcry_sexp_t tmp;
  if(flags & eRC_ENCRYPT)
    {
      skey = easyRSAGetKeySexp(0,key);
      gcry_sexp_build(&data,0,"(data (flags pkcs1)(value %b))",inSize,in);
      err = gcry_pk_encrypt(&val,data,skey);
      if(err)
        THROWFAIL(crypt_fail);
      *out = 0;
      tmp = gcry_sexp_find_token(val,"a",1);
      *out = gcry_sexp_nth_buffer(tmp,1,outSize);
      gcry_sexp_release(tmp);
    }
  else if(flags & eRC_DECRYPT)
    {
      skey = easyRSAGetKeySexp(key,0);
      gcry_sexp_build(&data,0,"(enc-val (flags pkcs1)(rsa (a %b)))",inSize,in);
      err = gcry_pk_decrypt(&val,data,skey);
      if(err)
        THROWFAIL(crypt_fail);
      *out = gcry_sexp_nth_buffer(val,1,outSize);
    }

crypt_fail:
  gcry_sexp_release(data);
  gcry_sexp_release(val);
  gcry_sexp_release(skey);
  return err;
}

int easyRSASign()
{

}

int easyRSAVerify()
{

}
