/*
   BLAKE2 reference source code package - reference C implementations

   Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under the
   terms of the CC0, the OpenSSL Licence, or the Apache Public License 2.0, at
   your option.  The terms of these licenses can be found at:

   - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
   - OpenSSL license   : https://www.openssl.org/source/license.html
   - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0

   More information about the BLAKE2 hash function can be found at
   https://blake2.net.
*/
#ifndef BLAKE2_H
#define BLAKE2_H

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif
enum blake2refs_constant
  {
    BLAKE2REFS_BLOCKBYTES = 64,
    BLAKE2REFS_OUTBYTES   = 32,
    BLAKE2REFS_KEYBYTES   = 32,
    BLAKE2REFS_SALTBYTES  = 8,
    BLAKE2REFS_PERSONALBYTES = 8
  };

  enum blake2refb_constant
  {
    BLAKE2REFB_BLOCKBYTES = 128,
    BLAKE2REFB_OUTBYTES   = 64,
    BLAKE2REFB_KEYBYTES   = 64,
    BLAKE2REFB_SALTBYTES  = 16,
    BLAKE2REFB_PERSONALBYTES = 16
  };

  typedef struct blake2refs_state__
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2REFS_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2refs_state;

  typedef struct blake2refb_state__
  {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2REFB_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2refb_state;

  typedef struct blake2refsp_state__
  {
    blake2refs_state S[8][1];
    blake2refs_state R[1];
    uint8_t       buf[8 * BLAKE2REFS_BLOCKBYTES];
    size_t        buflen;
    size_t        outlen;
  } blake2refsp_state;

  typedef struct blake2refbp_state__
  {
    blake2refb_state S[4][1];
    blake2refb_state R[1];
    uint8_t       buf[4 * BLAKE2REFB_BLOCKBYTES];
    size_t        buflen;
    size_t        outlen;
  } blake2refbp_state;


  BLAKE2_PACKED(struct blake2refs_param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;  /* 12 */
    uint16_t xof_length;    /* 14 */
    uint8_t  node_depth;    /* 15 */
    uint8_t  inner_length;  /* 16 */
    /* uint8_t  reserved[0]; */
    uint8_t  salt[BLAKE2REFS_SALTBYTES]; /* 24 */
    uint8_t  personal[BLAKE2REFS_PERSONALBYTES];  /* 32 */
  });

  typedef struct blake2refs_param__ blake2refs_param;

  BLAKE2_PACKED(struct blake2refb_param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;   /* 12 */
    uint32_t xof_length;    /* 16 */
    uint8_t  node_depth;    /* 17 */
    uint8_t  inner_length;  /* 18 */
    uint8_t  reserved[14];  /* 32 */
    uint8_t  salt[BLAKE2REFB_SALTBYTES]; /* 48 */
    uint8_t  personal[BLAKE2REFB_PERSONALBYTES];  /* 64 */
  });

  typedef struct blake2refb_param__ blake2refb_param;

  typedef struct blake2refxs_state__
  {
    blake2refs_state S[1];
    blake2refs_param P[1];
  } blake2refxs_state;

  typedef struct blake2refxb_state__
  {
    blake2refb_state S[1];
    blake2refb_param P[1];
  } blake2refxb_state;

  /* Padded structs result in a compile-time error */
  enum {
    BLAKEREF2_DUMMY_1 = 1/(int)(sizeof(blake2refs_param) == BLAKE2REFS_OUTBYTES),
    BLAKEREF2_DUMMY_2 = 1/(int)(sizeof(blake2refb_param) == BLAKE2REFB_OUTBYTES)
  };
  enum blake2s_constant
  {
    BLAKE2S_BLOCKBYTES = 64,
    BLAKE2S_OUTBYTES   = 32,
    BLAKE2S_KEYBYTES   = 32,
    BLAKE2S_SALTBYTES  = 8,
    BLAKE2S_PERSONALBYTES = 8
  };

  enum blake2b_constant
  {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES   = 64,
    BLAKE2B_KEYBYTES   = 64,
    BLAKE2B_SALTBYTES  = 16,
    BLAKE2B_PERSONALBYTES = 16
  };

  typedef struct blake2s_state__
  {
    uint32_t h[8];
    uint32_t t[2];
    uint32_t f[2];
    uint8_t  buf[BLAKE2S_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2s_state;

  typedef struct blake2b_state__
  {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[BLAKE2B_BLOCKBYTES];
    size_t   buflen;
    size_t   outlen;
    uint8_t  last_node;
  } blake2b_state;

  typedef struct blake2sp_state__
  {
    blake2s_state S[8][1];
    blake2s_state R[1];
    uint8_t       buf[8 * BLAKE2S_BLOCKBYTES];
    size_t        buflen;
    size_t        outlen;
  } blake2sp_state;

  typedef struct blake2bp_state__
  {
    blake2b_state S[4][1];
    blake2b_state R[1];
    uint8_t       buf[4 * BLAKE2B_BLOCKBYTES];
    size_t        buflen;
    size_t        outlen;
  } blake2bp_state;


  BLAKE2_PACKED(struct blake2s_param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;  /* 12 */
    uint16_t xof_length;    /* 14 */
    uint8_t  node_depth;    /* 15 */
    uint8_t  inner_length;  /* 16 */
    /* uint8_t  reserved[0]; */
    uint8_t  salt[BLAKE2S_SALTBYTES]; /* 24 */
    uint8_t  personal[BLAKE2S_PERSONALBYTES];  /* 32 */
  });

  typedef struct blake2s_param__ blake2s_param;

  BLAKE2_PACKED(struct blake2b_param__
  {
    uint8_t  digest_length; /* 1 */
    uint8_t  key_length;    /* 2 */
    uint8_t  fanout;        /* 3 */
    uint8_t  depth;         /* 4 */
    uint32_t leaf_length;   /* 8 */
    uint32_t node_offset;   /* 12 */
    uint32_t xof_length;    /* 16 */
    uint8_t  node_depth;    /* 17 */
    uint8_t  inner_length;  /* 18 */
    uint8_t  reserved[14];  /* 32 */
    uint8_t  salt[BLAKE2B_SALTBYTES]; /* 48 */
    uint8_t  personal[BLAKE2B_PERSONALBYTES];  /* 64 */
  });

  typedef struct blake2b_param__ blake2b_param;

  typedef struct blake2xs_state__
  {
    blake2s_state S[1];
    blake2s_param P[1];
  } blake2xs_state;

  typedef struct blake2xb_state__
  {
    blake2b_state S[1];
    blake2b_param P[1];
  } blake2xb_state;

  /* Padded structs result in a compile-time error */
  enum {
    BLAKE2_DUMMY_1 = 1/(int)(sizeof(blake2s_param) == BLAKE2S_OUTBYTES),
    BLAKE2_DUMMY_2 = 1/(int)(sizeof(blake2b_param) == BLAKE2B_OUTBYTES)
  };

  /* Streaming API */
  int blake2s_init( blake2s_state *S, size_t outlen );
  int blake2s_init_key( blake2s_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2s_init_param( blake2s_state *S, const blake2s_param *P );
  int blake2s_update( blake2s_state *S, const void *in, size_t inlen );
  int blake2s_final( blake2s_state *S, void *out, size_t outlen );

  int blake2b_init( blake2b_state *S, size_t outlen );
  int blake2b_init_key( blake2b_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2b_init_param( blake2b_state *S, const blake2b_param *P );
  int blake2b_update( blake2b_state *S, const void *in, size_t inlen );
  int blake2b_final( blake2b_state *S, void *out, size_t outlen );

  int blake2sp_init( blake2sp_state *S, size_t outlen );
  int blake2sp_init_key( blake2sp_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2sp_update( blake2sp_state *S, const void *in, size_t inlen );
  int blake2sp_final( blake2sp_state *S, void *out, size_t outlen );

  int blake2bp_init( blake2bp_state *S, size_t outlen );
  int blake2bp_init_key( blake2bp_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2bp_update( blake2bp_state *S, const void *in, size_t inlen );
  int blake2bp_final( blake2bp_state *S, void *out, size_t outlen );

  /* Variable output length API */
  int blake2xs_init( blake2xs_state *S, const size_t outlen );
  int blake2xs_init_key( blake2xs_state *S, const size_t outlen, const void *key, size_t keylen );
  int blake2xs_update( blake2xs_state *S, const void *in, size_t inlen );
  int blake2xs_final(blake2xs_state *S, void *out, size_t outlen);

  int blake2xb_init( blake2xb_state *S, const size_t outlen );
  int blake2xb_init_key( blake2xb_state *S, const size_t outlen, const void *key, size_t keylen );
  int blake2xb_update( blake2xb_state *S, const void *in, size_t inlen );
  int blake2xb_final(blake2xb_state *S, void *out, size_t outlen);

  /* Simple API */
  int blake2s( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2b( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int blake2sp( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2bp( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int blake2xs( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2xb( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
 int blake2refs_init( blake2refs_state *S, size_t outlen );
  int blake2refs_init_key( blake2refs_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2refs_init_param( blake2refs_state *S, const blake2refs_param *P );
  int blake2refs_update( blake2refs_state *S, const void *in, size_t inlen );
  int blake2refs_final( blake2refs_state *S, void *out, size_t outlen );

  int blake2refb_init( blake2refb_state *S, size_t outlen );
  int blake2refb_init_key( blake2refb_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2refb_init_param( blake2refb_state *S, const blake2refb_param *P );
  int blake2refb_update( blake2refb_state *S, const void *in, size_t inlen );
  int blake2refb_final( blake2refb_state *S, void *out, size_t outlen );

  int blake2refsp_init( blake2refsp_state *S, size_t outlen );
  int blake2refsp_init_key( blake2refsp_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2refsp_update( blake2refsp_state *S, const void *in, size_t inlen );
  int blake2refsp_final( blake2refsp_state *S, void *out, size_t outlen );

  int blake2refbp_init( blake2refbp_state *S, size_t outlen );
  int blake2refbp_init_key( blake2refbp_state *S, size_t outlen, const void *key, size_t keylen );
  int blake2refbp_update( blake2refbp_state *S, const void *in, size_t inlen );
  int blake2refbp_final( blake2refbp_state *S, void *out, size_t outlen );

  /* Variable output length API */
  int blake2refxs_init( blake2refxs_state *S, const size_t outlen );
  int blake2refxs_init_key( blake2refxs_state *S, const size_t outlen, const void *key, size_t keylen );
  int blake2refxs_update( blake2refxs_state *S, const void *in, size_t inlen );
  int blake2refxs_final(blake2refxs_state *S, void *out, size_t outlen);

  int blake2refxb_init( blake2refxb_state *S, const size_t outlen );
  int blake2refxb_init_key( blake2refxb_state *S, const size_t outlen, const void *key, size_t keylen );
  int blake2refxb_update( blake2refxb_state *S, const void *in, size_t inlen );
  int blake2refxb_final(blake2refxb_state *S, void *out, size_t outlen);

  /* Simple API */
  int blake2refs( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2refb( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int blake2refsp( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2refbp( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  int blake2refxs( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  int blake2refxb( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

  /* This is simply an alias for blake2refb */
  int blake2ref( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );
  
  /* This is simply an alias for blake2b */
  int blake2( void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen );

#if defined(__cplusplus)
}
#endif

#endif
