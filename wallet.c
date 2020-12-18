#include <cjose/cjose.h>
#include <stdio.h>
#include <string.h>

#include "wallet.h"
#include "./jsmn/jsmn.h"
#include "./sha256/sha256.h"
#include "openssl/sha.h"

const char *RSA_e = "AQAB";
char *RSA_n = "2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-"
                    "JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_"
                    "MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-"
                    "ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q";
const char *RSA_d = "P9N6tNRIXXGG8lnUyb43xt8ja7GVIv6QKuBXeN6SXWqYCp8OlKdei1gQC2To5bRtt36ZuV3yvI-ZRz-"
                    "Ffr4Q7at29y0mmBl0BsaoOcwxv5Dp1CJoYfJ8uBao6jyTelfsjcQKzs18xXrKRxIT0Rv6rmwe3iXmjeycCkKiqudKkv8m9RtbvdWH8AFd2ZsCL"
                    "NblVRrOZ9ZPQQCMVJLf65pF_cBfux-Zz_CJCfq93gFcN3h1tPFLX8UPBMqvqkBZzDx8PGoYgrydz-T8tcqtkDriyEL3mGYe9b2uH_"
                    "8JnzMMNMFheVPDdNBhyQQVOmQqPj7idv7677eSle4LJZANUYZdwQ";
const char *RSA_p = "8Yhaq4UMiFptSuUMcLUqOJdZ9Jr0z2KG_ZrPaaHIX8gfbtp5DGjhXEE--SwoX9ukEzR6vCewSFcEl20wnT0uTwrVs-Bf2J1L-"
                    "5tKKeiiwLQxXtk1cG5-PI-ECkqX0AP2K2Xa0wpIjldBE5SBR0S7whANpKxhVFMtNgKog4xNvxU";
const char *RSA_q = "5hkENNaWQSJ5qWXVJYh0LAHddr1NXwkKIfKNjK8vCYfOHXDgKxW4UbAIu7wIU9iZcVjTdN2UcaJMe5fBQR9ZEP8bcuY9ZpeUCkv-"
                    "g9IGw69HUXE7ERBz1es_lZOuJzENwL85Al7jOtVJ2y26g4r30q4jqaL7CcgUZjBKAytjUG0";
const char *RSA_dp = "pAn1epQsRNcVb05Muqdv-2tfnu824TqLb-YahCVqjxK9tm4O1EzO8fcmK9i_uwrTTm_QA8X4xcjDx4xS_"
                     "he1Qd2b8kSrE9UQ69s17WygTLyU41QmJSwF9F-MT-kFXjOylxrgGYDccj_0ZLXxb1PRKSX5_iNNHxY2mH4JsP4zN1k";
const char *RSA_dq = "gTTxAL6y9vZl_PKa4w2htoiBlMiuJryLvQ5X3_ULY72nxy54Ipl6vBwue0UWJAcP-u8XJpu6XKj3a7uGoIv61ql5_2Y8elyJm9Kao-"
                     "kPNVk6oggEVAu6EBiext57v7Qy9dYrLCKeVI4qf_JIts8VZG-2xO4pK4_3rH5XQTpe9W0";
const char *RSA_qi = "xTJ_ON_6kc9g3ZbunSSt_oqJBguxH2x8HVl2KQXafW-F0_DOv09P1e0fbSdOLhR-V9lLjq8DxOcvCMxkpQr2G8lTaBRVTF_-szu9adi9bgb_-"
                     "egvc_NAvRkuGE9fUmB2_nAyU-j4VUh1MMSP5qqQhMYvFdAF5y36MpI-pV1SLFQ";

static void hash_to_string(char string[65], const uint8_t hash[32])
{
	size_t i;
	for (i = 0; i < 32; i++) {
		string += sprintf(string, "%02x", hash[i]);
	}
}	

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

struct parsed_jwk {
  cjose_jwk_rsa_keyspec key;
  char *owner;
};

struct parsed_jwk parse_jwk(const char *jwk, cjose_err err) {
  int i;
  int r;
  jsmn_parser p;
  jsmntok_t t[128]; /* We expect no more than 128 tokens */
  jsmn_init(&p);
  cjose_jwk_rsa_keyspec specPub;
  cjose_jwk_rsa_keyspec specPriv;
  memset(&specPriv, 0, sizeof(cjose_jwk_rsa_keyspec));
  r = jsmn_parse(&p, jwk, strlen(jwk), t,
                 sizeof(t) / sizeof(t[0]));
  char rsa_e[200];
  char rsa_n[200];
  char rsa_d[200];
  char rsa_p[200];
  char rsa_q[200];
  char rsa_dp[200];
  char rsa_dq[200];
  char rsa_qi[200];
  for (i = 1; i < r; i++) {
    if (jsoneq(jwk, &t[i], "e") == 0) {
      sprintf(rsa_e, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_e, strlen(rsa_e), &specPriv.e, &specPriv.elen, &err);
    } else if (jsoneq(jwk, &t[i], "n") == 0) {
      sprintf(rsa_n, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_n, strlen(rsa_n), &specPriv.n, &specPriv.nlen, &err);
    } else if (jsoneq(jwk, &t[i], "d") == 0) {
      sprintf(rsa_d, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_d, strlen(rsa_d), &specPriv.d, &specPriv.dlen, &err);
    } else if (jsoneq(jwk, &t[i], "p") == 0) {
      sprintf(rsa_p, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_p, strlen(rsa_p), &specPriv.n, &specPriv.plen, &err);
    } else if (jsoneq(jwk, &t[i], "q") == 0) {
      sprintf(rsa_q, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_q, strlen(rsa_q), &specPriv.q, &specPriv.qlen, &err);
    } else if (jsoneq(jwk, &t[i], "dp") == 0) {
      sprintf(rsa_dp, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_dp, strlen(rsa_dp), &specPriv.dp, &specPriv.dplen, &err);
    } else if (jsoneq(jwk, &t[i], "dq") == 0) {
      sprintf(rsa_dq, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_dq, strlen(rsa_dq), &specPriv.dq, &specPriv.dqlen, &err);
    } else if (jsoneq(jwk, &t[i], "qi") == 0) {
      sprintf(rsa_qi, "%.*s", t[i + 1].end - t[i + 1].start,
             jwk + t[i + 1].start);
      cjose_base64url_decode(rsa_qi, strlen(rsa_qi), &specPriv.qi, &specPriv.qilen, &err);
    }
  }
  struct parsed_jwk prsf = { 
    .key = specPriv,
    .owner = rsa_n,
  };
  return prsf;
}

struct wallet new_wallet(const char *jwk_str) {
   cjose_err err;
   struct parsed_jwk prsd = parse_jwk(jwk_str, err);
   cjose_jwk_t *jwk = cjose_jwk_create_RSA_spec(&prsd.key, &err);
   uint8_t hash[32];
   char hash_string[65];
   size_t outlen = 0;
   char *output = NULL;
   calc_sha_256(hash, prsd.key.n, prsd.key.nlen);
   hash_to_string(hash_string, hash);
   cjose_base64_encode((uint8_t *)hash_string, strlen(hash_string), &output, &outlen, &err);
   struct wallet w = {
        .owner = prsd.owner, 
        .address = output,
        .jwk = jwk,
   };
   return w;
}
/**
* Sign payload with a wallet. Returns signed payload.
* @param wallet - JWK Wallet instance
* @param message - Payload to be signed
* @returns Signed payload 
**/
const char *sign(struct wallet *w, const char *message) {
    cjose_err *err;
    // set header for JWS
    cjose_header_t *hdr = cjose_header_new(err);
    cjose_header_set(hdr, CJOSE_HDR_ALG, CJOSE_HDR_ALG_RS256, err);
    size_t message_len = strlen(message);
    // Sign with JWK
    cjose_jws_t *sig = cjose_jws_sign(w->jwk, hdr, message, message_len, err);
    const char *compact = NULL;
    // Serialise JWK to char*
    cjose_jws_export(sig, &compact, err);
    return compact;
}

int main() {
    struct wallet w = new_wallet("{\"kty\":\"RSA\",\"e\":\"AQAB\""
                     ",\"n\":\"2Rgbvu_cGMpvVl8DE6aGGX7IE2lKn5c9ZtexriFrCLqBbKt2TBOZkoCn_AbcDjUVk23CxsIj9Z1VfsL_0UeVA_AeOLUWw0F5-"
                     "JhoK6NBeLpYZOz7HYieTOSJjSxYhoCYtVbLKI27e3NEvckxTs-90CdKl71P7YwrdSrY59hR-u2etyNCRGAPcoDH5xYJxrG2p5FH_Dh_"
                     "MQ0ugDnJY2_b_-w9NS2Y2atIkzXZDjtcSpjImKpL0eIFF69ptiF8vd4q2j-"
                     "ougipFBGP9U5bSVzeZ7FyGkJ5Qa2DYc0osYi1QFs3YZKzkKfcblx14u-yZYhUkZHlb_jbfulnUHxDdO_r8Q\""
                     ",\"d\":\"P9N6tNRIXXGG8lnUyb43xt8ja7GVIv6QKuBXeN6SXWqYCp8OlKdei1gQC2To5bRtt36ZuV3yvI-ZRz-"
                     "Ffr4Q7at29y0mmBl0BsaoOcwxv5Dp1CJoYfJ8uBao6jyTelfsjcQKzs18xXrKRxIT0Rv6rmwe3iXmjeycCkKiqudKkv8m9RtbvdWH8AFd2ZsC"
                     "LNblVRrOZ9ZPQQCMVJLf65pF_cBfux-Zz_CJCfq93gFcN3h1tPFLX8UPBMqvqkBZzDx8PGoYgrydz-T8tcqtkDriyEL3mGYe9b2uH_"
                     "8JnzMMNMFheVPDdNBhyQQVOmQqPj7idv7677eSle4LJZANUYZdwQ\""
                     ",\"p\":\"8Yhaq4UMiFptSuUMcLUqOJdZ9Jr0z2KG_ZrPaaHIX8gfbtp5DGjhXEE--SwoX9ukEzR6vCewSFcEl20wnT0uTwrVs-Bf2J1L-"
                     "5tKKeiiwLQxXtk1cG5-PI-ECkqX0AP2K2Xa0wpIjldBE5SBR0S7whANpKxhVFMtNgKog4xNvxU\""
                     ",\"q\":\"5hkENNaWQSJ5qWXVJYh0LAHddr1NXwkKIfKNjK8vCYfOHXDgKxW4UbAIu7wIU9iZcVjTdN2UcaJMe5fBQR9ZEP8bcuY9ZpeUCkv-"
                     "g9IGw69HUXE7ERBz1es_lZOuJzENwL85Al7jOtVJ2y26g4r30q4jqaL7CcgUZjBKAytjUG0\""
                     ",\"dp\":\"pAn1epQsRNcVb05Muqdv-2tfnu824TqLb-YahCVqjxK9tm4O1EzO8fcmK9i_uwrTTm_QA8X4xcjDx4xS_"
                     "he1Qd2b8kSrE9UQ69s17WygTLyU41QmJSwF9F-MT-kFXjOylxrgGYDccj_0ZLXxb1PRKSX5_iNNHxY2mH4JsP4zN1k\""
                     ",\"dq\":\"gTTxAL6y9vZl_PKa4w2htoiBlMiuJryLvQ5X3_ULY72nxy54Ipl6vBwue0UWJAcP-u8XJpu6XKj3a7uGoIv61ql5_"
                     "2Y8elyJm9Kao-kPNVk6oggEVAu6EBiext57v7Qy9dYrLCKeVI4qf_JIts8VZG-2xO4pK4_3rH5XQTpe9W0\""
                     ",\"qi\":\"xTJ_ON_6kc9g3ZbunSSt_oqJBguxH2x8HVl2KQXafW-F0_DOv09P1e0fbSdOLhR-V9lLjq8DxOcvCMxkpQr2G8lTaBRVTF_-"
                     "szu9adi9bgb_-egvc_NAvRkuGE9fUmB2_nAyU-j4VUh1MMSP5qqQhMYvFdAF5y36MpI-pV1SLFQ\""
                     "}");

    printf("Wallet Address: %s\n", w.address);
    const char *s = sign(&w, "Hello");
    printf("Signature for 'Hello': %s\n", s);
}


