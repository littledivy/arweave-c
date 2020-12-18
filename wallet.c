#include <cjose/cjose.h>
#include <stdio.h>
#include <string.h>

#include "wallet.h"
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

struct wallet new_wallet() {
   cjose_err err;
   cjose_jwk_rsa_keyspec specPub;
   cjose_jwk_rsa_keyspec specPriv;
   memset(&specPriv, 0, sizeof(cjose_jwk_rsa_keyspec));
   cjose_base64url_decode(RSA_e, strlen(RSA_e), &specPriv.e, &specPriv.elen, &err);
   cjose_base64url_decode(RSA_n, strlen(RSA_n), &specPriv.n, &specPriv.nlen, &err);
   cjose_base64url_decode(RSA_d, strlen(RSA_d), &specPriv.d, &specPriv.dlen, &err);
   cjose_base64url_decode(RSA_p, strlen(RSA_p), &specPriv.p, &specPriv.plen, &err);
   cjose_base64url_decode(RSA_q, strlen(RSA_q), &specPriv.q, &specPriv.qlen, &err);
   cjose_base64url_decode(RSA_dp, strlen(RSA_dp), &specPriv.dp, &specPriv.dplen, &err);
   cjose_base64url_decode(RSA_dq, strlen(RSA_dq), &specPriv.dq, &specPriv.dqlen, &err);
   cjose_base64url_decode(RSA_qi, strlen(RSA_qi), &specPriv.qi, &specPriv.qilen, &err);
   cjose_jwk_t *jwk = NULL;
   jwk = cjose_jwk_create_RSA_spec(&specPriv, &err);
   
   uint8_t hash[32];
   char hash_string[65];
   size_t outlen = 0;
   char *output = NULL;
   calc_sha_256(hash, specPriv.n, specPriv.nlen);
   hash_to_string(hash_string, hash);
   cjose_base64_encode((uint8_t *)hash_string, strlen(hash_string), &output, &outlen, &err);
   struct wallet w = {
        .owner = RSA_n, 
        .address = output,
   };
    return w;
}

int main() {
    struct wallet w = new_wallet();
    printf("%s", w.address);
}


