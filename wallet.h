#ifndef WALLET_H
#define WALLET_H


struct wallet {
    char *address;
    char *owner;
    cjose_jwk_t *jwk;
};

#endif
