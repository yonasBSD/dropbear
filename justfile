build:
    ./configure --enable-static --enable-plugin --enable-epka
    just localoptions
    gmake clean
    gmake PROGRAMS=dropbear

localoptions:
    sd --string-mode '"/etc/' '"/usr/local/etc/' src/default_options.h
    rm -f localoptions.h
    echo "#define DROPBEAR_SMALL_CODE 0" >> localoptions.h
    echo "#define DEBUG_TRACE 1" >> localoptions.h
    echo "#define DEBUG_NOFORK 1" >> localoptions.h
    echo "#define DROPBEAR_3DES 0" >> localoptions.h
    echo "#define DROPBEAR_AES128 0" >> localoptions.h
    echo "#define DROPBEAR_AES256 0" >> localoptions.h
    echo "#define DROPBEAR_CHACHA20POLY1305 1" >> localoptions.h
    echo "#define DROPBEAR_ENABLE_CBC_MODE 0" >> localoptions.h
    echo "#define DROPBEAR_ENABLE_CTR_MODE 0" >> localoptions.h
    echo "#define DROPBEAR_ENABLE_GCM_MODE 0" >> localoptions.h
    echo "#define DROPBEAR_CURVE25519 1" >> localoptions.h
    echo "#define DROPBEAR_DSS 0" >> localoptions.h
    echo "#define DROPBEAR_ECDH 0" >> localoptions.h
    echo "#define DROPBEAR_DH_GROUP1 0" >> localoptions.h
    echo "#define DROPBEAR_DH_GROUP14_SHA1 0" >> localoptions.h
    echo "#define DROPBEAR_DH_GROUP14_SHA256 0" >> localoptions.h
    echo "#define DROPBEAR_DH_GROUP16 1" >> localoptions.h
    echo "#define DROPBEAR_RSA 0" >> localoptions.h
    echo "#define DROPBEAR_RSA_SHA1 0" >> localoptions.h
    echo "#define DROPBEAR_ECDSA 1" >> localoptions.h
    echo "#define DROPBEAR_E25519 1" >> localoptions.h
    echo "#define DROPBEAR_MD5_HMAC 0" >> localoptions.h
    echo "#define DROPBEAR_SHA1_HMAC 0" >> localoptions.h
    echo "#define DROPBEAR_SHA1_96_HMAC 0" >> localoptions.h
    echo "#define DROPBEAR_SHA2_256_HMAC 0" >> localoptions.h
    echo "#define DROPBEAR_SHA2_512_HMAC 1" >> localoptions.h
    echo "#define DROPBEAR_X11FWD 1" >> localoptions.h
    echo "#define DROPBEAR_SVR_PUBKEY_AUTH 1" >> localoptions.h
    echo "#define DROPBEAR_SVR_PASSWORD_AUTH 0" >> localoptions.h
    echo "#define DROPBEAR_SVR_PAM_AUTH 0" >> localoptions.h
