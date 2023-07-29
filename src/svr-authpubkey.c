/*
 * Dropbear - a SSH2 server
 *
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */
/*
 * This file incorporates work covered by the following copyright and
 * permission notice:
 *
 * 	Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * 	Redistribution and use in source and binary forms, with or without
 * 	modification, are permitted provided that the following conditions
 * 	are met:
 * 	1. Redistributions of source code must retain the above copyright
 * 	   notice, this list of conditions and the following disclaimer.
 * 	2. Redistributions in binary form must reproduce the above copyright
 * 	   notice, this list of conditions and the following disclaimer in the
 * 	   documentation and/or other materials provided with the distribution.
 *
 * 	THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * 	IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * 	OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * 	IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * 	INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * 	NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * 	DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * 	THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * 	(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * 	THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This copyright and permission notice applies to the code parsing public keys
 * options string which can also be found in OpenSSH auth2-pubkey.c file
 * (user_key_allowed2). It has been adapted to work with buffers.
 *
 */

/* Process a pubkey auth request */

#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "buffer.h"
#include "signkey.h"
#include "auth.h"
#include "ssh.h"
#include "packet.h"
#include "algo.h"
#include "runopts.h"
#include "fileauth-pubkeyapi.h"

#if DROPBEAR_SVR_PUBKEY_AUTH

#define MIN_AUTHKEYS_LINE 10 /* "ssh-rsa AB" - short but doesn't matter */
#define MAX_AUTHKEYS_LINE 4200 /* max length of a line in authkeys */

static void send_msg_userauth_pk_ok(const char* sigalgo, unsigned int sigalgolen,
		const unsigned char* keyblob, unsigned int keybloblen);

/* process a pubkey auth request, sending success or failure message as
 * appropriate */
void svr_auth_pubkey(int valid_user) {

	unsigned char testkey; /* whether we're just checking if a key is usable */
	char* sigalgo = NULL;
	unsigned int sigalgolen;
	const char* keyalgo;
	unsigned int keyalgolen;
	unsigned char* keyblob = NULL;
	unsigned int keybloblen;
	unsigned int sign_payload_length;
	buffer * signbuf = NULL;
	sign_key * key = NULL;
	char* fp = NULL;
	enum signature_type sigtype;
	enum signkey_type keytype;
    int auth_failure = 1;

	TRACE(("enter pubkeyauth"))

	/* 0 indicates user just wants to check if key can be used, 1 is an
	 * actual attempt*/
	testkey = (buf_getbool(ses.payload) == 0);

	sigalgo = buf_getstring(ses.payload, &sigalgolen);
	keybloblen = buf_getint(ses.payload);
	keyblob = buf_getptr(ses.payload, keybloblen);

	if (!valid_user) {
		/* Return failure once we have read the contents of the packet
		required to validate a public key.
		Avoids blind user enumeration though it isn't possible to prevent
		testing for user existence if the public key is known */
		send_msg_userauth_failure(0, 0);
		goto out;
	}

	sigtype = signature_type_from_name(sigalgo, sigalgolen);
	if (sigtype == DROPBEAR_SIGNATURE_NONE) {
		send_msg_userauth_failure(0, 0);
		goto out;
	}

	keytype = signkey_type_from_signature(sigtype);
	keyalgo = signkey_name_from_type(keytype, &keyalgolen);

#if DROPBEAR_PLUGIN
        if (svr_ses.plugin_instance != NULL) {
            char *options_buf;
            if (svr_ses.plugin_instance->checkpubkey(
                        svr_ses.plugin_instance,
                        &ses.plugin_session,
                        keyalgo,
                        keyalgolen,
                        keyblob,
                        keybloblen,
                        ses.authstate.username) == DROPBEAR_SUCCESS) {
                /* Success */
                auth_failure = 0;

                /* Options provided? */
                options_buf = ses.plugin_session->get_options(ses.plugin_session);
                if (options_buf) {
                    struct buf temp_buf = {
                        .data = (unsigned char *)options_buf,
                        .len = strlen(options_buf),
                        .pos = 0,
                        .size = 0
                    };
                    int ret = svr_add_pubkey_options(&temp_buf, 0, "N/A");
                    if (ret == DROPBEAR_FAILURE) {
                        /* Fail immediately as the plugin provided wrong options */
                        send_msg_userauth_failure(0, 0);
                        goto out;
                    }
                }
            }
        }
#endif

	if (auth_failure) {
		send_msg_userauth_failure(0, 0);
		goto out;
	}

	/* let them know that the key is ok to use */
	if (testkey) {
		send_msg_userauth_pk_ok(sigalgo, sigalgolen, keyblob, keybloblen);
		goto out;
	}

	/* now we can actually verify the signature */

	/* get the key */
	key = new_sign_key();
	if (buf_get_pub_key(ses.payload, key, &keytype) == DROPBEAR_FAILURE) {
		send_msg_userauth_failure(0, 1);
		goto out;
	}

#if DROPBEAR_SK_ECDSA || DROPBEAR_SK_ED25519
	key->sk_flags_mask = SSH_SK_USER_PRESENCE_REQD;
	if (ses.authstate.pubkey_options && ses.authstate.pubkey_options->no_touch_required_flag) {
		key->sk_flags_mask &= ~SSH_SK_USER_PRESENCE_REQD;
	}
	if (ses.authstate.pubkey_options && ses.authstate.pubkey_options->verify_required_flag) {
		key->sk_flags_mask |= SSH_SK_USER_VERIFICATION_REQD;
	}
#endif

	/* create the data which has been signed - this a string containing
	 * session_id, concatenated with the payload packet up to the signature */
	assert(ses.payload_beginning <= ses.payload->pos);
	sign_payload_length = ses.payload->pos - ses.payload_beginning;
	signbuf = buf_new(ses.payload->pos + 4 + ses.session_id->len);
	buf_putbufstring(signbuf, ses.session_id);

	/* The entire contents of the payload prior. */
	buf_setpos(ses.payload, ses.payload_beginning);
	buf_putbytes(signbuf,
		buf_getptr(ses.payload, sign_payload_length),
		sign_payload_length);
	buf_incrpos(ses.payload, sign_payload_length);

	buf_setpos(signbuf, 0);

	/* ... and finally verify the signature */
	fp = sign_key_fingerprint(keyblob, keybloblen);
	if (buf_verify(ses.payload, key, sigtype, signbuf) == DROPBEAR_SUCCESS) {
		if (svr_opts.multiauthmethod && (ses.authstate.authtypes & ~AUTH_TYPE_PUBKEY)) {
			/* successful pubkey authentication, but extra auth required */
			dropbear_log(LOG_NOTICE,
					"Pubkey auth succeeded for '%s' with %s key %s from %s, extra auth required",
					ses.authstate.pw_name,
					signkey_name_from_type(keytype, NULL), fp,
					svr_ses.addrstring);
			ses.authstate.authtypes &= ~AUTH_TYPE_PUBKEY; /* pubkey auth ok, delete the method flag */
			send_msg_userauth_failure(1, 0); /* Send partial success */
		} else {
			/* successful authentication */
			dropbear_log(LOG_NOTICE,
					"Pubkey auth succeeded for '%s' with %s key %s from %s",
					ses.authstate.pw_name,
					signkey_name_from_type(keytype, NULL), fp,
					svr_ses.addrstring);
			send_msg_userauth_success();
		}
#if DROPBEAR_PLUGIN
                if ((ses.plugin_session != NULL) && (svr_ses.plugin_instance->auth_success != NULL)) {
                    /* Was authenticated through the external plugin. tell plugin that signature verification was ok */
                    svr_ses.plugin_instance->auth_success(ses.plugin_session);
                }
#endif
	} else {
		dropbear_log(LOG_WARNING,
				"Pubkey auth bad signature for '%s' with key %s from %s",
				ses.authstate.pw_name, fp, svr_ses.addrstring);
		send_msg_userauth_failure(0, 1);
	}
	m_free(fp);

out:
	/* cleanup stuff */
	if (signbuf) {
		buf_free(signbuf);
	}
	if (sigalgo) {
		m_free(sigalgo);
	}
	if (key) {
		sign_key_free(key);
		key = NULL;
	}
	/* Retain pubkey options only if auth succeeded */
	if (!ses.authstate.authdone) {
		svr_pubkey_options_cleanup();
	}
	TRACE(("leave pubkeyauth"))
}

/* Reply that the key is valid for auth, this is sent when the user sends
 * a straight copy of their pubkey to test, to avoid having to perform
 * expensive signing operations with a worthless key */
static void send_msg_userauth_pk_ok(const char* sigalgo, unsigned int sigalgolen,
		const unsigned char* keyblob, unsigned int keybloblen) {

	TRACE(("enter send_msg_userauth_pk_ok"))
	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_PK_OK);
	buf_putstring(ses.writepayload, sigalgo, sigalgolen);
	buf_putstring(ses.writepayload, (const char*)keyblob, keybloblen);

	encrypt_packet();
	TRACE(("leave send_msg_userauth_pk_ok"))

}

#endif
