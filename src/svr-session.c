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

#include "includes.h"
#include "session.h"
#include "dbutil.h"
#include "packet.h"
#include "algo.h"
#include "buffer.h"
#include "dss.h"
#include "ssh.h"
#include "dbrandom.h"
#include "kex.h"
#include "channel.h"
#include "chansession.h"
#include "atomicio.h"
#include "tcpfwd.h"
#include "service.h"
#include "auth.h"
#include "runopts.h"
#include "crypto_desc.h"
#include "fuzz.h"
#include "fileauth-common.h"

/*
 * dropbear_epka - Plugin Auth Plugin for Dropbear
 *
 * Copyright (c) 2018 Fabrizio Bertocci
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


/* fileauth.c - a Plugin (External Public Key Authentication) Plug-in
 * for Dropbear that performs a similar operation as dropbear that reads
 * the list of public keys from ~/.ssh/authorized_keys file
 *
 * You must specify the file containing the keys in the plugin
 * options (see option -A of dropbear).
 *
 * The format of the file is a JSON array of objects with the following properties:
 *  "user": string     - Name of the user for which the key apply
 *  "keytype": string  - A valid key type supported (i.e. "ssh-rsa", "ssh-dsa", ...)
 *  "key": string      - Base-64 encoded public key
 *  "options": string  - [optional] session options
 *  "comments": string - [optional] Comments associated with this entry
 *
 *
 * Requires the cJSON library cJSON from: https://github.com/DaveGamble/cJSON
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "fileauth-common.h"
#include "pubkeyapi.h"      /* The Plugin API */

#define PLUGIN_NAME             "fileauth"

#define MSG_PREFIX              "[" PLUGIN_NAME "] - "

/*
 * The following function is implemented in dropbear (it's part of
 * the libtomcrypt, included in dropbear). For the plugin to be
 * able to access global symbols defined in the loader application
 * (dropbear) you need to link dropbear with the option -rdynamic
 *
 *
   Relaxed base64 decode a block of memory
   @param in       The base64 data to decode
   @param inlen    The length of the base64 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK(0) if successful
*/
extern int base64_decode(const unsigned char *in,  unsigned long inlen,
                        unsigned char *out, unsigned long *outlen);

/* The plugin instance, extends PluginInstance */
struct MyPlugin {
    struct PluginInstance     m_parent;

    int                     m_verbose;
    char *                  m_fileName;     /* strdup'd */
    cJSON *                 m_jsonRoot;     /* must free with cJSON_Delete */
};

/* The ssh session: extends PluginSession */
struct MySession {
    struct PluginSession      m_parent;

    /* Cached User: set during pre-auth, it's reused during the 2nd call to
     * avoid re-scanning the entire file
     */
    cJSON *                 m_cachedUser;
    const char *            m_cachedUserName;   /* Ptr to the cachedUser json object */
};

/* Returns 1 if success (key match), 0 if key don't match */
static int compareKey(const char *keyblob, unsigned int keybloblen, const char *encodedKey) {
    char *buf = NULL;
    unsigned long bufLen = strlen(encodedKey) * 2;
    int retVal = 0;

    buf = malloc(bufLen);

    if (base64_decode(encodedKey, strlen(encodedKey), &buf[0], &bufLen) != 0) {
        /* Decode failure */
        printf(MSG_PREFIX "base64 decode fail\n");
        goto done;
    }
    /* Decode success, compare binary values */
    if (keybloblen != bufLen) {
        /* Key size mismatch */
        printf(MSG_PREFIX "Key size mismatch: in=%u, decodedKey=%lu\n", keybloblen, bufLen);
        goto done;
    }
    retVal = memcmp(keyblob, buf, keybloblen) == 0;

done:
    if (buf) {
        free(buf);
    }
    return retVal;
}

/* Returns 1 if success, 0 if auth failed */
static int matchLine(cJSON *node,
        const char* algo,
        unsigned int algolen,
        const unsigned char* keyblob,
        unsigned int keybloblen,
        const char *username) {
    cJSON *jsonUser;
    cJSON *jsonKeytype;
    cJSON *jsonKey;

    jsonUser = cJSON_GetObjectItem(node, "user");
    if (!jsonUser || jsonUser->type != cJSON_String) {
        /* Missing 'user' or invalid type */
        return 0;
    }
    jsonKeytype = cJSON_GetObjectItem(node, "keytype");
    if (!jsonKeytype || jsonKeytype->type != cJSON_String) {
        /* Missing 'keytype' or invalid type */
        return 0;
    }
    jsonKey = cJSON_GetObjectItem(node, "key");
    if (!jsonKey || jsonKey->type != cJSON_String) {
        /* Missing 'key' or invalid type */
        return 0;
    }

    if (strcmp(username, jsonUser->valuestring)) {
        /* User mismatch */
        return 0;
    }
    if (strncmp(algo, jsonKeytype->valuestring, algolen)) {
        /* Algo mismatch */
        return 0;
    }
    if (!compareKey(keyblob, keybloblen, jsonKey->valuestring)) {
        /* Key mismatch */
        return 0;
    }
    /* Match */
    return 1;
}

static char * MyGetOptions(struct PluginSession *_session) {
    struct MySession *session = (struct MySession *)_session;
    // struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;
    cJSON *optionNode = cJSON_GetObjectItem(session->m_cachedUser, "options");
    if (!optionNode) {
        return NULL;
    }
    if (optionNode->type != cJSON_String) {
        printf(MSG_PREFIX "invalid type for 'option' property: not a string");
        return NULL;
    }
    return optionNode->valuestring;
}

static int MyCheckPubKey(struct PluginInstance *instance,
        struct PluginSession **sessionInOut,
        const char* algo,
        unsigned int algolen,
        const unsigned char* keyblob,
        unsigned int keybloblen,
        const char *username) {
    struct MyPlugin * me = (struct MyPlugin *)instance;
    struct MySession *retVal = (struct MySession *)*sessionInOut;

    if (me->m_verbose) {
        printf(MSG_PREFIX "checking user '%s'...\n", username);
    }
    if (!retVal) {
        /* Authenticate by scanning the JSON file */
        cJSON *node;
        cJSON *foundNode = NULL;
        for (node = me->m_jsonRoot->child; node; node = node->next) {
            if (matchLine(node, algo, algolen, keyblob, keybloblen, username)) {
                /* Yes, I know you can interrupt the search now, but by always
                 * scanning the entire list of users, you can prevent discovery of
                 * all the user names in the JSON file by measuring the failure time.
                 * If you always scan the file, your failure time will remain constant.
                 */
                foundNode = node;
            }
        }
        if (!foundNode) {
            /* Auth failed: no match */
            if (me->m_verbose) {
                printf(MSG_PREFIX "pre-auth failed: no matching entry\n");
            }
            return -1;
        }

        /* Auth success */

        /* Create a new session */
        retVal = calloc(1, sizeof(*retVal));
        if (!retVal) {
            return -1; /* Failure */
        }

        retVal->m_parent.plugin_instance = instance;
        retVal->m_parent.get_options = MyGetOptions;

        retVal->m_cachedUser = foundNode;    /* Save ptr to auth entry */
        retVal->m_cachedUserName = cJSON_GetObjectItem(foundNode, "user")->valuestring;  /* Already guaranteed it exist */

        *sessionInOut = &retVal->m_parent;
        if (me->m_verbose) {
            printf(MSG_PREFIX "user '%s' pre-auth success\n", username);
        }

    } else {

        /* Already pre-auth, just validate the current node */
        if (!matchLine(retVal->m_cachedUser, algo, algolen, keyblob, keybloblen, username)) {
            /* Failed */
            if (me->m_verbose) {
                printf(MSG_PREFIX "pre-auth failed: no matching entry\n");
                return -1; /* Failure */
            }
        }
        if (me->m_verbose) {
            printf(MSG_PREFIX "user '%s' auth validated\n", username);
        }
    }
    return 0;   /* Success */
}

static void MyAuthSuccess(struct PluginSession *_session) {
    struct MySession *session = (struct MySession *)_session;
    struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;

    if (me->m_verbose) {
        printf(MSG_PREFIX "auth_success called - user = %s\n", session->m_cachedUserName);
    }
}

static void MyDeleteSession(struct PluginSession *_session) {
    struct MySession *session = (struct MySession *)_session;

    if (session) {
        struct MyPlugin *me = (struct MyPlugin *)_session->plugin_instance;
        free(session);
        if (me->m_verbose) {
            printf(MSG_PREFIX "session_deleted\n");
        }
    }
}

static void MyDeletePlugin(struct PluginInstance *instance) {
    struct MyPlugin * me = (struct MyPlugin *)instance;

    if (me) {
        int verbose = me->m_verbose;
        if (me->m_fileName) {
            free(me->m_fileName);
        }
        if (me->m_jsonRoot) {
            cJSON_Delete(me->m_jsonRoot);
        }
        memset(me, 0, sizeof(*me));
        free(me);
        if (verbose) {
            printf(MSG_PREFIX "plugin deleted\n");
        }
    }

}

/* The plugin entry point */
void * my2_plugin_new(int verbose, const char *options, const char *addrstring) {
    struct MyPlugin *retVal;
    cJSON *jsonRoot = NULL;
    char *confFile = NULL;
    long confFileLength = 0;
    const char *errMsg = NULL;

    if (!options) {
        printf(MSG_PREFIX "missing auth file from options\n");
        goto err;
    }
    if (!readFile(options,  &confFile, &confFileLength, &errMsg)) {
        printf(MSG_PREFIX "error reading configuration file '%s': %s\n", options, errMsg);
        goto err;
    }

    jsonRoot = cJSON_Parse(confFile);
    if (!jsonRoot) {
        printf(MSG_PREFIX "error parsing configuration file '%s'\n", options);
        goto err;
    }

    /* Perform a simple validation of the JSON file and verify that the root object is
     * an array */
    if (jsonRoot->type != cJSON_Array) {
        printf(MSG_PREFIX "error in configuration file: expected root array\n");
        goto err;
    }


    retVal = calloc(1, sizeof(*retVal));
    retVal->m_parent.api_version[0] = DROPBEAR_PLUGIN_VERSION_MAJOR;
    retVal->m_parent.api_version[1] = DROPBEAR_PLUGIN_VERSION_MINOR;

    retVal->m_parent.checkpubkey = MyCheckPubKey;
    retVal->m_parent.auth_success = MyAuthSuccess;
    retVal->m_parent.delete_session = MyDeleteSession;
    retVal->m_parent.delete_plugin = MyDeletePlugin;
    retVal->m_verbose = verbose;
    retVal->m_fileName = strdup(options);
    retVal->m_jsonRoot = jsonRoot;

    if (verbose) {
        printf(MSG_PREFIX "plugin initialized - config file = %s, clientIP=%s\n", (options ? options : "<N/A>"), addrstring);
    }
    return &retVal->m_parent;

err:
    if (jsonRoot) {
        cJSON_Delete(jsonRoot);
    }
    if (confFile) {
        free(confFile);
    }
    return NULL;
}

static void svr_remoteclosed(void);
static void svr_algos_initialise(void);

struct serversession svr_ses; /* GLOBAL */

static const packettype svr_packettypes[] = {
	{SSH_MSG_CHANNEL_DATA, recv_msg_channel_data},
	{SSH_MSG_CHANNEL_WINDOW_ADJUST, recv_msg_channel_window_adjust},
	{SSH_MSG_USERAUTH_REQUEST, recv_msg_userauth_request}, /* server */
	{SSH_MSG_SERVICE_REQUEST, recv_msg_service_request}, /* server */
	{SSH_MSG_KEXINIT, recv_msg_kexinit},
	{SSH_MSG_KEXDH_INIT, recv_msg_kexdh_init}, /* server */
	{SSH_MSG_NEWKEYS, recv_msg_newkeys},
	{SSH_MSG_GLOBAL_REQUEST, recv_msg_global_request_remotetcp},
	{SSH_MSG_CHANNEL_REQUEST, recv_msg_channel_request},
	{SSH_MSG_CHANNEL_OPEN, recv_msg_channel_open},
	{SSH_MSG_CHANNEL_EOF, recv_msg_channel_eof},
	{SSH_MSG_CHANNEL_CLOSE, recv_msg_channel_close},
	{SSH_MSG_CHANNEL_SUCCESS, ignore_recv_response},
	{SSH_MSG_CHANNEL_FAILURE, ignore_recv_response},
	{SSH_MSG_REQUEST_FAILURE, ignore_recv_response}, /* for keepalive */
	{SSH_MSG_REQUEST_SUCCESS, ignore_recv_response}, /* client */
#if DROPBEAR_LISTENERS
	{SSH_MSG_CHANNEL_OPEN_CONFIRMATION, recv_msg_channel_open_confirmation},
	{SSH_MSG_CHANNEL_OPEN_FAILURE, recv_msg_channel_open_failure},
#endif
	{0, NULL} /* End */
};

static const struct ChanType *svr_chantypes[] = {
	&svrchansess,
#if DROPBEAR_SVR_LOCALTCPFWD
	&svr_chan_tcpdirect,
#endif
	NULL /* Null termination is mandatory. */
};

static void
svr_session_cleanup(void) {
	/* free potential public key options */
	svr_pubkey_options_cleanup();

	m_free(svr_ses.addrstring);
	m_free(svr_ses.remotehost);
	m_free(svr_ses.childpids);
	svr_ses.childpidsize = 0;

#if DROPBEAR_PLUGIN
        if (svr_ses.plugin_handle != NULL) {
            if (svr_ses.plugin_instance) {
                svr_ses.plugin_instance->delete_plugin(svr_ses.plugin_instance);
                svr_ses.plugin_instance = NULL;
            }

            //dlclose(svr_ses.plugin_handle);
            svr_ses.plugin_handle = NULL;
        }
#endif
}

void svr_session(int sock, int childpipe) {
	char *host, *port;
	size_t len;

	common_session_init(sock, sock);

	/* Initialise server specific parts of the session */
	svr_ses.childpipe = childpipe;
#if DROPBEAR_VFORK
	svr_ses.server_pid = getpid();
#endif

	/* for logging the remote address */
	get_socket_address(ses.sock_in, NULL, NULL, &host, &port, 0);
	len = strlen(host) + strlen(port) + 2;
	svr_ses.addrstring = m_malloc(len);
	snprintf(svr_ses.addrstring, len, "%s:%s", host, port);
	m_free(host);
	m_free(port);

#if DROPBEAR_PLUGIN
        /* Initializes the PLUGIN Plugin */
        svr_ses.plugin_handle = NULL;
        svr_ses.plugin_instance = NULL;
        if (svr_opts.pubkey_plugin) {
#if DEBUG_TRACE
            const int verbose = debug_trace;
#else
            const int verbose = 0;
#endif
            PubkeyExtPlugin_newFn  pluginConstructor;

            /* RTLD_NOW: fails if not all the symbols are resolved now. Better fail now than at run-time */
			/*
            svr_ses.plugin_handle = dlopen(svr_opts.pubkey_plugin, RTLD_NOW);
            if (svr_ses.plugin_handle == NULL) {
                dropbear_exit("failed to load external pubkey plugin '%s': %s", svr_opts.pubkey_plugin, dlerror());
            }
            pluginConstructor = (PubkeyExtPlugin_newFn)dlsym(svr_ses.plugin_handle, DROPBEAR_PUBKEY_PLUGIN_FNNAME_NEW);
            if (!pluginConstructor) {
                dropbear_exit("plugin constructor method not found in external pubkey plugin");
            }
			*/
            //pluginConstructor = (PubkeyExtPlugin_newFn)struct EPKAInstance;

            /*
			struct MyPlugin *fileauth;
			fileauth = (struct MyPlugin *) malloc(sizeof(struct MyPlugin));
            */

            //pluginConstructor = my2_plugin_new;

            /* Create an instance of the plugin */
            //svr_ses.plugin_instance = pluginConstructor(verbose, svr_opts.pubkey_plugin_options, svr_ses.addrstring);
            svr_ses.plugin_instance = my2_plugin_new(verbose, svr_opts.pubkey_plugin_options, svr_ses.addrstring);
            if (svr_ses.plugin_instance == NULL) {
                dropbear_exit("external plugin initialization failed");
            }
            /* Check if the plugin is compatible */
            if ( (svr_ses.plugin_instance->api_version[0] != DROPBEAR_PLUGIN_VERSION_MAJOR) ||
                 (svr_ses.plugin_instance->api_version[1] < DROPBEAR_PLUGIN_VERSION_MINOR) ) {
                dropbear_exit("plugin version check failed: "
                              "Dropbear=%d.%d, plugin=%d.%d",
                        DROPBEAR_PLUGIN_VERSION_MAJOR, DROPBEAR_PLUGIN_VERSION_MINOR,
                        svr_ses.plugin_instance->api_version[0], svr_ses.plugin_instance->api_version[1]);
            }
            if (svr_ses.plugin_instance->api_version[1] > DROPBEAR_PLUGIN_VERSION_MINOR) {
                dropbear_log(LOG_WARNING, "plugin API newer than dropbear API: "
                              "Dropbear=%d.%d, plugin=%d.%d",
                        DROPBEAR_PLUGIN_VERSION_MAJOR, DROPBEAR_PLUGIN_VERSION_MINOR,
                        svr_ses.plugin_instance->api_version[0], svr_ses.plugin_instance->api_version[1]);
            }
            dropbear_log(LOG_INFO, "successfully loaded and initialized pubkey plugin '%s'", svr_opts.pubkey_plugin);
        }
#endif

	svr_authinitialise();
	chaninitialise(svr_chantypes);
	svr_chansessinitialise();
	svr_algos_initialise();

	get_socket_address(ses.sock_in, NULL, NULL,
			&svr_ses.remotehost, NULL, 1);

	/* set up messages etc */
	ses.remoteclosed = svr_remoteclosed;
	ses.extra_session_cleanup = svr_session_cleanup;

	/* packet handlers */
	ses.packettypes = svr_packettypes;

	ses.isserver = 1;

	/* We're ready to go now */
	ses.init_done = 1;

	/* exchange identification, version etc */
	send_session_identification();

	kexfirstinitialise(); /* initialise the kex state */

	/* start off with key exchange */
	send_msg_kexinit();

#if DROPBEAR_FUZZ
    if (fuzz.fuzzing) {
        fuzz_svr_hook_preloop();
    }
#endif

	/* Run the main for-loop. */
	session_loop(svr_chansess_checksignal);

	/* Not reached */

}

/* cleanup and exit - format must be <= 100 chars */
void svr_dropbear_exit(int exitcode, const char* format, va_list param) {
	char exitmsg[150];
	char fullmsg[300];
	char fromaddr[60];
	int i;
	int add_delay = 0;

#if DROPBEAR_PLUGIN
	if ((ses.plugin_session != NULL)) {
		svr_ses.plugin_instance->delete_session(ses.plugin_session);
	}
	ses.plugin_session = NULL;
	svr_opts.pubkey_plugin_options = NULL;
	m_free(svr_opts.pubkey_plugin);
#endif

	/* Render the formatted exit message */
	vsnprintf(exitmsg, sizeof(exitmsg), format, param);

	/* svr_ses.addrstring may not be set for some early exits, or for
	the listener process */
	fromaddr[0] = '\0';
	if (svr_ses.addrstring) {
	    snprintf(fromaddr, sizeof(fromaddr), " from <%s>", svr_ses.addrstring);
    }

	/* Add the prefix depending on session/auth state */
	if (!ses.init_done) {
		/* before session init */
		snprintf(fullmsg, sizeof(fullmsg), "Early exit%s: %s", fromaddr, exitmsg);
	} else if (ses.authstate.authdone) {
		/* user has authenticated */
		snprintf(fullmsg, sizeof(fullmsg),
				"Exit (%s)%s: %s",
				ses.authstate.pw_name, fromaddr, exitmsg);
	} else if (ses.authstate.pw_name) {
		/* we have a potential user */
		snprintf(fullmsg, sizeof(fullmsg),
				"Exit before auth%s: (user '%s', %u fails): %s",
				fromaddr, ses.authstate.pw_name, ses.authstate.failcount, exitmsg);
		add_delay = 1;
	} else {
		/* before userauth */
		snprintf(fullmsg, sizeof(fullmsg), "Exit before auth%s: %s", fromaddr, exitmsg);
		add_delay = 1;
	}

	dropbear_log(LOG_INFO, "%s", fullmsg);

	/* To make it harder for attackers, introduce a delay to keep an
	 * unauthenticated session open a bit longer, thus blocking a connection
	 * slot until after the delay. Without this, while there is a limit on
	 * the amount of attempts an attacker can make at the same time
	 * (MAX_UNAUTH_PER_IP), the time taken by dropbear to handle one attempt
	 * is still short and thus for each of the allowed parallel attempts
	 * many attempts can be chained one after the other. The attempt rate is
	 * then:
	 *     "MAX_UNAUTH_PER_IP / <process time of one attempt>".
	 * With the delay, this rate becomes:
	 *     "MAX_UNAUTH_PER_IP / UNAUTH_CLOSE_DELAY".
	 */
	if ((add_delay != 0) && (UNAUTH_CLOSE_DELAY > 0)) {
		TRACE(("svr_dropbear_exit: start delay of %d seconds", UNAUTH_CLOSE_DELAY));
		sleep(UNAUTH_CLOSE_DELAY);
		TRACE(("svr_dropbear_exit: end delay of %d seconds", UNAUTH_CLOSE_DELAY));
	}

#if DROPBEAR_VFORK
	/* For uclinux only the main server process should cleanup - we don't want
	 * forked children doing that */
	if (svr_ses.server_pid == getpid())
#endif
	{
		/* must be after we've done with username etc */
		session_cleanup();
	}

#if DROPBEAR_FUZZ
	/* longjmp before cleaning up svr_opts */
    if (fuzz.do_jmp) {
        longjmp(fuzz.jmp, 1);
    }
#endif

	if (svr_opts.hostkey) {
		sign_key_free(svr_opts.hostkey);
		svr_opts.hostkey = NULL;
	}
	for (i = 0; i < DROPBEAR_MAX_PORTS; i++) {
		m_free(svr_opts.addresses[i]);
		m_free(svr_opts.ports[i]);
	}


	exit(exitcode);

}

/* priority is priority as with syslog() */
void svr_dropbear_log(int priority, const char* format, va_list param) {

	char printbuf[1024];
	char datestr[20];
	time_t timesec;
	int havetrace = 0;

	vsnprintf(printbuf, sizeof(printbuf), format, param);

#ifndef DISABLE_SYSLOG
	if (opts.usingsyslog) {
		syslog(priority, "%s", printbuf);
	}
#endif

	/* if we are using DEBUG_TRACE, we want to print to stderr even if
	 * syslog is used, so it is included in error reports */
#if DEBUG_TRACE
	havetrace = debug_trace;
#endif

	if (!opts.usingsyslog || havetrace) {
		struct tm * local_tm = NULL;
		timesec = time(NULL);
		local_tm = localtime(&timesec);
		if (local_tm == NULL
			|| strftime(datestr, sizeof(datestr), "%b %d %H:%M:%S",
						local_tm) == 0)
		{
			/* upon failure, just print the epoch-seconds time. */
			snprintf(datestr, sizeof(datestr), "%d", (int)timesec);
		}
		fprintf(stderr, "[%d] %s %s\n", getpid(), datestr, printbuf);
	}
}

/* called when the remote side closes the connection */
static void svr_remoteclosed() {

	m_close(ses.sock_in);
	if (ses.sock_in != ses.sock_out) {
		m_close(ses.sock_out);
	}
	ses.sock_in = -1;
	ses.sock_out = -1;
	dropbear_close("Exited normally");

}

static void svr_algos_initialise(void) {
	algo_type *algo;
	for (algo = sshkex; algo->name; algo++) {
#if DROPBEAR_DH_GROUP1 && DROPBEAR_DH_GROUP1_CLIENTONLY
		if (strcmp(algo->name, "diffie-hellman-group1-sha1") == 0) {
			algo->usable = 0;
		}
#endif
#if DROPBEAR_EXT_INFO
		if (strcmp(algo->name, SSH_EXT_INFO_C) == 0) {
			algo->usable = 0;
		}
#endif
	}
}

