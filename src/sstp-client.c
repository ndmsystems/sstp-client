/*!
 * @brief This is the sstp-client code
 *
 * @file sstp-client.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>


#include "sstp-private.h"
#include "sstp-client.h"

/*! OpenSSL cipher suites
 * 
 * https://wiki.mozilla.org/Security/Server_Side_TLS
 * Intermediate compatibility (default), as SSTP appeared only in WinSrv2k8
 */

static const char* const sstp_client_ssl_ciphers =
    "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305" \
    ":ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256" \
    ":ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384" \
    ":DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384" \
    ":ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA" \
    ":ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384" \
    ":ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256" \
    ":DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA" \
    ":ECDHE-ECDSA-DES-CBC3-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA" \
    ":AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256" \
    ":AES128-SHA:AES256-SHA:DES-CBC3-SHA" \
    ":!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4:!DSS";

/*! Global context for the sstp-client */
static sstp_client_st client;

/*
 * precomputed DH value, as generation on CPE may take several hours
 * use ffdhe2048 as of RFC7919 https://tools.ietf.org/html/rfc7919#appendix-A.1
 * https://wiki.mozilla.org/Security/Server_Side_TLS#Pre-defined_DHE_groups
 */
static DH *sstp_ssl_get_dh()
{
    static const unsigned char dh2048_p[] =
    {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xAD,0xF8,0x54,0x58,
        0xA2,0xBB,0x4A,0x9A,0xAF,0xDC,0x56,0x20,0x27,0x3D,0x3C,0xF1,
        0xD8,0xB9,0xC5,0x83,0xCE,0x2D,0x36,0x95,0xA9,0xE1,0x36,0x41,
        0x14,0x64,0x33,0xFB,0xCC,0x93,0x9D,0xCE,0x24,0x9B,0x3E,0xF9,
        0x7D,0x2F,0xE3,0x63,0x63,0x0C,0x75,0xD8,0xF6,0x81,0xB2,0x02,
        0xAE,0xC4,0x61,0x7A,0xD3,0xDF,0x1E,0xD5,0xD5,0xFD,0x65,0x61,
        0x24,0x33,0xF5,0x1F,0x5F,0x06,0x6E,0xD0,0x85,0x63,0x65,0x55,
        0x3D,0xED,0x1A,0xF3,0xB5,0x57,0x13,0x5E,0x7F,0x57,0xC9,0x35,
        0x98,0x4F,0x0C,0x70,0xE0,0xE6,0x8B,0x77,0xE2,0xA6,0x89,0xDA,
        0xF3,0xEF,0xE8,0x72,0x1D,0xF1,0x58,0xA1,0x36,0xAD,0xE7,0x35,
        0x30,0xAC,0xCA,0x4F,0x48,0x3A,0x79,0x7A,0xBC,0x0A,0xB1,0x82,
        0xB3,0x24,0xFB,0x61,0xD1,0x08,0xA9,0x4B,0xB2,0xC8,0xE3,0xFB,
        0xB9,0x6A,0xDA,0xB7,0x60,0xD7,0xF4,0x68,0x1D,0x4F,0x42,0xA3,
        0xDE,0x39,0x4D,0xF4,0xAE,0x56,0xED,0xE7,0x63,0x72,0xBB,0x19,
        0x0B,0x07,0xA7,0xC8,0xEE,0x0A,0x6D,0x70,0x9E,0x02,0xFC,0xE1,
        0xCD,0xF7,0xE2,0xEC,0xC0,0x34,0x04,0xCD,0x28,0x34,0x2F,0x61,
        0x91,0x72,0xFE,0x9C,0xE9,0x85,0x83,0xFF,0x8E,0x4F,0x12,0x32,
        0xEE,0xF2,0x81,0x83,0xC3,0xFE,0x3B,0x1B,0x4C,0x6F,0xAD,0x73,
        0x3B,0xB5,0xFC,0xBC,0x2E,0xC2,0x20,0x05,0xC5,0x8E,0xF1,0x83,
        0x7D,0x16,0x83,0xB2,0xC6,0xF3,0x4A,0x26,0xC1,0xB2,0xEF,0xFA,
        0x88,0x6B,0x42,0x38,0x61,0x28,0x5C,0x97,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,
    };
    static const unsigned char dh2048_q[] =
    {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xD6,0xFC,0x2A,0x2C,
        0x51,0x5D,0xA5,0x4D,0x57,0xEE,0x2B,0x10,0x13,0x9E,0x9E,0x78,
        0xEC,0x5C,0xE2,0xC1,0xE7,0x16,0x9B,0x4A,0xD4,0xF0,0x9B,0x20,
        0x8A,0x32,0x19,0xFD,0xE6,0x49,0xCE,0xE7,0x12,0x4D,0x9F,0x7C,
        0xBE,0x97,0xF1,0xB1,0xB1,0x86,0x3A,0xEC,0x7B,0x40,0xD9,0x01,
        0x57,0x62,0x30,0xBD,0x69,0xEF,0x8F,0x6A,0xEA,0xFE,0xB2,0xB0,
        0x92,0x19,0xFA,0x8F,0xAF,0x83,0x37,0x68,0x42,0xB1,0xB2,0xAA,
        0x9E,0xF6,0x8D,0x79,0xDA,0xAB,0x89,0xAF,0x3F,0xAB,0xE4,0x9A,
        0xCC,0x27,0x86,0x38,0x70,0x73,0x45,0xBB,0xF1,0x53,0x44,0xED,
        0x79,0xF7,0xF4,0x39,0x0E,0xF8,0xAC,0x50,0x9B,0x56,0xF3,0x9A,
        0x98,0x56,0x65,0x27,0xA4,0x1D,0x3C,0xBD,0x5E,0x05,0x58,0xC1,
        0x59,0x92,0x7D,0xB0,0xE8,0x84,0x54,0xA5,0xD9,0x64,0x71,0xFD,
        0xDC,0xB5,0x6D,0x5B,0xB0,0x6B,0xFA,0x34,0x0E,0xA7,0xA1,0x51,
        0xEF,0x1C,0xA6,0xFA,0x57,0x2B,0x76,0xF3,0xB1,0xB9,0x5D,0x8C,
        0x85,0x83,0xD3,0xE4,0x77,0x05,0x36,0xB8,0x4F,0x01,0x7E,0x70,
        0xE6,0xFB,0xF1,0x76,0x60,0x1A,0x02,0x66,0x94,0x1A,0x17,0xB0,
        0xC8,0xB9,0x7F,0x4E,0x74,0xC2,0xC1,0xFF,0xC7,0x27,0x89,0x19,
        0x77,0x79,0x40,0xC1,0xE1,0xFF,0x1D,0x8D,0xA6,0x37,0xD6,0xB9,
        0x9D,0xDA,0xFE,0x5E,0x17,0x61,0x10,0x02,0xE2,0xC7,0x78,0xC1,
        0xBE,0x8B,0x41,0xD9,0x63,0x79,0xA5,0x13,0x60,0xD9,0x77,0xFD,
        0x44,0x35,0xA1,0x1C,0x30,0x94,0x2E,0x4B,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,
    };
    static const unsigned char dh2048_g[] = { 0x02 };
    DH *dh = DH_new();

    if( dh == NULL )
    {
        return NULL;
    }

    BIGNUM *const dh_p = BN_bin2bn(dh2048_p, sizeof(dh2048_p), NULL);
    BIGNUM *const dh_q = BN_bin2bn(dh2048_q, sizeof(dh2048_q), NULL);
    BIGNUM *const dh_g = BN_bin2bn(dh2048_g, sizeof(dh2048_g), NULL);

    if( (dh_p == NULL) || (dh_q == NULL) || (dh_g == NULL) ||
        !DH_set0_pqg(dh, dh_p, dh_q, dh_g) )
    {
        DH_free(dh);

        return NULL;
    }

    return dh;
}

typedef void (*sstp_client_cb)(sstp_stream_st*, sstp_buff_st*, sstp_client_st*, status_t);

/*!
 * @brief Called when proxy is connected
 */
static void sstp_client_proxy_connected(sstp_stream_st *stream, sstp_buff_st *buf,
        sstp_client_st *client, status_t status);


static void sstp_client_event_cb(sstp_client_st *client, int ret)
{
    uint8_t *skey;
    uint8_t *rkey;
    size_t   slen;
    size_t   rlen;

    /* Check the result of the event */
    if (SSTP_OKAY != ret)
    {
        sstp_die("Failed to receive ip-up notify callback", -1);
    }

    /* Get the result */
    ret = sstp_event_mppe_result(client->event, &skey, &slen, &rkey, &rlen);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Failed to obtain the MPPE keys", -1);
    }

    /* Set the MPPE keys */
    sstp_state_mppe_keys(client->state, skey, slen, rkey, rlen);

    /* Tell the state machine to connect */
    ret = sstp_state_accept(client->state);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Negotiation with server failed", -1);
    }
}


static void sstp_client_pppd_cb(sstp_client_st *client, sstp_pppd_event_t ev)
{
    int ret = (-1);

    switch (ev)
    {
    case SSTP_PPP_DOWN:
        log_err("PPPd terminated");
        //sstp_state_disconnect(client->state);
        event_base_loopbreak(client->ev_base);
        break;

    case SSTP_PPP_UP:

        /* Tell the state machine to connect */
        ret = sstp_state_accept(client->state);
        if (SSTP_FAIL == ret)
        {
            sstp_die("Negotiation with server failed", -1);
        }
        break;

    case SSTP_PPP_AUTH:
    {
        uint8_t skey[16];
        uint8_t rkey[16];

        /* Get the MPPE keys */
        ret = sstp_chap_mppe_get(sstp_pppd_getchap(client->pppd), 
                client->option.password, skey, rkey, 0); 
        if (SSTP_FAIL == ret)
        {
            return;
        }

        /* Set the keys */
        sstp_state_mppe_keys(client->state, skey, 16, rkey, 16);
        break;
    }

    default:
        
        break;
    }

    return;
}


/*!
 * @brief Called when the state machine transitions
 */
static void sstp_client_state_cb(sstp_client_st *client, sstp_state_t event)
{
    int ret = 0;

    switch (event)
    {
    case SSTP_CALL_CONNECT:

        /* Create the PPP context */
        ret = sstp_pppd_create(&client->pppd, client->ev_base, client->stream, 
                (sstp_pppd_fn) sstp_client_pppd_cb, client);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not initialize PPP daemon", -1);
        }

        /* Start the pppd daemon */
        ret = sstp_pppd_start(client->pppd, &client->option, 
                sstp_event_sockname(client->event));
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not start PPP daemon", -1);
        }

        /* Set the forwarder function */
        sstp_state_set_forward(client->state, (sstp_state_forward_fn) 
                sstp_pppd_send, client->pppd);

        log_info("Started PPP Link Negotiation");
        break;
    
    case SSTP_CALL_ESTABLISHED:

        log_info("Connection Established");
        
        /* Enter the privilege separation directory */
        if (getuid() == 0)
        {
            ret = sstp_sandbox(client->option.priv_dir, 
                    client->option.priv_user, 
                    client->option.priv_group);
            if (ret != 0) 
            {
                log_warn("Could not enter privilege directory");
            }
        }

        break;

    case SSTP_CALL_ABORT:
    default:

	if (client->pppd) 
        {
	    sstp_pppd_stop(client->pppd);
        }
        sstp_die("Connection was aborted, %s", -1, 
                sstp_state_reason(client->state));
        break;
    }
}


/*! 
 * @brief Called upon HTTP handshake complete w/result
 */
static void sstp_client_http_done(sstp_client_st *client, int status)
{
    int opts = SSTP_VERIFY_NONE;

    if (SSTP_OKAY != status)
    {
        sstp_die("HTTP handshake with server failed", -1);
    }

    /* Free the handshake data */
    sstp_http_free(client->http);
    client->http = NULL;

    /* Set verify options */
    opts = SSTP_VERIFY_NAME;
    if (client->option.ca_cert ||
        client->option.ca_path)
    {
        opts = SSTP_VERIFY_CERT;
    }

    /* Verify the server certificate */
    status = sstp_verify_cert(client->stream,
        ((client->option.host != NULL) ?
            client->option.host :
            client->option.server), opts);
    if (SSTP_OKAY != status)
    {
        if (!(SSTP_OPT_CERTWARN & client->option.enable))
            sstp_die("Verification of server certificate failed", -2);
        
        log_warn("Server certificate verification failed, ignoring");
    }

    /* Now we need to start the state-machine */
    status = sstp_state_create(&client->state, client->stream, (sstp_state_change_fn)
            sstp_client_state_cb, client, SSTP_MODE_CLIENT);
    if (SSTP_OKAY != status)
    {
        sstp_die("Could not create state machine", -1);
    }

    /* Kick off the state machine */
    status = sstp_state_start(client->state);
    if (SSTP_FAIL == status)
    {
        sstp_die("Could not start the state machine", -1);
    }
}


/*!
 * @brief Called upon connect complete w/result
 */
static void sstp_client_connected(sstp_stream_st *stream, sstp_buff_st *buf, 
        sstp_client_st *client, status_t status)
{
    int ret  = 0;

    if (SSTP_CONNECTED != status)
    {
        sstp_die("Could not complete connect to the client", -1);
    }

    /* Success! */
    if (client->option.host == NULL)
    {
        log_info("Connected to %s", client->host.name);

    } else
    {
        log_info("Connected to %s (host: %s)",
            client->host.name,
            client->option.host);
    }

    /* Create the HTTP handshake context */
    ret = sstp_http_create(&client->http, client->host.name,
            ((client->option.host != NULL) ?
                 client->option.host :
                 client->host.name), (sstp_http_done_fn) 
            sstp_client_http_done, client, SSTP_MODE_CLIENT);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not configure HTTP handshake with server", -1);
    }

    /* Set the uuid of the connection if provided */
    if (client->option.uuid)
    {
        sstp_http_setuuid(client->http, client->option.uuid);
    }

    /* Perform the HTTP handshake with server */
    ret = sstp_http_handshake(client->http, client->stream);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Could not perform HTTP handshake with server", -1);
    }

    return;
}


/*!
 * @brief Called on completion of the proxy request
 */
static void sstp_client_proxy_done(sstp_client_st *client, int status)
{
    int ret = 0;

    switch (status)
    {
    /* Proxy asked us to authenticate */
    case SSTP_AUTHENTICATE:
        
        /* Close the connection, re-connect and use the credentials */
        sstp_stream_destroy(client->stream);

        /* Create the SSL I/O streams */
        if (SSTP_OPT_TLSEXT & client->option.enable)
        {
            log_info("TLS hostname extension is enabled");
            ret = sstp_stream_create(&client->stream, client->ev_base,
                    client->ssl_ctx,
                    ((client->option.host != NULL) ?
                      client->option.host :
                      client->host.name));
        }
        else
        {
            log_info("TLS hostname extension is disabled");
            ret = sstp_stream_create(&client->stream, client->ev_base,
                    client->ssl_ctx, NULL);
        }
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not create I/O stream", -1);
        }

        /* Proxy asked us to authenticate, but we have no password */
        if (!client->url->password || !client->url->password)
        {
            sstp_die("Proxy asked for credentials, none provided", -1);
        }

        /* Update with username and password */
        sstp_http_setcreds(client->http, client->url->user,
                client->url->password);

        /* Reconnect to the proxy (now with credentials set) */
        ret = sstp_stream_connect(client->stream, &client->host.addr, client->host.alen,
                (sstp_complete_fn) sstp_client_proxy_connected, client, 10);
        break;

    case SSTP_OKAY:

        log_info("Connected to %s via proxy server", 
                client->option.server);

        /* Re-initialize the HTTP context */
        sstp_http_free(client->http);

        /* Create the HTTP handshake context */
        ret = sstp_http_create(&client->http, client->option.server,
                ((client->option.host != NULL) ?
                    client->option.host :
                    client->host.name), (sstp_http_done_fn) 
                sstp_client_http_done, client, SSTP_MODE_CLIENT);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not configure HTTP handshake with server", -1);
        }
        
        /* Perform the HTTPS/SSTP handshake */
        ret = sstp_http_handshake(client->http, client->stream);
        if (SSTP_FAIL == ret)
        {
            sstp_die("Could not perform HTTP handshake with server", -1);
        }

        break;

    default:

        sstp_die("Could not connect to proxy server", -1);
        break;
    }

    return;
}


/*!
 * @brief Called when connection to the proxy server is completed
 */
static void sstp_client_proxy_connected(sstp_stream_st *stream, sstp_buff_st *buf,
        sstp_client_st *client, status_t status)
{
    int ret = 0;

    if (SSTP_CONNECTED != status)
    {
        sstp_die("Could not connect to proxy server", -1);
    }

    /* Create the HTTP object if one doesn't already exist */
    if (!client->http) 
    {
        ret = sstp_http_create(&client->http, client->option.server,
            ((client->option.host != NULL) ?
                 client->option.host :
                 client->host.name),
            (sstp_http_done_fn) sstp_client_proxy_done, client, SSTP_MODE_CLIENT);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not configure HTTP handshake with server", -1);
        }
    }

    /* Perform the HTTP handshake with server */
    ret = sstp_http_proxy(client->http, client->stream);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Could not perform HTTP handshake with server", -1);
    }

    return;
}


/*!
 * @brief Connect to the server
 */
static status_t sstp_client_connect(sstp_client_st *client, 
        struct sockaddr *addr, int alen)
{
    sstp_client_cb complete_cb = (client->option.proxy)
            ? sstp_client_proxy_connected
            : sstp_client_connected;
    status_t ret = SSTP_FAIL;

    /* Create the I/O streams */
    if (SSTP_OPT_TLSEXT & client->option.enable)
    {
        log_info("TLS hostname extension is enabled");
        ret = sstp_stream_create(&client->stream, client->ev_base, client->ssl_ctx,
                    ((client->option.host != NULL) ?
                      client->option.host :
                      client->host.name));
    }
    else
    {
        log_info("TLS hostname extension is disabled");
        ret = sstp_stream_create(&client->stream, client->ev_base, client->ssl_ctx, NULL);
    }

    if (SSTP_OKAY != ret)
    {
        log_err("Could not setup SSL streams");
        goto done;
    }

    /* Have the stream connect */
    ret = sstp_stream_connect(client->stream, addr, alen, (sstp_complete_fn) complete_cb, client, 10);
    if (SSTP_INPROG != ret && 
        SSTP_OKAY   != ret)
    {
        log_err("Could not connect to the server, %s (%d)", 
            strerror(errno), errno);
        goto done;
    }

    /* Success! */
    ret = SSTP_OKAY;

done:

    return ret;
}


/*!
 * @brief Perform the global SSL initializers
 */
static status_t sstp_init_ssl(sstp_client_st *client, sstp_option_st *opt)
{
    int retval = SSTP_FAIL;
    int status = 0;
    DH* dh = NULL;

    /* Initialize the OpenSSL library */
    status = SSL_library_init();
    if (status != 1)
    {
        log_err("Could not initialize SSL");
        goto done;
    }

    /* Load all error strings */
    SSL_load_error_strings();

    /* Create a new crypto context */
    client->ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (client->ssl_ctx == NULL)
    {
        log_err("Could not get SSL crypto context");
        goto done;
    }

    /* Configure the crypto options, eliminate SSLv2, SSLv3 */
    status = SSL_CTX_set_options(
        client->ssl_ctx,
        SSL_OP_ALL |
            SSL_OP_NO_SSLv2 |
            SSL_OP_NO_SSLv3);
    if (status == -1)
    {
        log_err("Could not set SSL options");
        goto done;
    }

#ifdef SSL_OP_NO_COMPRESSION
    /* disable to mitigate CRIME attack */
    status = SSL_CTX_set_options(client->ssl_ctx, SSL_OP_NO_COMPRESSION);
    if (status == -1)
    {
        log_err("Could not set SSL options");
        goto done;
    }
#endif

#ifdef SSL_MODE_RELEASE_BUFFERS
    /* reduce idle connection memory usage */
    status = SSL_CTX_set_mode(client->ssl_ctx, SSL_MODE_RELEASE_BUFFERS);
    if (status == -1)
    {
        log_err("Could not set SSL options");
        goto done;
    }
#endif

    /* disable DH parameters generation for each request */
    status = SSL_CTX_clear_options(client->ssl_ctx, SSL_OP_SINGLE_DH_USE);
    if (status == -1)
    {
        log_err("Could not set SSL options");
        goto done;
    }

    dh = sstp_ssl_get_dh();

    if (dh == NULL)
    {
        log_err("Could not get SSL DH parameters");
        goto done;
    }

    if (SSL_CTX_set_tmp_dh(client->ssl_ctx, dh) <= 0)
    {
        DH_free(dh);
        log_err("Could not set SSL DH parameters");
        goto done;
    }

    DH_free(dh);

#if OPENSSL_VERSION_NUMBER >= 0x0090800fL
#ifndef OPENSSL_NO_ECDH
    status = SSL_CTX_clear_options(client->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
    if (status == -1)
    {
        log_err("Could not set SSL options");
        goto done;
    }
#endif
#endif

    status = SSL_CTX_set_cipher_list(
        client->ssl_ctx,
        sstp_client_ssl_ciphers);
    if (status != 1)
    {
        log_err("Could not set SSL ciphersuites");
        goto done;
    }

    /* Configure the CA-Certificate or Directory */
    if (opt->ca_cert || opt->ca_path)
    {
        /* Look for certificates in the default certificate path */
        status = SSL_CTX_load_verify_locations(client->ssl_ctx, 
                opt->ca_cert, opt->ca_path);
        if (status != 1)
        {
            log_err("Could not set default verify location");
            goto done;
        }
    }

    /* OBS: In case of longer certificate chains than 1 */
    SSL_CTX_set_verify_depth(client->ssl_ctx, 9);

    /*! Success */
    retval = SSTP_OKAY;

done:
    
    return (retval);
}


/*!
 * @brief Lookup the server name
 */
static status_t sstp_client_lookup(sstp_url_st *uri, sstp_peer_st *peer)
{
    char ipaddr[INET6_ADDRSTRLEN];
    status_t status    = SSTP_FAIL;
    const char *service= NULL;
    addrinfo_st *list  = NULL;
    addrinfo_st hints  = 
    {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = 0,
        .ai_flags    = AI_PASSIVE | AI_CANONNAME,
    };
    int ret;

    /* Get the service string */
    service = (uri->port) 
        ? uri->port
        : uri->schema;

    /* Resolve the server address */
    ret = getaddrinfo(uri->host, service, &hints, &list);
    if (ret != 0 || !list)
    {
        log_err("Could not resolve host: %s, %s (%d)",
                uri->host, gai_strerror(ret), ret);
        goto done;
    }

    /* Save the results for later */
    strncpy(peer->name, (list->ai_canonname) ? : uri->host, sizeof(peer->name));
    memcpy(&peer->addr, list->ai_addr, sizeof(peer->addr));
    peer->alen = list->ai_addrlen;

    log_info("Resolved %s to %s", peer->name, 
        sstp_ipaddr(&peer->addr, ipaddr, sizeof(ipaddr)))

    /* Success! */
    status = SSTP_OKAY;

done:
    
    if (list)
    {
        freeaddrinfo(list);
    }

    return status;
}


/*!
 * @brief Initialize the sstp-client 
 */
static status_t sstp_client_init(sstp_client_st *client, sstp_option_st *opts)
{
    int retval = SSTP_FAIL;
    int status = 0;

    /* Initialize the event library */
    client->ev_base = event_base_new();
    if (!client->ev_base)
    {
        log_err("Could not initialize event base");
        goto done;
    }

    /* Initialize the SSL context, cert store, etc */
    status = sstp_init_ssl(client, opts);
    if (SSTP_OKAY != status)
    {
        log_err("Could not initialize secure socket layer");
        goto done;
    }
    
    /* Keep a copy of the options */
    memcpy(&client->option, opts, sizeof(client->option));

    /* Success! */
    retval = SSTP_OKAY;

done:
    
    return retval;
}


/*!
 * @brief Free any associated resources with the client
 */
static void sstp_client_free(sstp_client_st *client)
{
    /* Destory the HTTPS stream */
    if (client->stream)
    {
        sstp_stream_destroy(client->stream);
        client->stream = NULL;
    }

    /* Shutdown the SSL context */
    if (client->ssl_ctx)
    {
        SSL_CTX_free(client->ssl_ctx);
        client->ssl_ctx = NULL;
    }

    /* Close the PPPD layer */
    if (client->pppd)
    {
        sstp_pppd_free(client->pppd);
        client->pppd = NULL;
    }

    /* Close the IPC */
    if (client->event)
    {
        sstp_event_free(client->event);
        client->event = NULL;
    }

    /* Free the route context */
    if (client->route_ctx)
    {
        sstp_route_done(client->route_ctx);
        client->route_ctx = NULL;
    }

    /* Free the options */
    sstp_option_free(&client->option);

    /* Free the event base */
    event_base_free(client->ev_base);
}


void sstp_signal_cb(int signal)
{
    log_err("Terminating on %s (%d)", 
            strsignal(signal), signal);

    event_base_loopbreak(client.ev_base);
}


status_t sstp_signal_init(void)
{
    status_t status = SSTP_FAIL;
    struct sigaction act;
    int ret = -1;

    memset(&act, 0, sizeof(act));
    sigemptyset(&act.sa_mask);
    act.sa_handler = sstp_signal_cb;

    /* Handle Ctrl+C on keyboard */
    ret = sigaction(SIGINT, &act, NULL);
    if (ret)
    {   
        goto done;
    }

    ret = sigaction(SIGHUP, &act, NULL);
    if (ret)
    {   
        goto done;
    }

    /* Handle program termination */
    ret = sigaction(SIGTERM, &act, NULL);
    if (ret)
    {
        goto done;
    }

    /* Success */
    status = SSTP_OKAY;

done:
    
    return status;
}


/*!
 * @brief The main application entry-point
 */
int main(int argc, char *argv[])
{
    sstp_option_st option;
    int ret = 0;

    /* Reset the memory */
    memset(&client, 0, sizeof(client));

    /* Perform initialization */
    ret = sstp_log_init_argv(&argc, argv);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize logging", -1);
    }

    /* Setup signal handling */
    ret = sstp_signal_init();
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize signal handling", -1);
    }
   
    /* Parse the arguments */
    ret = sstp_parse_argv(&option, argc, argv);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not parse input arguments", -1);
    }

    /* Check if we can access the runtime directory */
    if (access(SSTP_RUNTIME_DIR, F_OK))
    {
        ret = sstp_create_dir(SSTP_RUNTIME_DIR, option.priv_user, 
                option.priv_group, 0755);
        if (ret != 0)
        {
            log_warn("Could not access or create runtime directory");
        }
    }

    /* Create the privilege separation directory */
    if (option.priv_dir && access(option.priv_dir, F_OK))
    {
        ret = sstp_create_dir(option.priv_dir, option.priv_user,
                option.priv_group, 0700);
        if (ret != 0)
        {
            log_warn("Could not access or create privilege separation directory, %s",
                    option.priv_dir);
        }
    }

#ifndef HAVE_PPP_PLUGIN
    /* In non-plugin mode, username and password must be specified */
    if (!option.password || !option.user)
    {
        sstp_die("The username and password must be specified", -1);
    }
#endif /* #ifndef HAVE_PPP_PLUGIN */

    /* Initialize the client */
    ret = sstp_client_init(&client, &option);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not initialize the client", -1);
    }

    /* Create the event notification callback */
    if (!(option.enable & SSTP_OPT_NOPLUGIN))
    {
        ret = sstp_event_create(&client.event, &client.option, client.ev_base,
            (sstp_event_fn) sstp_client_event_cb, &client);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not setup notification", -1);
        }
    }

    /* Connect to the proxy first */
    if (option.proxy)
    {
        /* Parse the Proxy URL */
        ret = sstp_url_parse(&client.url, option.proxy);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not parse the proxy URL", -1);
        }
    }
    else
    {
        ret = sstp_url_parse(&client.url, option.server);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not parse the server URL", -1);
        }
    }

    /* Lookup the URL of the proxy server */
    ret = sstp_client_lookup(client.url, &client.host);
    if (SSTP_OKAY != ret)
    {
        sstp_die("Could not lookup host: `%s'", -1, client.url->host);
    }

    /* Connect to the server */
    ret = sstp_client_connect(&client, &client.host.addr, 
            client.host.alen);
    if (SSTP_FAIL == ret)
    {
        sstp_die("Could not connect to `%s'", -1, client.host.name);
    }

    /* Add a server route if we are asked to */
    if (option.enable & SSTP_OPT_SAVEROUTE)
    {
        ret = sstp_route_init(&client.route_ctx);
        if (SSTP_OKAY != ret)
        {
            sstp_die("Could not initialize route module", -1);
        }

        ret = sstp_route_get(client.route_ctx, &client.host.addr,
                &client.route);
        if (ret != 0)
        {
            sstp_die("Could not get server route", -1);
        }

        ret = sstp_route_replace(client.route_ctx, &client.route);
        if (ret != 0)
        {
          sstp_die("Could not replace server route", -1);
        }
    }
    
    /* Wait for the connect to finish and then continue */
    ret = event_base_dispatch(client.ev_base);
    if (ret != 0)
    {
        sstp_die("The event loop terminated unsuccessfully", -1);
    }

    /* Record the session info for the curious peer */
    if (client.pppd)
    {
        sstp_session_st detail;
        char buf1[32];
        char buf2[32];

        /* Try to signal stop first */
        sstp_pppd_stop(client.pppd);

        sstp_pppd_session_details(client.pppd, &detail);
        log_info("SSTP session was established for %s",
                sstp_norm_time(detail.established, buf1, sizeof(buf1)));
        log_info("Received %s, sent %s", 
                sstp_norm_data(detail.rx_bytes, buf1, sizeof(buf1)),
                sstp_norm_data(detail.tx_bytes, buf2, sizeof(buf2)));
    }

    /* Remove the server route */
    if (option.enable & SSTP_OPT_SAVEROUTE)
    {
        ret = sstp_route_delete(client.route_ctx, &client.route);
        if (SSTP_OKAY != ret)
        {
            log_warn("Could not remove the server route");
        }
    }

    /* Release allocated resources */
    sstp_client_free(&client);
    return EXIT_SUCCESS;
}
