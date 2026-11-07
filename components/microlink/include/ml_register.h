/**
 * @file ml_register.h
 * @brief RegisterRequest encoder and RegisterResponse classifier
 *
 * Pure C on top of cJSON: no ESP-IDF, FreeRTOS or socket dependency, so the
 * host harness (tools/host-register-probe) compiles and runs the exact code
 * the firmware uses to build and read /machine/register messages.
 *
 * Wire types: tailscale.com/tailcfg RegisterRequest / RegisterResponse
 * (SDK v1.104.0, tailcfg/tailcfg.go:1318-1386). The decision order in
 * ml_register_parse_response() follows control/controlclient/direct.go:854-889.
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inputs of one RegisterRequest. Pointers are borrowed, never retained. */
typedef struct {
    uint32_t capability_version;        /* RegisterRequest.Version */
    const uint8_t *node_pub;            /* NodeKey, 32 bytes, required */
    const uint8_t *old_node_pub;        /* OldNodeKey, 32 bytes; NULL omits the field */
    const char *auth_key;               /* Auth.AuthKey; NULL or "" omits Auth */
    const char *followup;               /* Followup (the AuthURL being waited on); NULL or "" omits */
    const char *hostname;               /* Hostinfo.Hostname */
    int preferred_derp;                 /* Hostinfo.NetInfo.PreferredDERP */
    const char *challenge_response;     /* NodeKeyChallengeResponse ("chalresp:<hex>"); NULL omits */
} ml_register_req_t;

/**
 * Build the RegisterRequest JSON body.
 * @return NUL-terminated string allocated through cJSON's allocator (release
 *         with free()), or NULL on allocation failure or missing required input.
 */
char *ml_register_build_request(const ml_register_req_t *req);

/* Classification of one RegisterResponse. */
typedef enum {
    ML_REG_OK = 0,            /* no Error, no AuthURL, key valid: registered */
    ML_REG_AUTH_URL,          /* login pending: result.auth_url is set */
    ML_REG_NODE_KEY_EXPIRED,  /* NodeKeyExpired: the node key must be replaced */
    ML_REG_REJECTED,          /* Error non-empty: the server refused */
    ML_REG_TAILNET_LOCK,      /* NodeKeySignature present: tailnet lock, unsupported */
    ML_REG_EMPTY,             /* no response body */
    ML_REG_MALFORMED,         /* body is not a JSON object */
} ml_register_kind_t;

typedef struct {
    ml_register_kind_t kind;
    char *auth_url;           /* ML_REG_AUTH_URL only; heap string, owned by the result */
    bool node_key_expired;    /* RegisterResponse.NodeKeyExpired as sent */
    bool machine_authorized;  /* RegisterResponse.MachineAuthorized as sent; informational:
                               * machine approval is read from the netmap (DESIGN section 7.3) */
    bool error_present;       /* Error was non-empty (text is deliberately not kept) */
} ml_register_result_t;

/**
 * Classify a RegisterResponse body.
 *
 * Decision order (direct.go): Error, NodeKeySignature, NodeKeyExpired,
 * AuthURL, otherwise OK. An empty or non-JSON body is never OK.
 * A leading binary prefix of up to 8 bytes before '{' is skipped, as the
 * baseline did.
 */
ml_register_kind_t ml_register_parse_response(const uint8_t *body, size_t len,
                                              ml_register_result_t *out);

/** Wipe and free everything the result owns (the AuthURL is a login capability). */
void ml_register_result_clear(ml_register_result_t *r);

/** Wipe a buffer that held a response or request, then free it. */
void ml_register_secure_free(void *p, size_t len);

#ifdef __cplusplus
}
#endif
