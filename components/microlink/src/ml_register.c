/**
 * @file ml_register.c
 * @brief RegisterRequest encoder and RegisterResponse classifier
 *
 * No ESP-IDF dependency (see ml_register.h). Nothing here logs: the caller
 * reports states and sizes only, because the response can carry an AuthURL
 * and a login name.
 */

#include "ml_register.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Existing baseline behaviour: tolerate a short binary prefix before the JSON. */
#define REG_JSON_PREFIX_SCAN 8

static void key_to_str(const char *prefix, const uint8_t key[32], char *out, size_t out_size) {
    static const char hextab[] = "0123456789abcdef";
    size_t n = strlen(prefix);
    if (out_size < n + 65) {
        if (out_size) out[0] = '\0';
        return;
    }
    memcpy(out, prefix, n);
    for (int i = 0; i < 32; i++) {
        out[n + i * 2] = hextab[key[i] >> 4];
        out[n + i * 2 + 1] = hextab[key[i] & 0x0F];
    }
    out[n + 64] = '\0';
}

char *ml_register_build_request(const ml_register_req_t *req) {
    if (!req || !req->node_pub || !req->hostname) return NULL;

    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddNumberToObject(root, "Version", req->capability_version);

    char key_str[80];
    key_to_str("nodekey:", req->node_pub, key_str, sizeof(key_str));
    cJSON_AddStringToObject(root, "NodeKey", key_str);

    if (req->old_node_pub) {
        key_to_str("nodekey:", req->old_node_pub, key_str, sizeof(key_str));
        cJSON_AddStringToObject(root, "OldNodeKey", key_str);
    }

    if (req->auth_key && req->auth_key[0]) {
        cJSON *auth = cJSON_CreateObject();
        if (auth) {
            cJSON_AddStringToObject(auth, "AuthKey", req->auth_key);
            cJSON_AddItemToObject(root, "Auth", auth);
        }
    }

    if (req->followup && req->followup[0]) {
        cJSON_AddStringToObject(root, "Followup", req->followup);
    }

    cJSON *hostinfo = cJSON_CreateObject();
    if (hostinfo) {
        cJSON_AddStringToObject(hostinfo, "Hostname", req->hostname);
        cJSON_AddStringToObject(hostinfo, "OS", "linux");
        cJSON_AddStringToObject(hostinfo, "OSVersion", "ESP-IDF");
        cJSON_AddStringToObject(hostinfo, "GoArch", "arm");

        /* The control plane reads Hostinfo.NetInfo.PreferredDERP to fill
         * Node.HomeDERP for the other peers. */
        cJSON *netinfo = cJSON_CreateObject();
        if (netinfo) {
            cJSON_AddNumberToObject(netinfo, "PreferredDERP", req->preferred_derp);
            cJSON_AddItemToObject(hostinfo, "NetInfo", netinfo);
        }
        cJSON_AddItemToObject(root, "Hostinfo", hostinfo);
    }

    if (req->challenge_response && req->challenge_response[0]) {
        cJSON_AddStringToObject(root, "NodeKeyChallengeResponse", req->challenge_response);
    }

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

static bool string_nonempty(const cJSON *item) {
    return cJSON_IsString(item) && item->valuestring && item->valuestring[0];
}

ml_register_kind_t ml_register_parse_response(const uint8_t *body, size_t len,
                                              ml_register_result_t *out) {
    if (!out) return ML_REG_MALFORMED;
    memset(out, 0, sizeof(*out));

    if (!body || len == 0) {
        out->kind = ML_REG_EMPTY;
        return out->kind;
    }

    size_t start = 0;
    bool found = false;
    for (size_t i = 0; i < REG_JSON_PREFIX_SCAN && i < len; i++) {
        if (body[i] == '{') {
            start = i;
            found = true;
            break;
        }
    }
    if (!found) {
        out->kind = ML_REG_MALFORMED;
        return out->kind;
    }

    cJSON *resp = cJSON_ParseWithLength((const char *)body + start, len - start);
    if (!resp || !cJSON_IsObject(resp)) {
        if (resp) cJSON_Delete(resp);
        out->kind = ML_REG_MALFORMED;
        return out->kind;
    }

    out->node_key_expired = cJSON_IsTrue(cJSON_GetObjectItem(resp, "NodeKeyExpired"));
    out->machine_authorized = cJSON_IsTrue(cJSON_GetObjectItem(resp, "MachineAuthorized"));
    out->error_present = string_nonempty(cJSON_GetObjectItem(resp, "Error"));

    /* Order of direct.go:854-889: Error ignores every other field. */
    if (out->error_present) {
        out->kind = ML_REG_REJECTED;
    } else if (string_nonempty(cJSON_GetObjectItem(resp, "NodeKeySignature"))) {
        out->kind = ML_REG_TAILNET_LOCK;
    } else if (out->node_key_expired) {
        out->kind = ML_REG_NODE_KEY_EXPIRED;
    } else {
        const cJSON *url = cJSON_GetObjectItem(resp, "AuthURL");
        if (string_nonempty(url)) {
            size_t n = strlen(url->valuestring);
            out->auth_url = malloc(n + 1);
            if (!out->auth_url) {
                cJSON_Delete(resp);
                out->kind = ML_REG_MALFORMED;
                return out->kind;
            }
            memcpy(out->auth_url, url->valuestring, n + 1);
            out->kind = ML_REG_AUTH_URL;
        } else {
            out->kind = ML_REG_OK;
        }
    }

    cJSON_Delete(resp);
    return out->kind;
}

void ml_register_secure_free(void *p, size_t len) {
    if (!p) return;
    volatile uint8_t *v = (volatile uint8_t *)p;
    for (size_t i = 0; i < len; i++) v[i] = 0;
    free(p);
}

void ml_register_result_clear(ml_register_result_t *r) {
    if (!r) return;
    if (r->auth_url) ml_register_secure_free(r->auth_url, strlen(r->auth_url));
    memset(r, 0, sizeof(*r));
}
