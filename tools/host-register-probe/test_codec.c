/**
 * Unit tests for the register codec (ml_register.c) and the login getters
 * (ml_login.c). Both files are compiled unchanged from components/microlink.
 *
 * The response bodies below are fabricated placeholders: no real URL, key or
 * login name appears in this file.
 */

#include "microlink_internal.h"
#include "ml_register.h"
#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failed, g_total;

#define CHECK(cond)                                                          \
    do {                                                                     \
        g_total++;                                                           \
        if (!(cond)) {                                                       \
            g_failed++;                                                      \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

static ml_register_kind_t parse(const char *s, ml_register_result_t *r) {
    return ml_register_parse_response((const uint8_t *)s, s ? strlen(s) : 0, r);
}

/* ---- request builder ------------------------------------------------------ */

static void test_build_request(void) {
    uint8_t node[32], old[32];
    memset(node, 0xAB, sizeof(node));
    memset(old, 0xCD, sizeof(old));

    ml_register_req_t req = {
        .capability_version = 131, .node_pub = node, .hostname = "dev-1", .preferred_derp = 7,
    };
    char *json = ml_register_build_request(&req);
    CHECK(json != NULL);
    cJSON *o = cJSON_Parse(json);
    CHECK(o != NULL);
    CHECK(cJSON_GetObjectItem(o, "Version")->valueint == 131);
    const cJSON *nk = cJSON_GetObjectItem(o, "NodeKey");
    CHECK(cJSON_IsString(nk) && !strcmp(nk->valuestring,
          "nodekey:abababababababababababababababababababababababababababababababab"));
    CHECK(!cJSON_HasObjectItem(o, "OldNodeKey"));
    CHECK(!cJSON_HasObjectItem(o, "Auth"));        /* keyless: interactive login */
    CHECK(!cJSON_HasObjectItem(o, "Followup"));
    CHECK(!cJSON_HasObjectItem(o, "NodeKeyChallengeResponse"));
    const cJSON *hi = cJSON_GetObjectItem(o, "Hostinfo");
    CHECK(!strcmp(cJSON_GetObjectItem(hi, "Hostname")->valuestring, "dev-1"));
    CHECK(!strcmp(cJSON_GetObjectItem(hi, "OS")->valuestring, "linux"));
    CHECK(cJSON_GetObjectItem(cJSON_GetObjectItem(hi, "NetInfo"), "PreferredDERP")->valueint == 7);
    cJSON_Delete(o);
    free(json);

    /* An empty auth key is the same as none. */
    req.auth_key = "";
    json = ml_register_build_request(&req);
    o = cJSON_Parse(json);
    CHECK(!cJSON_HasObjectItem(o, "Auth"));
    cJSON_Delete(o);
    free(json);

    /* The auth-key path keeps its wire shape: Auth.AuthKey. */
    req.auth_key = "tskey-test-placeholder";
    json = ml_register_build_request(&req);
    o = cJSON_Parse(json);
    CHECK(!strcmp(cJSON_GetObjectItem(cJSON_GetObjectItem(o, "Auth"), "AuthKey")->valuestring,
                  "tskey-test-placeholder"));
    cJSON_Delete(o);
    free(json);

    /* Followup, OldNodeKey and the challenge response. */
    req.auth_key = NULL;
    req.followup = "https://example.invalid/a/placeholder";
    req.old_node_pub = old;
    req.challenge_response = "chalresp:00";
    json = ml_register_build_request(&req);
    o = cJSON_Parse(json);
    CHECK(!strcmp(cJSON_GetObjectItem(o, "Followup")->valuestring, "https://example.invalid/a/placeholder"));
    CHECK(!strncmp(cJSON_GetObjectItem(o, "OldNodeKey")->valuestring, "nodekey:cdcd", 12));
    CHECK(!strcmp(cJSON_GetObjectItem(o, "NodeKeyChallengeResponse")->valuestring, "chalresp:00"));
    cJSON_Delete(o);
    free(json);

    req.node_pub = NULL;
    CHECK(ml_register_build_request(&req) == NULL);
}

/* ---- response classifier -------------------------------------------------- */

static void test_parse_response(void) {
    ml_register_result_t r;

    CHECK(parse(NULL, &r) == ML_REG_EMPTY);
    CHECK(parse("", &r) == ML_REG_EMPTY);
    CHECK(parse("not json at all", &r) == ML_REG_MALFORMED);
    CHECK(parse("[1,2,3]", &r) == ML_REG_MALFORMED);          /* array, no '{' within the scan */
    CHECK(parse("{\"AuthURL\":\"https://exa", &r) == ML_REG_MALFORMED);   /* truncated */

    CHECK(parse("{}", &r) == ML_REG_OK);
    CHECK(parse("{\"MachineAuthorized\":true}", &r) == ML_REG_OK);
    CHECK(r.machine_authorized);
    CHECK(parse("{\"MachineAuthorized\":false}", &r) == ML_REG_OK);
    CHECK(!r.machine_authorized);

    CHECK(parse("{\"AuthURL\":\"https://example.invalid/a/placeholder\"}", &r) == ML_REG_AUTH_URL);
    CHECK(r.auth_url && !strcmp(r.auth_url, "https://example.invalid/a/placeholder"));
    ml_register_result_clear(&r);
    CHECK(r.auth_url == NULL && r.kind == ML_REG_OK);

    CHECK(parse("{\"AuthURL\":\"\"}", &r) == ML_REG_OK);      /* empty URL is no URL */
    CHECK(r.auth_url == NULL);

    /* Decision order of direct.go:854-889. */
    CHECK(parse("{\"Error\":\"denied\",\"AuthURL\":\"https://example.invalid/a/x\"}", &r) == ML_REG_REJECTED);
    CHECK(r.auth_url == NULL && r.error_present);
    CHECK(parse("{\"Error\":\"\"}", &r) == ML_REG_OK);        /* empty Error is no error */
    CHECK(!r.error_present);
    CHECK(parse("{\"NodeKeySignature\":\"c2ln\",\"NodeKeyExpired\":true}", &r) == ML_REG_TAILNET_LOCK);
    CHECK(parse("{\"NodeKeyExpired\":true,\"AuthURL\":\"https://example.invalid/a/x\"}", &r) == ML_REG_NODE_KEY_EXPIRED);
    CHECK(r.node_key_expired && r.auth_url == NULL);

    /* Binary prefix of up to 8 bytes before '{' (baseline tolerance). */
    uint8_t prefixed[] = {0x00, 0x01, 0x02, '{', '}', 0};
    CHECK(ml_register_parse_response(prefixed, 5, &r) == ML_REG_OK);
    uint8_t far_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, '{', '}', 0};
    CHECK(ml_register_parse_response(far_prefix, 11, &r) == ML_REG_MALFORMED);

    /* Unknown fields are ignored. */
    CHECK(parse("{\"Login\":{\"LoginName\":\"someone\"},\"User\":{},\"NodeKeyExpired\":false}", &r) == ML_REG_OK);
}

/* ---- login getters -------------------------------------------------------- */

static microlink_t *new_ml(const char *device_name) {
    microlink_t *ml = calloc(1, sizeof(*ml));
    portMUX_INITIALIZE(&ml->id_lock);
    ml->config.device_name = device_name;
    return ml;
}

static void test_auth_url_getter(void) {
    microlink_t *ml = new_ml("dev-1");
    const char *url = "https://example.invalid/a/placeholder";   /* 37 chars */
    char buf[64];

    CHECK(microlink_copy_auth_url(ml, buf, sizeof(buf)) == ESP_ERR_NOT_FOUND);
    CHECK(microlink_get_auth_url_length(ml) == 0);

    ml_set_auth_url(ml, url);
    size_t n = strlen(url);
    CHECK(microlink_get_auth_url_length(ml) == n);
    CHECK(microlink_copy_auth_url(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, url));

    char exact[38];
    memset(exact, 'Z', sizeof(exact));
    CHECK(microlink_copy_auth_url(ml, exact, n + 1) == ESP_OK && !strcmp(exact, url));

    /* One byte short: error, and the buffer is not written (never truncates). */
    char shortb[37];
    memset(shortb, 'Z', sizeof(shortb));
    CHECK(microlink_copy_auth_url(ml, shortb, n) == ESP_ERR_INVALID_SIZE);
    CHECK(shortb[0] == 'Z' && shortb[n - 1] == 'Z');
    CHECK(microlink_copy_auth_url(ml, buf, 0) == ESP_ERR_INVALID_ARG);
    CHECK(microlink_copy_auth_url(ml, NULL, 8) == ESP_ERR_INVALID_ARG);
    CHECK(microlink_copy_auth_url(NULL, buf, sizeof(buf)) == ESP_ERR_INVALID_ARG);

    ml_set_auth_url(ml, "https://example.invalid/a/other");      /* replacement */
    CHECK(microlink_copy_auth_url(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, "https://example.invalid/a/other"));
    ml_set_auth_url(ml, NULL);
    CHECK(microlink_copy_auth_url(ml, buf, sizeof(buf)) == ESP_ERR_NOT_FOUND);
    ml_set_auth_url(ml, "");
    CHECK(microlink_get_auth_url_length(ml) == 0);
    free(ml);
}

static void test_self_name(void) {
    microlink_t *ml = new_ml("dev-1");
    char buf[ML_DNS_NAME_MAX + 1];

    CHECK(microlink_copy_self_fqdn(ml, buf, sizeof(buf)) == ESP_ERR_NOT_FOUND);
    CHECK(microlink_copy_magicdns_suffix(ml, buf, sizeof(buf)) == ESP_ERR_NOT_FOUND);

    ml_set_self_fqdn(ml, "dev-1.tail1234.ts.net.");              /* Node.Name ends with a dot */
    CHECK(microlink_copy_self_fqdn(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, "dev-1.tail1234.ts.net"));
    CHECK(microlink_copy_magicdns_suffix(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, "tail1234.ts.net"));

    char tiny[8];
    CHECK(microlink_copy_self_fqdn(ml, tiny, sizeof(tiny)) == ESP_ERR_INVALID_SIZE);
    CHECK(microlink_copy_magicdns_suffix(ml, tiny, sizeof(tiny)) == ESP_ERR_INVALID_SIZE);

    /* Invalid input keeps the previous name. */
    ml_set_self_fqdn(ml, "");
    ml_set_self_fqdn(ml, ".");
    ml_set_self_fqdn(ml, NULL);
    char longname[ML_DNS_NAME_MAX + 8];
    memset(longname, 'a', sizeof(longname) - 1);
    longname[sizeof(longname) - 1] = '\0';
    ml_set_self_fqdn(ml, longname);
    CHECK(microlink_copy_self_fqdn(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, "dev-1.tail1234.ts.net"));

    /* A name without a dot is its own suffix, as in the SDK. */
    ml_set_self_fqdn(ml, "solo");
    CHECK(microlink_copy_magicdns_suffix(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, "solo"));
    free(ml);
}

static void test_device_name_and_error(void) {
    char buf[32];
    microlink_t *ml = new_ml("dev-1");
    CHECK(microlink_copy_device_name(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, "dev-1"));
    CHECK(microlink_copy_device_name(ml, buf, 5) == ESP_ERR_INVALID_SIZE);   /* needs 6 */
    CHECK(microlink_copy_device_name(ml, buf, 6) == ESP_OK);
    free(ml);

    ml = new_ml(NULL);                                           /* falls back to the default name */
    CHECK(microlink_copy_device_name(ml, buf, sizeof(buf)) == ESP_OK && !strcmp(buf, microlink_default_device_name()));
    CHECK(microlink_get_error(ml) == ML_ERR_NONE);
    ml->last_error = ML_ERR_KEY_ROTATED;
    CHECK(microlink_get_error(ml) == ML_ERR_KEY_ROTATED);
    CHECK(microlink_get_error(NULL) == ML_ERR_NONE);
    free(ml);
}

int main(void) {
    test_build_request();
    test_parse_response();
    test_auth_url_getter();
    test_self_name();
    test_device_name_and_error();
    printf("%d checks, %d failed\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
