/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "ogs-dbi.h"
#include "ogs-crypt.h"
#include "hss-auc.h"
#include "hss-context.h"

static hss_context_t self;
static ogs_diam_config_t g_diam_conf;

int __hss_log_domain;

static int context_initialized = 0;

hss_context_t* hss_self(void)
{
    return &self;
}

void hss_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initial FreeDiameter Config */
    memset(&g_diam_conf, 0, sizeof(ogs_diam_config_t));

    /* Initialize HSS context */
    memset(&self, 0, sizeof(hss_context_t));
    self.diam_config = &g_diam_conf;

    ogs_log_install_domain(&__ogs_diam_domain, "diam", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_dbi_domain, "dbi", ogs_core()->log.level);
    ogs_log_install_domain(&__hss_log_domain, "hss", ogs_core()->log.level);

    ogs_thread_mutex_init(&self.db_lock);

    context_initialized = 1;
}

void hss_context_final(void)
{
    ogs_assert(context_initialized == 1);

    ogs_thread_mutex_destroy(&self.db_lock);

    context_initialized = 0;
}

static int hss_context_prepare(void)
{
    self.diam_config->cnf_port = DIAMETER_PORT;
    self.diam_config->cnf_port_tls = DIAMETER_SECURE_PORT;

    return OGS_OK;
}

static int hss_context_validation(void)
{
    if (self.diam_conf_path == NULL &&
        (self.diam_config->cnf_diamid == NULL ||
        self.diam_config->cnf_diamrlm == NULL ||
        self.diam_config->cnf_addr == NULL)) {
        ogs_error("No hss.freeDiameter in '%s'", ogs_config()->file);
        return OGS_ERROR;
    }

    return OGS_OK;
}

int hss_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_config()->document;
    ogs_assert(document);

    rv = hss_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "hss")) {
            ogs_yaml_iter_t hss_iter;
            ogs_yaml_iter_recurse(&root_iter, &hss_iter);
            while (ogs_yaml_iter_next(&hss_iter)) {
                const char *hss_key = ogs_yaml_iter_key(&hss_iter);
                ogs_assert(hss_key);
                if (!strcmp(hss_key, "freeDiameter")) {
                    yaml_node_t *node = 
                        yaml_document_get_node(document, hss_iter.pair->value);
                    ogs_assert(node);
                    if (node->type == YAML_SCALAR_NODE) {
                        self.diam_conf_path = ogs_yaml_iter_value(&hss_iter);
                    } else if (node->type == YAML_MAPPING_NODE) {
                        ogs_yaml_iter_t fd_iter;
                        ogs_yaml_iter_recurse(&hss_iter, &fd_iter);

                        while (ogs_yaml_iter_next(&fd_iter)) {
                            const char *fd_key = ogs_yaml_iter_key(&fd_iter);
                            ogs_assert(fd_key);
                            if (!strcmp(fd_key, "identity")) {
                                self.diam_config->cnf_diamid = 
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "realm")) {
                                self.diam_config->cnf_diamrlm = 
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_port = atoi(v);
                            } else if (!strcmp(fd_key, "sec_port")) {
                                const char *v = ogs_yaml_iter_value(&fd_iter);
                                if (v) self.diam_config->cnf_port_tls = atoi(v);
                            } else if (!strcmp(fd_key, "listen_on")) {
                                self.diam_config->cnf_addr = 
                                    ogs_yaml_iter_value(&fd_iter);
                            } else if (!strcmp(fd_key, "load_extension")) {
                                ogs_yaml_iter_t ext_array, ext_iter;
                                ogs_yaml_iter_recurse(&fd_iter, &ext_array);
                                do {
                                    const char *module = NULL;
                                    const char *conf = NULL;

                                    if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_MAPPING_NODE) {
                                        memcpy(&ext_iter, &ext_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&ext_array))
                                            break;
                                        ogs_yaml_iter_recurse(
                                                &ext_array, &ext_iter);
                                    } else if (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&ext_iter)) {
                                        const char *ext_key =
                                            ogs_yaml_iter_key(&ext_iter);
                                        ogs_assert(ext_key);
                                        if (!strcmp(ext_key, "module")) {
                                            module = ogs_yaml_iter_value(
                                                    &ext_iter);
                                        } else if (!strcmp(ext_key, "conf")) {
                                            conf = ogs_yaml_iter_value(
                                                    &ext_iter);
                                        } else
                                            ogs_warn("unknown key `%s`",
                                                    ext_key);
                                    }

                                    if (module) {
                                        self.diam_config->
                                            ext[self.diam_config->num_of_ext].
                                                module = module;
                                        self.diam_config->
                                            ext[self.diam_config->num_of_ext].
                                                conf = conf;
                                        self.diam_config->num_of_ext++;
                                    }
                                } while (ogs_yaml_iter_type(&ext_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(fd_key, "connect")) {
                                ogs_yaml_iter_t conn_array, conn_iter;
                                ogs_yaml_iter_recurse(&fd_iter, &conn_array);
                                do {
                                    const char *identity = NULL;
                                    const char *addr = NULL;
                                    uint16_t port = 0;

                                    if (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_MAPPING_NODE) {
                                        memcpy(&conn_iter, &conn_array,
                                                sizeof(ogs_yaml_iter_t));
                                    } else if (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&conn_array))
                                            break;
                                        ogs_yaml_iter_recurse(&conn_array, &conn_iter);
                                    } else if (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_SCALAR_NODE) {
                                        break;
                                    } else
                                        ogs_assert_if_reached();

                                    while (ogs_yaml_iter_next(&conn_iter)) {
                                        const char *conn_key =
                                            ogs_yaml_iter_key(&conn_iter);
                                        ogs_assert(conn_key);
                                        if (!strcmp(conn_key, "identity")) {
                                            identity = ogs_yaml_iter_value(
                                                    &conn_iter);
                                        } else if (!strcmp(conn_key, "addr")) {
                                            addr = ogs_yaml_iter_value(&conn_iter);
                                        } else if (!strcmp(conn_key, "port")) {
                                            const char *v =
                                                ogs_yaml_iter_value(&conn_iter);
                                            if (v) port = atoi(v);
                                        } else
                                            ogs_warn("unknown key `%s`", conn_key);
                                    }

                                    if (identity && addr) {
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                identity = identity;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                addr = addr;
                                        self.diam_config->
                                            conn[self.diam_config->num_of_conn].
                                                port = port;
                                        self.diam_config->num_of_conn++;
                                    }
                                } while (ogs_yaml_iter_type(&conn_array) ==
                                        YAML_SEQUENCE_NODE);
                            } else
                                ogs_warn("unknown key `%s`", fd_key);
                        }
                    }
                } else
                    ogs_warn("unknown key `%s`", hss_key);
            }
        }
    }

    rv = hss_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

int hss_db_init()
{
    int rv;

    rv = ogs_mongoc_init(ogs_config()->db_uri);
    if (rv != OGS_OK) return rv;

    if (ogs_mongoc()->client && ogs_mongoc()->name) {
        self.subscriberCollection = mongoc_client_get_collection(
            ogs_mongoc()->client, ogs_mongoc()->name, "subscribers");
        ogs_assert(self.subscriberCollection);
    }

    return OGS_OK;
}

int hss_db_final()
{
    if (self.subscriberCollection) {
        mongoc_collection_destroy(self.subscriberCollection);
    }

    ogs_mongoc_final();

    return OGS_OK;
}

int hss_db_fetch_sawtooth_authentication_vectors(char *imsi_bcd, hss_blockchain_auth_vector_t *blockchain_auth_info) {
    ogs_debug("    [BYPASS] Fetching the Authentication Vectors submitted to the blockchain");
    int rv = OGS_OK;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    bson_t *pop = NULL;
    bson_error_t error;
    const bson_t *document;
    bson_iter_t iter;
    bson_iter_t inner_iter;
    bson_iter_t child;
    uint32_t av_count;
    const uint8_t *av;
    char buf[HSS_KEY_LEN];
    char kasmebuf[OGS_SHA256_DIGEST_SIZE];
    char *utf8 = NULL;
    uint32_t length = 0;

    ogs_assert(imsi_bcd);
    ogs_assert(blockchain_auth_info);

    ogs_thread_mutex_lock(&self.db_lock);

    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
#if MONGOC_MAJOR_VERSION >= 1 && MONGOC_MINOR_VERSION >= 5
    cursor = mongoc_collection_find_with_opts(
            self.subscriberCollection, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(self.subscriberCollection,
                                    MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        ogs_warn("Cannot find IMSI in DB : %s", imsi_bcd);

        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("Cursor Failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }

    if (!bson_iter_init_find(&iter, document, "security")) {
        ogs_error("No 'security' field in this document");

        rv = OGS_ERROR;
        goto out;
    }

    // authvectors are a part of the security parameters.
    memset(blockchain_auth_info, 0, sizeof(hss_blockchain_auth_vector_t));
    bson_iter_recurse(&iter, &inner_iter);

    while (bson_iter_next(&inner_iter)) {
        const char *key = bson_iter_key(&inner_iter);
        // Replace the authentication_info objects based on the quadruples of information that's read from here as
        // a new key entry into the security object of each IMSI collection.
        if (!strcmp(key, "authvectors") && BSON_ITER_HOLDS_ARRAY(&inner_iter)) {
            bson_iter_array(&inner_iter, &av_count, &av);
            ogs_debug("Count AV_Count : [%d]", av_count);
            if (av_count <= 0) {
                ogs_debug("    Could not find any auth vectors in the field. Failing and falling back gracefully.");
            } else {
                ogs_debug("    Time to perform the required actions and create the auth vector from the data");
                bson_t * temporary_vectors = bson_new_from_data(av, av_count);
                ogs_debug("    Parsing the response into the corresponding auth vector structures");
                bson_iter_t tIter;
                bson_iter_t tInnerIter;
                bson_iter_init(&tIter, temporary_vectors);
                // Get only one item
                bson_iter_find(&tIter, "0");
                // This is a document structure.
                bson_iter_recurse(&tIter, &tInnerIter);
                while (bson_iter_next(&tInnerIter)) {
                    const char *key = bson_iter_key(&tInnerIter);
                    ogs_debug("         [InnerObject] Found the key : [%s]" , key);
                    if (!strcmp(key, "rand")) {
                        // TODO: Process and read this content clearly from the database.
                        utf8 = (char *) bson_iter_utf8(&tInnerIter, &length);
                        ogs_debug("Assigning RAND : [%s]", utf8);
                        memcpy(blockchain_auth_info->rand, OGS_HEX(utf8, length, buf), OGS_RAND_LEN);
                    } else if (!strcmp(key, "xres")) {
                        utf8 = (char*) bson_iter_utf8(&tInnerIter, &length);
                        ogs_debug("Assigning XRES : [%s] [%d]", utf8, length);
                        blockchain_auth_info->xres_len = 8; // TODO: Figure this out later if it breaks.
                        memcpy(blockchain_auth_info->xres, OGS_HEX(utf8, length, buf), 8);
                    } else if (!strcmp(key, "autn")) {
                        utf8 = (char*) bson_iter_utf8(&tInnerIter, &length);
                        ogs_debug("Assigning AUTN: [%s]", utf8);
                        memcpy(blockchain_auth_info->autn, OGS_HEX(utf8, length, buf), OGS_AUTN_LEN);
                    } else if (!strcmp(key, "kasme")) {
                        utf8 = (char*) bson_iter_utf8(&tInnerIter, &length);
                        ogs_debug("Assigning Kasme : [%s]", utf8);
                        memcpy(blockchain_auth_info->kasme, OGS_HEX(utf8, length, kasmebuf), OGS_SHA256_DIGEST_SIZE);
                    } else if (!strcmp(key, "sqn")) {
                        blockchain_auth_info->sqn = bson_iter_int64(&tInnerIter);
                        ogs_debug("Assigning SQN to [%lx] : ", blockchain_auth_info->sqn);
                    }
                    else if (!strcmp(key, "ak")) {
                        utf8 = (char*) bson_iter_utf8(&tInnerIter, &length);
                        memcpy(blockchain_auth_info->ak, OGS_HEX(utf8, length, buf), HSS_AK_LEN);
                        ogs_debug("Assigning AK to [%s]", utf8);
                    }
                    else if (!strcmp(key, "ck")) {
                        utf8 = (char*) bson_iter_utf8(&tInnerIter, &length);
                        memcpy(blockchain_auth_info->ck, OGS_HEX(utf8, length, buf), HSS_KEY_LEN);
                        ogs_debug("Assigning CK to [%s]", utf8);
                    }
                    else if (!strcmp(key, "ik")) {
                        utf8 = (char*) bson_iter_utf8(&tInnerIter, &length);
                        memcpy(blockchain_auth_info->ik, OGS_HEX(utf8, length, buf), HSS_KEY_LEN);
                        ogs_debug("Assigning IK to [%s]", utf8);
                    }
                }
            }
        }
    }

    // Remove the accessed item from the database using $pop -1 on the security.authvectors for the given IMSI.
    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
    pop = BCON_NEW("$pop",
                    "{",
                        "security.authvectors", BCON_INT64(-1),
                    "}");

    ogs_debug("    [DB UPDATE] Removing a used auth vector from IMSI [%s]", imsi_bcd);

    if (!mongoc_collection_update(self.subscriberCollection,
                                  MONGOC_UPDATE_UPSERT, query, pop, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);
        rv = OGS_ERROR;
    }

out:
    if (query) bson_destroy(query);
    if (cursor) mongoc_cursor_destroy(cursor);

    ogs_thread_mutex_unlock(&self.db_lock);

    return rv;
}

int hss_db_write_additional_vectors(char *imsi_bcd, hss_db_auth_info_t *auth_info, uint8_t *opc, struct avp_hdr *hdr,
                                    hss_blockchain_auth_vector_t *blockchain_auth_info) {

    // TODO: Do this with different RAND values to change the corresponding XRES value.

    ogs_debug("    [Home HSS] Generating additional authentication vectors");
    int rv = OGS_OK;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    bson_t *push = NULL;
    bson_error_t error;
    const bson_t *document;

    // Temporary parameters being overwritten
    uint8_t sqn[HSS_SQN_LEN];
    uint8_t autn[OGS_AUTN_LEN];
    uint8_t ik[HSS_KEY_LEN];
    uint8_t ck[HSS_KEY_LEN];
    uint8_t ak[HSS_AK_LEN];
    uint8_t xres[OGS_MAX_RES_LEN];
    uint8_t kasme[OGS_SHA256_DIGEST_SIZE];
    size_t xres_len = 8;
    // End of Temporary parameters that are being used.

    ogs_thread_mutex_lock(&self.db_lock);

    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
#if MONGOC_MAJOR_VERSION >= 1 && MONGOC_MINOR_VERSION >= 5
    cursor = mongoc_collection_find_with_opts(
            self.subscriberCollection, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(self.subscriberCollection,
                                    MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        ogs_warn("Cannot find IMSI in DB : %s", imsi_bcd);

        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("Cursor Failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }

    uint64_t temp_sqn;
    temp_sqn = auth_info->sqn;

    int i=1;
    for (; i<10; i++) {
        temp_sqn+=32;
        ogs_uint64_to_buffer(temp_sqn, HSS_SQN_LEN, sqn);
        milenage_generate(opc, auth_info->amf, auth_info->k, sqn, auth_info->rand, autn, ik, ck, ak, xres, &xres_len);
        hss_auc_kasme(ck, ik, hdr->avp_value->os.data, sqn, ak, kasme);

        if (i == 1) {
            memcpy(blockchain_auth_info->autn, autn, OGS_AUTN_LEN);
            memcpy(blockchain_auth_info->rand, auth_info->rand, OGS_RAND_LEN);
            blockchain_auth_info->sqn = temp_sqn;
            blockchain_auth_info->xres_len = xres_len;
            memcpy(blockchain_auth_info->xres, xres, xres_len);
            memcpy(blockchain_auth_info->kasme, kasme, OGS_SHA256_DIGEST_SIZE);
            blockchain_auth_info->use_db = 1;
        }

        ogs_debug("===================[START AUTH VECTORS]===================");
        char printable_autn[128];
        ogs_assert(autn);
        ogs_hex_to_ascii(autn, OGS_AUTN_LEN, printable_autn, sizeof(printable_autn));
        ogs_debug("  AUTN : [%s]", printable_autn);

        char printable_sqn[128];
        ogs_assert(sqn);
        ogs_hex_to_ascii(sqn, HSS_SQN_LEN, printable_sqn, sizeof(printable_sqn));
        ogs_debug("  SQN  : [%s]", printable_sqn);

        char printable_xres[128];
        ogs_assert(xres);
        ogs_hex_to_ascii(xres, xres_len, printable_xres, sizeof(printable_xres));
        ogs_debug("  XRES : [%s]", printable_xres);

        char printable_rand[128];
        ogs_assert(rand);
        ogs_hex_to_ascii(rand, OGS_RAND_LEN, printable_rand, sizeof(printable_rand));
        ogs_debug("  RAND : [%s]", printable_rand);

        char printable_kasme[128];
        ogs_assert(kasme);
        ogs_hex_to_ascii(kasme, OGS_SHA256_DIGEST_SIZE, printable_kasme, sizeof(printable_kasme));
        ogs_debug("  Kasme: [%s]", printable_kasme);

        char printable_ck[128];
        ogs_assert(ck);
        ogs_hex_to_ascii(ck, HSS_KEY_LEN, printable_ck, sizeof(printable_ck));
        ogs_debug("  CK : [%s]", printable_ck);

        char printable_ik[128];
        ogs_assert(ik);
        ogs_hex_to_ascii(ik, HSS_KEY_LEN, printable_ik, sizeof(printable_ik));
        ogs_debug("  IK : [%s]", printable_ik);

        char printable_ak[128];
        ogs_assert(ak);
        ogs_hex_to_ascii(ak, HSS_AK_LEN, printable_ak, sizeof(printable_ak));
        ogs_debug("   AK : [%s]", printable_ak);
        ogs_debug("===================[END   AUTH VECTORS]===================");

        // Need to write this data to the mongo db instance.

        query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
        push = BCON_NEW("$push",
                          "{",
                              "security.authvectors",
                              "{",
                                  "rand", printable_rand,
                                  "sqn", BCON_INT64(temp_sqn),
                                  "xres", printable_xres,
                                  "kasme", printable_kasme,
                                  "autn", printable_autn,
                                  "ck", printable_ck,
                                  "ak", printable_ak,
                                  "ik", printable_ik,
                              "}",
                          "}");

        ogs_debug("    [DB UPDATE] Adding new auth vectors to IMSI [%s]", imsi_bcd);

        if (!mongoc_collection_update(self.subscriberCollection,
                                      MONGOC_UPDATE_UPSERT, query, push, NULL, &error)) {
            ogs_error("mongoc_collection_update() failure: %s", error.message);

            rv = OGS_ERROR;
        }
    }

    ogs_debug("    [Home HSS] Finished generating additional authentication vectors");

out:
    if (query) bson_destroy(query);
    if (push) bson_destroy(push);
    if (cursor) mongoc_cursor_destroy(cursor);

    ogs_thread_mutex_unlock(&self.db_lock);

    return rv;
}

void print_required_vectors(uint8_t *autn, uint8_t *sqn, uint8_t *xres, uint8_t *rand, uint8_t *kasme) {

}

int hss_db_auth_info(
    char *imsi_bcd, hss_db_auth_info_t *auth_info)
{
    ogs_debug("[HSS Context] DB AUTH INFO: Received IMSI : [%s]", imsi_bcd);
    ogs_debug("              DB AUTH INFO: Received SQN : [%lx]", auth_info->sqn);
    ogs_debug("              DB AUTH INFO: Received RAND : [%s]", auth_info->rand);
    int rv = OGS_OK;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    bson_error_t error;
    const bson_t *document;
    bson_iter_t iter;
    bson_iter_t inner_iter;
    bson_iter_t auth_vector_iter;
    char buf[HSS_KEY_LEN];
    char *utf8 = NULL;
    uint32_t length = 0;
    int is_remote = 0;

    ogs_assert(imsi_bcd);
    ogs_assert(auth_info);

    ogs_thread_mutex_lock(&self.db_lock);

    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
#if MONGOC_MAJOR_VERSION >= 1 && MONGOC_MINOR_VERSION >= 5
    cursor = mongoc_collection_find_with_opts(
            self.subscriberCollection, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(self.subscriberCollection,
            MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        ogs_warn("Cannot find IMSI in DB : %s", imsi_bcd);

        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("Cursor Failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }

    memset(auth_info, 0, sizeof(hss_db_auth_info_t));

    if (!bson_iter_init_find(&iter, document, "remote")) {
        // This is a new key that is added to the remote HSS corresponding to the different IMSI which
        // are not owned by the actual HSS.
        ogs_debug("No 'remote' field in this document. Setting remote = %d", is_remote);
    } else {
        is_remote = 1;
        auth_info->use_remote_vectors = 1;
        ogs_debug("The Requested IMSI [%s] is from a remote peer. Use predefined vectors instead. Remote: %d",
                imsi_bcd, is_remote);
    }

    if (!bson_iter_init_find(&iter, document, "security")) {
        ogs_error("No 'security' field in this document");

        rv = OGS_ERROR;
        goto out;
    }

    bson_iter_recurse(&iter, &inner_iter);
    while (bson_iter_next(&inner_iter)) {
        const char *key = bson_iter_key(&inner_iter);

        if (!strcmp(key, "k") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->k, OGS_HEX(utf8, length, buf), HSS_KEY_LEN);
        } else if (!strcmp(key, "opc") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            auth_info->use_opc = 1;
            memcpy(auth_info->opc, OGS_HEX(utf8, length, buf), HSS_KEY_LEN);
        } else if (!strcmp(key, "op") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->op, OGS_HEX(utf8, length, buf), HSS_KEY_LEN);
        } else if (!strcmp(key, "amf") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->amf, OGS_HEX(utf8, length, buf), HSS_AMF_LEN);
        } else if (!strcmp(key, "rand") && BSON_ITER_HOLDS_UTF8(&inner_iter)) {
            utf8 = (char *)bson_iter_utf8(&inner_iter, &length);
            memcpy(auth_info->rand, OGS_HEX(utf8, length, buf), OGS_RAND_LEN);
        } else if (!strcmp(key, "sqn") && BSON_ITER_HOLDS_INT64(&inner_iter)) {
            auth_info->sqn = bson_iter_int64(&inner_iter);
        }
        // Replace the authentication_info objects based on the quadruples of information that's read from here as
        // a new key entry into the security object of each IMSI collection.
    }

    char printable_rand[128], printable_amf[16], printable_op[128], printable_opc[128], printable_k[128];
    ogs_hex_to_ascii(auth_info->rand, OGS_RAND_LEN, printable_rand, sizeof(printable_rand));
    ogs_hex_to_ascii(auth_info->amf, 2, printable_amf, sizeof(printable_amf));
    ogs_hex_to_ascii(auth_info->op, 16, printable_op, sizeof(printable_op));
    ogs_hex_to_ascii(auth_info->opc, 16, printable_opc, sizeof(printable_opc));
    ogs_hex_to_ascii(auth_info->k, 16, printable_k, sizeof(printable_k));

    ogs_debug("[HSS Context After DB Operation] DB AUTH INFO: Received IMSI : [%s]", imsi_bcd);
    ogs_debug("              DB AUTH INFO: Received SQN : [%lx]", auth_info->sqn);
    ogs_debug("              DB AUTH INFO: Received RAND : [%s]", printable_rand);
    ogs_debug("              DB AUTH INFO: Received AMF : [%s]", printable_amf);
    ogs_debug("              DB AUTH INFO: Received OP : [%s]", printable_op);
    ogs_debug("              DB AUTH INFO: Received OPC : [%s]", printable_opc);
    ogs_debug("              DB AUTH INFO: Received K : [%s]", printable_k);

out:
    if (query) bson_destroy(query);
    if (cursor) mongoc_cursor_destroy(cursor);

    ogs_thread_mutex_unlock(&self.db_lock);

    return rv;
}

int hss_db_update_rand_and_sqn(
    char *imsi_bcd, uint8_t *rand, uint64_t sqn)
{
    int rv = OGS_OK;
    bson_t *query = NULL;
    bson_t *update = NULL;
    bson_error_t error;
    char printable_rand[128];

    ogs_assert(rand);
    ogs_hex_to_ascii(rand, OGS_RAND_LEN, printable_rand, sizeof(printable_rand));

    ogs_thread_mutex_lock(&self.db_lock);

    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
    update = BCON_NEW("$set",
            "{",
                "security.rand", printable_rand,
                "security.sqn", BCON_INT64(sqn),
            "}");

    ogs_debug("    [DB UPDATE] Updating IMSI %s to have RAND [%s] and SQN [%lx]", imsi_bcd, printable_rand, sqn);

    if (!mongoc_collection_update(self.subscriberCollection,
            MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);

        rv = OGS_ERROR;
    }

    if (query) bson_destroy(query);
    if (update) bson_destroy(update);

    ogs_thread_mutex_unlock(&self.db_lock);

    return rv;
}

int hss_db_increment_sqn(char *imsi_bcd)
{
    int rv = OGS_OK;
    bson_t *query = NULL;
    bson_t *update = NULL;
    bson_error_t error;
    uint64_t max_sqn = HSS_MAX_SQN;

    ogs_thread_mutex_lock(&self.db_lock);
    ogs_debug("    [DB UPDATE] Incrementing SEQ for IMSI: [%s] and MAX_SQN: [%lx]", imsi_bcd, max_sqn);

    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
    // Does this keep incrementing the SQN parameters by 32? Looks like it.
    update = BCON_NEW("$inc",
            "{",
                "security.sqn", BCON_INT64(32),
            "}");
    ogs_debug("    [HSS Mongo Context] Running inc operation on IMSI");
    if (!mongoc_collection_update(self.subscriberCollection,
            MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }
    bson_destroy(update);

    update = BCON_NEW("$bit",
            "{",
                "security.sqn", 
                "{", "and", BCON_INT64(max_sqn), "}",
            "}");
    ogs_debug("    [HSS Mongo Context] Running bit (and) operation on IMSI");
    if (!mongoc_collection_update(self.subscriberCollection,
            MONGOC_UPDATE_NONE, query, update, NULL, &error)) {
        ogs_error("mongoc_collection_update() failure: %s", error.message);

        rv = OGS_ERROR;
    }

out:
    if (query) bson_destroy(query);
    if (update) bson_destroy(update);

    ogs_thread_mutex_unlock(&self.db_lock);

    return rv;
}

int hss_db_subscription_data(
    char *imsi_bcd, ogs_diam_s6a_subscription_data_t *subscription_data)
{
    int rv = OGS_OK;
    mongoc_cursor_t *cursor = NULL;
    bson_t *query = NULL;
    bson_error_t error;
    const bson_t *document;
    bson_iter_t iter;
    bson_iter_t child1_iter, child2_iter, child3_iter, child4_iter;
    const char *utf8 = NULL;
    uint32_t length = 0;

    ogs_assert(imsi_bcd);
    ogs_assert(subscription_data);

    ogs_thread_mutex_lock(&self.db_lock);

    query = BCON_NEW("imsi", BCON_UTF8(imsi_bcd));
#if MONGOC_MAJOR_VERSION >= 1 && MONGOC_MINOR_VERSION >= 5
    cursor = mongoc_collection_find_with_opts(
            self.subscriberCollection, query, NULL, NULL);
#else
    cursor = mongoc_collection_find(self.subscriberCollection,
            MONGOC_QUERY_NONE, 0, 0, 0, query, NULL, NULL);
#endif

    if (!mongoc_cursor_next(cursor, &document)) {
        ogs_error("Cannot find IMSI in DB : %s", imsi_bcd);

        rv = OGS_ERROR;
        goto out;
    }

    if (mongoc_cursor_error(cursor, &error)) {
        ogs_error("Cursor Failure: %s", error.message);

        rv = OGS_ERROR;
        goto out;
    }

    if (!bson_iter_init(&iter, document)) {
        ogs_error("bson_iter_init failed in this document");

        rv = OGS_ERROR;
        goto out;
    }

    memset(subscription_data, 0, sizeof(ogs_diam_s6a_subscription_data_t));
    while (bson_iter_next(&iter)) {
        const char *key = bson_iter_key(&iter);
        if (!strcmp(key, "access_restriction_data") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->access_restriction_data =
                bson_iter_int32(&iter);

        } else if (!strcmp(key, "subscriber_status") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->subscriber_status =
                bson_iter_int32(&iter);
        } else if (!strcmp(key, "network_access_mode") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->network_access_mode =
                bson_iter_int32(&iter);
        } else if (!strcmp(key, "subscribed_rau_tau_timer") &&
            BSON_ITER_HOLDS_INT32(&iter)) {
            subscription_data->subscribed_rau_tau_timer =
                bson_iter_int32(&iter);
        } else if (!strcmp(key, "ambr") &&
            BSON_ITER_HOLDS_DOCUMENT(&iter)) {
            bson_iter_recurse(&iter, &child1_iter);
            while (bson_iter_next(&child1_iter)) {
                const char *child1_key = bson_iter_key(&child1_iter);
                if (!strcmp(child1_key, "uplink") &&
                    BSON_ITER_HOLDS_INT64(&child1_iter)) {
                    subscription_data->ambr.uplink =
                        bson_iter_int64(&child1_iter) * 1024;
                } else if (!strcmp(child1_key, "downlink") &&
                    BSON_ITER_HOLDS_INT64(&child1_iter)) {
                    subscription_data->ambr.downlink =
                        bson_iter_int64(&child1_iter) * 1024;
                }
            }
        } else if (!strcmp(key, "pdn") &&
            BSON_ITER_HOLDS_ARRAY(&iter)) {
            int pdn_index = 0;

            bson_iter_recurse(&iter, &child1_iter);
            while (bson_iter_next(&child1_iter)) {
                const char *child1_key = bson_iter_key(&child1_iter);
                ogs_pdn_t *pdn = NULL;

                ogs_assert(child1_key);
                pdn_index = atoi(child1_key);
                ogs_assert(pdn_index < OGS_MAX_NUM_OF_SESS);

                pdn = &subscription_data->pdn[pdn_index];

                bson_iter_recurse(&child1_iter, &child2_iter);
                while (bson_iter_next(&child2_iter)) {
                    const char *child2_key = bson_iter_key(&child2_iter);
                    if (!strcmp(child2_key, "apn") &&
                        BSON_ITER_HOLDS_UTF8(&child2_iter)) {
                        utf8 = bson_iter_utf8(&child2_iter, &length);
                        ogs_cpystrn(pdn->apn, utf8,
                            ogs_min(length, OGS_MAX_APN_LEN)+1);
                    } else if (!strcmp(child2_key, "type") &&
                        BSON_ITER_HOLDS_INT32(&child2_iter)) {
                        pdn->pdn_type = bson_iter_int32(&child2_iter);
                    } else if (!strcmp(child2_key, "qos") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "qci") &&
                                BSON_ITER_HOLDS_INT32(&child3_iter)) {
                                pdn->qos.qci = bson_iter_int32(&child3_iter);
                            } else if (!strcmp(child3_key, "arp") &&
                                BSON_ITER_HOLDS_DOCUMENT(&child3_iter)) {
                                bson_iter_recurse(&child3_iter, &child4_iter);
                                while (bson_iter_next(&child4_iter)) {
                                    const char *child4_key =
                                        bson_iter_key(&child4_iter);
                                    if (!strcmp(child4_key, "priority_level") &&
                                        BSON_ITER_HOLDS_INT32(&child4_iter)) {
                                        pdn->qos.arp.priority_level =
                                            bson_iter_int32(&child4_iter);
                                    } else if (!strcmp(child4_key,
                                                "pre_emption_capability") &&
                                        BSON_ITER_HOLDS_INT32(&child4_iter)) {
                                        pdn->qos.arp.pre_emption_capability =
                                            bson_iter_int32(&child4_iter);
                                    } else if (!strcmp(child4_key,
                                                "pre_emption_vulnerability") &&
                                        BSON_ITER_HOLDS_INT32(&child4_iter)) {
                                        pdn->qos.arp.pre_emption_vulnerability =
                                            bson_iter_int32(&child4_iter);
                                    }
                                }
                            }
                        }
                    } else if (!strcmp(child2_key, "ambr") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "uplink") &&
                                BSON_ITER_HOLDS_INT64(&child3_iter)) {
                                pdn->ambr.uplink =
                                    bson_iter_int64(&child3_iter) * 1024;
                            } else if (!strcmp(child3_key, "downlink") &&
                                BSON_ITER_HOLDS_INT64(&child3_iter)) {
                                pdn->ambr.downlink =
                                    bson_iter_int64(&child3_iter) * 1024;
                            }
                        }
                    } else if (!strcmp(child2_key, "pgw") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "addr") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    pdn->pgw_ip.ipv4 = 1;
                                    pdn->pgw_ip.both.addr = ipsub.sub[0];
                                }
                            } else if (!strcmp(child3_key, "addr6") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    pdn->pgw_ip.ipv6 = 1;
                                    memcpy(pdn->pgw_ip.both.addr6,
                                            ipsub.sub, sizeof(ipsub.sub));
                                }
                            }
                        }
                    } else if (!strcmp(child2_key, "ue") &&
                        BSON_ITER_HOLDS_DOCUMENT(&child2_iter)) {
                        bson_iter_recurse(&child2_iter, &child3_iter);
                        while (bson_iter_next(&child3_iter)) {
                            const char *child3_key =
                                bson_iter_key(&child3_iter);
                            if (!strcmp(child3_key, "addr") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    if (pdn->paa.pdn_type ==
                                            OGS_GTP_PDN_TYPE_IPV6) {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV4V6;
                                    } else {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV4;
                                    }
                                    pdn->paa.both.addr = ipsub.sub[0];
                                }
                            } else if (!strcmp(child3_key, "addr6") &&
                                BSON_ITER_HOLDS_UTF8(&child3_iter)) {
                                ogs_ipsubnet_t ipsub;
                                const char *v = 
                                    bson_iter_utf8(&child3_iter, &length);
                                rv = ogs_ipsubnet(&ipsub, v, NULL);
                                if (rv == OGS_OK) {
                                    if (pdn->paa.pdn_type ==
                                            OGS_GTP_PDN_TYPE_IPV4) {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV4V6;
                                    } else {
                                        pdn->paa.pdn_type =
                                            OGS_GTP_PDN_TYPE_IPV6;
                                    }
                                    memcpy(&(pdn->paa.both.addr6),
                                            ipsub.sub, OGS_IPV6_LEN);
                                }

                            }
                        }
                    }
                }
                pdn_index++;
            }
            subscription_data->num_of_pdn = pdn_index;
        }
    }

out:
    if (query) bson_destroy(query);
    if (cursor) mongoc_cursor_destroy(cursor);

    ogs_thread_mutex_unlock(&self.db_lock);

    return rv;
}
