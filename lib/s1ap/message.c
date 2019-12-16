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

#include "ogs-s1ap.h"

int __ogs_s1ap_domain;

ogs_pkbuf_t *ogs_s1ap_encode(ogs_s1ap_message_t *message)
{
    asn_enc_rval_t enc_ret = {0};
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(message);

    if (ogs_log_get_domain_level(OGS_LOG_DOMAIN) >= OGS_LOG_TRACE) {
        asn_fprint(stdout, &asn_DEF_S1AP_S1AP_PDU, message);
    }

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    enc_ret = aper_encode_to_buffer(&asn_DEF_S1AP_S1AP_PDU, NULL,
                    message, pkbuf->data, OGS_MAX_SDU_LEN);

    if (enc_ret.encoded < 0) {
        ogs_error("Failed to encode S1AP-PDU[%d]", (int)enc_ret.encoded);
        ogs_error("More info: name=%s, xml=%s", enc_ret.failed_type->name, enc_ret.failed_type->xml_tag);
        asn_fprint(stdout, &asn_DEF_S1AP_S1AP_PDU, message);
        
        ogs_s1ap_free(message);
        ogs_pkbuf_free(pkbuf);
        return NULL;
    }

    ogs_s1ap_free(message);
    ogs_pkbuf_trim(pkbuf, (enc_ret.encoded >> 3));

    return pkbuf;
}

int ogs_s1ap_decode(ogs_s1ap_message_t *message, ogs_pkbuf_t *pkbuf)
{
    asn_dec_rval_t dec_ret = {0};

    ogs_assert(message);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);
    ogs_assert(pkbuf->len);

    memset((void *)message, 0, sizeof(ogs_s1ap_message_t));
    dec_ret = aper_decode(NULL, &asn_DEF_S1AP_S1AP_PDU, (void **)&message, 
            pkbuf->data, pkbuf->len, 0, 0);

    if (dec_ret.code != RC_OK) {
        ogs_warn("Failed to decode S1AP-PDU[code:%d,consumed:%d]",
                dec_ret.code, (int)dec_ret.consumed);
        return OGS_ERROR;
    }

    if (ogs_log_get_domain_level(OGS_LOG_DOMAIN) >= OGS_LOG_TRACE)
        asn_fprint(stdout, &asn_DEF_S1AP_S1AP_PDU, message);

    return OGS_OK;
}

int ogs_s1ap_free(ogs_s1ap_message_t *message)
{
    ogs_assert(message);

    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_S1AP_S1AP_PDU, message);

    return OGS_OK;
}
