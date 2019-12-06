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

#include "nas-security.h"

ogs_pkbuf_t *nas_security_encode(
        mme_ue_t *mme_ue, ogs_nas_message_t *message)
{
    int integrity_protected = 0;
    int new_security_context = 0;
    int ciphered = 0;

    ogs_assert(mme_ue);
    ogs_assert(message);

    switch (message->h.security_header_type) {
    case OGS_NAS_SECURITY_HEADER_PLAIN_NAS_MESSAGE:
        return ogs_nas_plain_encode(message);
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED:
        integrity_protected = 1;
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHERED:
        integrity_protected = 1;
        ciphered = 1;
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_NEW_SECURITY_CONTEXT:
        integrity_protected = 1;
        new_security_context = 1;
        break;
    case OGS_NAS_SECURITY_HEADER_INTEGRITY_PROTECTED_AND_CIPHTERD_WITH_NEW_INTEGRITY_CONTEXT:
        integrity_protected = 1;
        new_security_context = 1;
        ciphered = 1;
        break;
    default:
        ogs_error("Not implemented(securiry header type:0x%x)", 
                message->h.security_header_type);
        return NULL;
    }

    if (new_security_context) {
        mme_ue->dl_count = 0;
        mme_ue->ul_count.i32 = 0;
    }

    if (mme_ue->selected_enc_algorithm == 0)
        ciphered = 0;
    if (mme_ue->selected_int_algorithm == 0)
        integrity_protected = 0;

    // if (ciphered || integrity_protected) {
    ogs_nas_security_header_t h;
    ogs_pkbuf_t *new = NULL;

    memset(&h, 0, sizeof(h));
    h.security_header_type = message->h.security_header_type;
    h.protocol_discriminator = message->h.protocol_discriminator;
    h.sequence_number = (mme_ue->dl_count & 0xff);

    new = ogs_nas_plain_encode(message);
    if (!new) {
        ogs_error("ogs_nas_plain_encode() failed");
        return NULL;
    }

    if (ciphered) {
        /* encrypt NAS message */
        nas_encrypt(mme_ue->selected_enc_algorithm,
            mme_ue->knas_enc, mme_ue->dl_count, NAS_SECURITY_BEARER,
            NAS_SECURITY_DOWNLINK_DIRECTION, new);
    }

    /* encode sequence number */
    ogs_assert(ogs_pkbuf_push(new, 1));
    *(uint8_t *)(new->data) = h.sequence_number;

    if (integrity_protected) {
        uint8_t mac[NAS_SECURITY_MAC_SIZE];

        /* calculate NAS MAC(message authentication code) */
        nas_mac_calculate(mme_ue->selected_int_algorithm,
            mme_ue->knas_int, mme_ue->dl_count, NAS_SECURITY_BEARER, 
            NAS_SECURITY_DOWNLINK_DIRECTION, new, mac);
        memcpy(&h.message_authentication_code, mac, sizeof(mac));
    }

    /* increase dl_count */
    mme_ue->dl_count = (mme_ue->dl_count + 1) & 0xffffff; /* Use 24bit */

    /* encode all security header */
    ogs_assert(ogs_pkbuf_push(new, 5));
    memcpy(new->data, &h, sizeof(ogs_nas_security_header_t));

    mme_ue->security_context_available = 1;

    return new;
    // }

    // ogs_error("Invalid param : type[%d] ciphered[%d] integrity_protected[%d]",
    //         message->h.security_header_type, ciphered, integrity_protected);
    // return NULL;
}

int nas_security_decode(mme_ue_t *mme_ue, 
    nas_security_header_type_t security_header_type, ogs_pkbuf_t *pkbuf)
{
    ogs_assert(mme_ue);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);

    if (security_header_type.service_request) {
#define SHORT_MAC_SIZE 2
        ogs_nas_ksi_and_sequence_number_t *ksi_and_sequence_number =
            (ogs_nas_ksi_and_sequence_number_t *)(pkbuf->data + 1);
        uint8_t original_mac[SHORT_MAC_SIZE];
        uint8_t estimated_sequence_number;
        uint8_t sequence_number_high_3bit;
        uint8_t mac[NAS_SECURITY_MAC_SIZE];

        if (mme_ue->selected_int_algorithm == 0) {
            ogs_warn("integrity algorithm is not defined");
            return OGS_ERROR;
        }

        ogs_assert(ksi_and_sequence_number);
        estimated_sequence_number = 
            ksi_and_sequence_number->sequence_number;

        sequence_number_high_3bit = mme_ue->ul_count.sqn & 0xe0;
        if ((mme_ue->ul_count.sqn & 0x1f) > estimated_sequence_number) {
            sequence_number_high_3bit += 0x20;
        }
        estimated_sequence_number += sequence_number_high_3bit;

        if (mme_ue->ul_count.sqn > estimated_sequence_number)
            mme_ue->ul_count.overflow++;
        mme_ue->ul_count.sqn = estimated_sequence_number;

        memcpy(original_mac, pkbuf->data + 2, SHORT_MAC_SIZE);

        ogs_pkbuf_trim(pkbuf, 2);
        nas_mac_calculate(mme_ue->selected_int_algorithm,
            mme_ue->knas_int, mme_ue->ul_count.i32, NAS_SECURITY_BEARER,
            NAS_SECURITY_UPLINK_DIRECTION, pkbuf, mac);

        ogs_pkbuf_put_data(pkbuf, original_mac, SHORT_MAC_SIZE);
        if (memcmp(mac + 2, pkbuf->data + 2, 2) != 0) {
            ogs_warn("NAS MAC verification failed(%x%x != %x%x)",
                    mac[2], mac[3],
                    ((unsigned char *)pkbuf->data)[2],
                    ((unsigned char *)pkbuf->data)[3]);

            mme_ue->mac_failed = 1;
        }

        return OGS_OK;
    }

    if (!mme_ue->security_context_available) {
        security_header_type.integrity_protected = 0;
        security_header_type.new_security_context = 0;
        security_header_type.ciphered = 0;
    }

    if (security_header_type.new_security_context) {
        mme_ue->ul_count.i32 = 0;
    }

    if (mme_ue->selected_enc_algorithm == 0)
        security_header_type.ciphered = 0;
    if (mme_ue->selected_int_algorithm == 0)
        security_header_type.integrity_protected = 0;

    if (security_header_type.ciphered || 
        security_header_type.integrity_protected) {
        ogs_nas_security_header_t *h = NULL;

        /* NAS Security Header */
        ogs_assert(ogs_pkbuf_push(pkbuf, 6));
        h = (ogs_nas_security_header_t *)pkbuf->data;

        /* NAS Security Header.Sequence_Number */
        ogs_assert(ogs_pkbuf_pull(pkbuf, 5));

        /* calculate ul_count */
        if (mme_ue->ul_count.sqn > h->sequence_number)
            mme_ue->ul_count.overflow++;
        mme_ue->ul_count.sqn = h->sequence_number;

        if (security_header_type.integrity_protected) {
            uint8_t mac[NAS_SECURITY_MAC_SIZE];
            uint32_t mac32;
            uint32_t original_mac = h->message_authentication_code;

            /* calculate NAS MAC(message authentication code) */
            nas_mac_calculate(mme_ue->selected_int_algorithm,
                mme_ue->knas_int, mme_ue->ul_count.i32, NAS_SECURITY_BEARER, 
                NAS_SECURITY_UPLINK_DIRECTION, pkbuf, mac);
            h->message_authentication_code = original_mac;

            memcpy(&mac32, mac, NAS_SECURITY_MAC_SIZE);
            if (h->message_authentication_code != mac32) {
                ogs_warn("NAS MAC verification failed(0x%x != 0x%x)",
                        ntohl(h->message_authentication_code), ntohl(mac32));
                mme_ue->mac_failed = 1;
            }
        }

        /* NAS EMM Header or ESM Header */
        ogs_assert(ogs_pkbuf_pull(pkbuf, 1));

        if (security_header_type.ciphered) {
            /* decrypt NAS message */
            nas_encrypt(mme_ue->selected_enc_algorithm,
                mme_ue->knas_enc, mme_ue->ul_count.i32, NAS_SECURITY_BEARER,
                NAS_SECURITY_UPLINK_DIRECTION, pkbuf);
        }
    }

    return OGS_OK;
}

void nas_mac_calculate(uint8_t algorithm_identity,
        uint8_t *knas_int, uint32_t count, uint8_t bearer, 
        uint8_t direction, ogs_pkbuf_t *pkbuf, uint8_t *mac)
{
    uint8_t *ivec = NULL;;
    uint8_t cmac[16];
    uint32_t mac32;

    ogs_assert(knas_int);
    ogs_assert(bearer <= 0x1f);
    ogs_assert(direction == 0 || direction == 1);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);
    ogs_assert(pkbuf->len);
    ogs_assert(mac);

    switch (algorithm_identity) {
    case OGS_NAS_SECURITY_ALGORITHMS_128_EIA1:
        snow_3g_f9(knas_int, count, (bearer << 27), direction, 
                pkbuf->data, (pkbuf->len << 3), mac);
        break;
    case OGS_NAS_SECURITY_ALGORITHMS_128_EIA2:
        count = htonl(count);

        ogs_pkbuf_push(pkbuf, 8);

        ivec = pkbuf->data;
        memset(ivec, 0, 8);
        memcpy(ivec + 0, &count, sizeof(count));
        ivec[4] = (bearer << 3) | (direction << 2);

        ogs_aes_cmac_calculate(cmac, knas_int, pkbuf->data, pkbuf->len);
        memcpy(mac, cmac, 4);

        ogs_pkbuf_pull(pkbuf, 8);

        break;
    case OGS_NAS_SECURITY_ALGORITHMS_128_EIA3:
        zuc_eia3(knas_int, count, bearer, direction, 
                (pkbuf->len << 3), pkbuf->data, &mac32);
        mac32 = ntohl(mac32);
        memcpy(mac, &mac32, sizeof(uint32_t));
        break;
    case OGS_NAS_SECURITY_ALGORITHMS_EIA0:
        ogs_error("Invalid identity : NAS_SECURITY_ALGORITHMS_EIA0");
        break;
    default:
        ogs_assert_if_reached();
        break;
    }
}

void nas_encrypt(uint8_t algorithm_identity,
        uint8_t *knas_enc, uint32_t count, uint8_t bearer, 
        uint8_t direction, ogs_pkbuf_t *pkbuf)
{
    uint8_t ivec[16];

    ogs_assert(knas_enc);
    ogs_assert(bearer <= 0x1f);
    ogs_assert(direction == 0 || direction == 1);
    ogs_assert(pkbuf);
    ogs_assert(pkbuf->data);
    ogs_assert(pkbuf->len);

    switch (algorithm_identity) {
    case OGS_NAS_SECURITY_ALGORITHMS_128_EEA1:
        snow_3g_f8(knas_enc, count, bearer, direction, 
                pkbuf->data, (pkbuf->len << 3));
        break;
    case OGS_NAS_SECURITY_ALGORITHMS_128_EEA2:
        count = htonl(count);

        memset(ivec, 0, 16);
        memcpy(ivec + 0, &count, sizeof(count));
        ivec[4] = (bearer << 3) | (direction << 2);
        ogs_aes_ctr128_encrypt(knas_enc, ivec, 
                pkbuf->data, pkbuf->len, pkbuf->data);
        break;
    case OGS_NAS_SECURITY_ALGORITHMS_128_EEA3:
        zuc_eea3(knas_enc, count, bearer, direction, 
                (pkbuf->len << 3), pkbuf->data, pkbuf->data);
        break;
    case OGS_NAS_SECURITY_ALGORITHMS_EEA0:
        ogs_error("Invalid identity : NAS_SECURITY_ALGORITHMS_EEA0");
        break;
    default:
        ogs_assert_if_reached();
        break;
    }
}
