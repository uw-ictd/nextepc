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

#include "ogs-crypt.h"
#include "ogs-core.h"

#include "hss-auc.h"

#define FC_VALUE 0x10

void hss_auc_kasme(const uint8_t *ck, const uint8_t *ik, 
        const uint8_t plmn_id[3], const uint8_t *sqn,  const uint8_t *ak,
        uint8_t *kasme)
{
    int HSS_KEY_LEN=16;
    char debug_plmnid[128];
    ogs_hex_to_ascii(plmn_id, 3, debug_plmnid, sizeof(debug_plmnid));
    char debug_printable_ck[128], debug_printable_ik[128], debug_printable_ak[128], debug_sqn[128];
    ogs_debug("----====Kasme Computation====----");
    ogs_debug("PLMN : [%s]", debug_plmnid);
    ogs_hex_to_ascii(ck, HSS_KEY_LEN, debug_printable_ck, sizeof(debug_printable_ck));
    ogs_debug("CK   : [%s]", debug_printable_ck);
    ogs_hex_to_ascii(ik, HSS_KEY_LEN, debug_printable_ik, sizeof(debug_printable_ik));
    ogs_debug("IK   : [%s]", debug_printable_ik);
    ogs_hex_to_ascii(sqn, HSS_SQN_LEN, debug_sqn, sizeof(debug_sqn));
    ogs_debug("SQN  : [%s]", debug_sqn);
    ogs_hex_to_ascii(ak, HSS_AK_LEN, debug_printable_ak, sizeof(debug_printable_ak));
    ogs_debug("AK   : [%s]", debug_printable_ak);
    uint8_t s[14];
    uint8_t k[32];
    int i;

    memcpy(&k[0], ck, 16);
    memcpy(&k[16], ik, 16);

    char debug_printable_k[128];
    ogs_hex_to_ascii(k, 2*HSS_KEY_LEN, debug_printable_k, sizeof(debug_printable_k));
    ogs_debug("    [AFTER MEMCPY] K : [%s]", debug_printable_k);


    s[0] = FC_VALUE;
    memcpy(&s[1], plmn_id, 3);
    s[4] = 0x00;
    s[5] = 0x03;

    for (i = 0; i < 6; i++)
        s[6+i] = sqn[i] ^ ak[i];
    s[12] = 0x00;
    s[13] = 0x06;

    char debug_s_value[128];
    ogs_hex_to_ascii(s, 14, debug_s_value, sizeof(debug_s_value));
    ogs_debug("     [Before SHA256] S : [%s]", debug_s_value);

    ogs_hmac_sha256(k, 32, s, 14, kasme, 32);

    char printable_kasme[128];
    ogs_hex_to_ascii(kasme, 32, printable_kasme, sizeof(printable_kasme));
    ogs_debug("Kasme : [%s]", printable_kasme);
    ogs_debug("------");
}

void hss_auc_sqn(
    const uint8_t *opc, const uint8_t *k, const uint8_t *auts,
    uint8_t *sqn_ms, uint8_t *mac_s)
{
    int i;
    uint8_t ak[HSS_AK_LEN];
    uint8_t amf[2] = { 0, 0 };
    const uint8_t *rand = auts;
    const uint8_t *conc_sqn_ms = auts + OGS_RAND_LEN;

    milenage_f2345(opc, k, rand, NULL, NULL, NULL, NULL, ak);
    for (i = 0; i < HSS_SQN_LEN; i++)
        sqn_ms[i] = ak[i] ^ conc_sqn_ms[i];
    milenage_f1(opc, k, auts, sqn_ms, amf, NULL, mac_s);
}
