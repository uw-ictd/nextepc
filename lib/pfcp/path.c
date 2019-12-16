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

#include "ogs-pfcp.h"

ogs_sock_t *ogs_pfcp_server(ogs_socknode_t *node)
{
    char buf[OGS_ADDRSTRLEN];
    ogs_sock_t *pfcp;
    ogs_assert(node);

    pfcp = ogs_udp_server(node);
    ogs_assert(pfcp);

    ogs_info("pfcp_server() [%s]:%d",
            OGS_ADDR(node->addr, buf), OGS_PORT(node->addr));

    return pfcp;
}

int ogs_pfcp_connect(ogs_sock_t *ipv4, ogs_sock_t *ipv6, ogs_pfcp_node_t *gnode)
{
    ogs_sockaddr_t *addr;
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(ipv4 || ipv6);
    ogs_assert(gnode);
    ogs_assert(gnode->sa_list);

    addr = gnode->sa_list;
    while (addr) {
        ogs_sock_t *sock = NULL;

        if (addr->ogs_sa_family == AF_INET)
            sock = ipv4;
        else if (addr->ogs_sa_family == AF_INET6)
            sock = ipv6;
        else
            ogs_assert_if_reached();

        if (sock) {
            ogs_info("pfcp_connect() [%s]:%d",
                    OGS_ADDR(addr, buf), OGS_PORT(addr));

            gnode->sock = sock;
            memcpy(&gnode->remote_addr, addr, sizeof gnode->remote_addr);
            break;
        }

        addr = addr->next;
    }

    if (addr == NULL) {
        ogs_log_message(OGS_LOG_WARN, ogs_socket_errno,
                "pfcp_connect() [%s]:%d failed",
                OGS_ADDR(gnode->sa_list, buf), OGS_PORT(gnode->sa_list));
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_pfcp_send(ogs_pfcp_node_t *gnode, ogs_pkbuf_t *pkbuf)
{
    ssize_t sent;
    ogs_sock_t *sock = NULL;

    ogs_assert(gnode);
    ogs_assert(pkbuf);
    sock = gnode->sock;
    ogs_assert(sock);

    sent = ogs_send(sock->fd, pkbuf->data, pkbuf->len, 0);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("ogs_send() failed");
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_pfcp_sendto(ogs_pfcp_node_t *gnode, ogs_pkbuf_t *pkbuf)
{
    ssize_t sent;
    ogs_sock_t *sock = NULL;
    ogs_sockaddr_t *addr = NULL;

    ogs_assert(gnode);
    ogs_assert(pkbuf);
    sock = gnode->sock;
    ogs_assert(sock);
    addr = &gnode->remote_addr;
    ogs_assert(addr);

    sent = ogs_sendto(sock->fd, pkbuf->data, pkbuf->len, 0, addr);
    if (sent < 0 || sent != pkbuf->len) {
        ogs_error("ogs_send() failed");
        return OGS_ERROR;
    }

    return OGS_OK;
}
