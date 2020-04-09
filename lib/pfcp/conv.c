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

int ogs_pfcp_sockaddr_to_node_id(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6, int prefer_ipv4,
    ogs_pfcp_node_id_t *node_id, int *len)
{
    const int hdr_len = 1;
    int rv;
    char hostname[OGS_MAX_FQDN_LEN];

    ogs_assert(node_id);

    memset(node_id, 0, sizeof *node_id);

    if (addr && addr->hostname) {
        rv = ogs_getnameinfo(hostname, OGS_MAX_FQDN_LEN, addr, 0);
        if (rv == OGS_OK && strcmp(addr->hostname, hostname) == 0) {
            node_id->type = OGS_PFCP_NODE_ID_FQDN;
            *len = ogs_fqdn_build(node_id->fqdn,
                        addr->hostname, strlen(addr->hostname)) + hdr_len;

            return OGS_OK;
        }
    }

    if (addr6 && addr6->hostname) {
        rv = ogs_getnameinfo(hostname, OGS_MAX_FQDN_LEN, addr6, 0);
        if (rv == OGS_OK && strcmp(addr6->hostname, hostname) == 0) {
            node_id->type = OGS_PFCP_NODE_ID_FQDN;
            *len = ogs_fqdn_build(node_id->fqdn,
                        addr6->hostname, strlen(addr6->hostname)) + hdr_len;

            return OGS_OK;
        }
    }

    if (prefer_ipv4 && addr) {
        node_id->type = OGS_PFCP_NODE_ID_IPV4;
        node_id->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_IPV4_LEN + hdr_len;
    } else if (addr6) {
        node_id->type = OGS_PFCP_NODE_ID_IPV6;
        memcpy(node_id->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_IPV6_LEN + hdr_len;
    } else if (addr) {
        node_id->type = OGS_PFCP_NODE_ID_IPV4;
        node_id->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_IPV4_LEN + hdr_len;
    } else {
        ogs_assert_if_reached();
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ogs_pfcp_f_seid_to_sockaddr(
    ogs_pfcp_f_seid_t *f_seid, uint16_t port, ogs_sockaddr_t **list)
{
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    ogs_assert(f_seid);
    ogs_assert(list);

    addr = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    ogs_assert(addr);
    addr->ogs_sa_family = AF_INET;
    addr->ogs_sin_port = htobe16(port);

    addr6 = ogs_calloc(1, sizeof(ogs_sockaddr_t));
    ogs_assert(addr6);
    addr6->ogs_sa_family = AF_INET6;
    addr6->ogs_sin_port = htobe16(port);

    if (f_seid->ipv4 && f_seid->ipv6) {
        addr->next = addr6;

        addr->sin.sin_addr.s_addr = f_seid->both.addr;
        memcpy(addr6->sin6.sin6_addr.s6_addr, f_seid->both.addr6, OGS_IPV6_LEN);

        *list = addr;
    } else if (f_seid->ipv4) {
        addr->sin.sin_addr.s_addr = f_seid->addr;
        ogs_free(addr6);

        *list = addr;
    } else if (f_seid->ipv6) {
        memcpy(addr6->sin6.sin6_addr.s6_addr, f_seid->addr6, OGS_IPV6_LEN);
        ogs_free(addr);

        *list = addr6;
    } else {
        ogs_free(addr);
        ogs_free(addr6);
        ogs_assert_if_reached();
    }

    return OGS_OK;
}

int ogs_pfcp_sockaddr_to_f_seid(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6,
    ogs_pfcp_f_seid_t *f_seid, int *len)
{
    const int hdr_len = 9;

    ogs_assert(f_seid);

    memset(f_seid, 0, sizeof *f_seid);

    if (addr && addr6) {
        f_seid->ipv4 = 1;
        f_seid->both.addr = addr->sin.sin_addr.s_addr;
        f_seid->ipv6 = 1;
        memcpy(f_seid->both.addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_IPV4V6_LEN + hdr_len;
    } else if (addr) {
        f_seid->ipv4 = 1;
        f_seid->ipv6 = 0;
        f_seid->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_IPV4_LEN + hdr_len;
    } else if (addr6) {
        f_seid->ipv4 = 0;
        f_seid->ipv6 = 1;
        memcpy(f_seid->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_IPV6_LEN + hdr_len;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

int ogs_pfcp_f_seid_to_ip(ogs_pfcp_f_seid_t *f_seid, ogs_ip_t *ip)
{
    ogs_assert(ip);
    ogs_assert(f_seid);

    memset(ip, 0, sizeof *ip);

    ip->ipv4 = f_seid->ipv4;
    ip->ipv6 = f_seid->ipv6;

    if (ip->ipv4 && ip->ipv6) {
        ip->both.addr = f_seid->both.addr;
        memcpy(ip->both.addr6, f_seid->both.addr6, OGS_IPV6_LEN);
        ip->len = OGS_IPV4V6_LEN;
    } else if (ip->ipv4) {
        ip->addr = f_seid->addr;
        ip->len = OGS_IPV4_LEN;
    } else if (ip->ipv6) {
        memcpy(ip->addr6, f_seid->addr6, OGS_IPV6_LEN);
        ip->len = OGS_IPV6_LEN;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

static int sockaddr_to_f_teid(
    ogs_sockaddr_t *addr, ogs_sockaddr_t *addr6,
    ogs_pfcp_f_teid_t *f_teid, int *len)
{
    const int hdr_len = 5;

    ogs_assert(addr == NULL || addr6 == NULL);
    ogs_assert(f_teid);
    memset(f_teid, 0, sizeof *f_teid);

    if (addr && addr6) {
        f_teid->ipv4 = 1;
        f_teid->both.addr = addr->sin.sin_addr.s_addr;
        f_teid->ipv6 = 1;
        memcpy(f_teid->both.addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_IPV4V6_LEN + hdr_len;
    } else if (addr) {
        f_teid->ipv4 = 1;
        f_teid->ipv6 = 0;
        f_teid->addr = addr->sin.sin_addr.s_addr;
        *len = OGS_IPV4_LEN + hdr_len;
    } else if (addr6) {
        f_teid->ipv4 = 0;
        f_teid->ipv6 = 1;
        memcpy(f_teid->addr6, addr6->sin6.sin6_addr.s6_addr, OGS_IPV6_LEN);
        *len = OGS_IPV6_LEN + hdr_len;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

int ogs_pfcp_sockaddr_to_f_teid(
    ogs_sockaddr_t *a, ogs_sockaddr_t *b, ogs_pfcp_f_teid_t *f_teid, int *len)
{
    ogs_sockaddr_t *addr = NULL, *addr6 = NULL;

    if (a && a->sin.sin_family == AF_INET) {
        addr = a;
    }
    if (a && a->sin.sin_family == AF_INET6) {
        addr6 = a;
    }
    if (b && b->sin.sin_family == AF_INET) {
        ogs_assert(addr);
        addr = b;
    }
    if (b && b->sin.sin_family == AF_INET6) {
        ogs_assert(addr6);
        addr6 = b;
    }

    return sockaddr_to_f_teid(addr, addr6, f_teid, len);
}

int ogs_pfcp_paa_to_ue_ip_addr(
    ogs_paa_t *paa, ogs_pfcp_ue_ip_addr_t *addr, int *len)
{
    const int hdr_len = 1;

    ogs_assert(paa);
    ogs_assert(addr);

    memset(addr, 0, sizeof *addr);

    if (paa->pdn_type == OGS_GTP_PDN_TYPE_IPV4V6) {
        addr->ipv4 = 1;
        addr->both.addr = paa->both.addr;
        addr->ipv6 = 1;
        memcpy(addr->both.addr6, paa->both.addr6, OGS_IPV6_LEN);
        *len = OGS_IPV4V6_LEN + hdr_len;
    } else if (paa->pdn_type == OGS_GTP_PDN_TYPE_IPV4) {
        addr->ipv4 = 1;
        addr->ipv6 = 0;
        addr->addr = paa->addr;
        *len = OGS_IPV4_LEN + hdr_len;
    } else if (paa->pdn_type == OGS_GTP_PDN_TYPE_IPV6) {
        addr->ipv4 = 0;
        addr->ipv6 = 1;
        memcpy(addr->addr6, paa->addr6, OGS_IPV6_LEN);
        *len = OGS_IPV6_LEN + hdr_len;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}

int ogs_pfcp_ip_to_outer_header_creation(ogs_ip_t *ip,
        ogs_pfcp_outer_header_creation_t *outer_header_creation, int *len)
{
    const int hdr_len = 6;

    ogs_assert(ip);
    ogs_assert(outer_header_creation);
    memset(outer_header_creation, 0, sizeof *outer_header_creation);

    if (ip->ipv4 && ip->ipv6) {
        outer_header_creation->gtpu4 = 1;
        outer_header_creation->both.addr = ip->both.addr;
        outer_header_creation->gtpu6 = 1;
        memcpy(outer_header_creation->both.addr6, ip->both.addr6, OGS_IPV6_LEN);
        *len = OGS_IPV4V6_LEN + hdr_len;
    } else if (ip->ipv4) {
        outer_header_creation->gtpu4 = 1;
        outer_header_creation->gtpu6 = 0;
        outer_header_creation->addr = ip->addr;
        *len = OGS_IPV4_LEN + hdr_len;
    } else if (ip->ipv6) {
        outer_header_creation->gtpu4 = 0;
        outer_header_creation->gtpu6 = 1;
        memcpy(outer_header_creation->addr6, ip->addr6, OGS_IPV6_LEN);
        *len = OGS_IPV6_LEN + hdr_len;
    } else
        ogs_assert_if_reached();

    return OGS_OK;
}
