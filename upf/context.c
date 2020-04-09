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

#include "context.h"

static upf_context_t self;
static ogs_diam_config_t g_diam_conf;

int __upf_log_domain;

static OGS_POOL(upf_sess_pool, upf_sess_t);
static OGS_POOL(upf_bearer_pool, upf_bearer_t);

static OGS_POOL(upf_pf_pool, upf_pf_t);

static int context_initiaized = 0;

int num_sessions = 0;
void stats_add_session(void) {
    num_sessions = num_sessions + 1;
    ogs_info("Added a session. Number of active sessions is now %d", num_sessions);
}

void stats_remove_session(void) {
    num_sessions = num_sessions - 1;
    ogs_info("Removed a session. Number of active sessions is now %d", num_sessions);
}

void upf_context_init(void)
{
    ogs_assert(context_initiaized == 0);

    /* Initial FreeDiameter Config */
    memset(&g_diam_conf, 0, sizeof(ogs_diam_config_t));

    /* Initialize UPF context */
    memset(&self, 0, sizeof(upf_context_t));
    self.diam_config = &g_diam_conf;

    ogs_log_install_domain(&__ogs_gtp_domain, "gtp", ogs_core()->log.level);
    ogs_log_install_domain(&__ogs_diam_domain, "diam", ogs_core()->log.level);
    ogs_log_install_domain(&__upf_log_domain, "upf", ogs_core()->log.level);

    ogs_gtp_node_init(512);

    ogs_list_init(&self.gtpc_list);
    ogs_list_init(&self.gtpc_list6);
    ogs_list_init(&self.gtpu_list);

    ogs_list_init(&self.sgw_s5c_list);
    ogs_list_init(&self.sgw_s5u_list);

    ogs_pool_init(&upf_sess_pool, ogs_config()->pool.sess);
    ogs_pool_init(&upf_bearer_pool, ogs_config()->pool.bearer);

    ogs_pool_init(&upf_pf_pool, ogs_config()->pool.pf);

    self.sess_hash = ogs_hash_make();
    self.ipv4_hash = ogs_hash_make();
    self.ipv6_hash = ogs_hash_make();

    context_initiaized = 1;
}

void upf_context_final(void)
{
    ogs_assert(context_initiaized == 1);

    upf_sess_remove_all();

    ogs_assert(self.sess_hash);
    ogs_hash_destroy(self.sess_hash);
    ogs_assert(self.ipv4_hash);
    ogs_hash_destroy(self.ipv4_hash);
    ogs_assert(self.ipv6_hash);
    ogs_hash_destroy(self.ipv6_hash);

    ogs_pool_final(&upf_bearer_pool);
    ogs_pool_final(&upf_sess_pool);
    ogs_pool_final(&upf_pf_pool);

    ogs_gtp_node_remove_all(&self.sgw_s5c_list);
    ogs_gtp_node_remove_all(&self.sgw_s5u_list);

    ogs_gtp_node_final();

    context_initiaized = 0;
}

upf_context_t *upf_self(void)
{
    return &self;
}

static int upf_context_prepare(void)
{
    self.gtpc_port = OGS_GTPV2_C_UDP_PORT;
    self.gtpu_port = OGS_GTPV1_U_UDP_PORT;
    self.diam_config->cnf_port = DIAMETER_PORT;
    self.diam_config->cnf_port_tls = DIAMETER_SECURE_PORT;

    return OGS_OK;
}

static int upf_context_validation(void)
{
    if (ogs_list_first(&self.gtpu_list) == NULL) {
        ogs_error("No upf.gtpu in '%s'", ogs_config()->file);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int upf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_config()->document;
    ogs_assert(document);

    rv = upf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "upf")) {
            ogs_yaml_iter_t upf_iter;
            ogs_yaml_iter_recurse(&root_iter, &upf_iter);
            while (ogs_yaml_iter_next(&upf_iter)) {
                const char *upf_key = ogs_yaml_iter_key(&upf_iter);
                ogs_assert(upf_key);
                if (!strcmp(upf_key, "gtpu")) {
                    ogs_yaml_iter_t gtpu_array, gtpu_iter;
                    ogs_yaml_iter_recurse(&upf_iter, &gtpu_array);
                    do {
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.gtpu_port;
                        const char *dev = NULL;
                        ogs_sockaddr_t *addr = NULL;

                        if (ogs_yaml_iter_type(&gtpu_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&gtpu_iter, &gtpu_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&gtpu_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&gtpu_array))
                                break;
                            ogs_yaml_iter_recurse(&gtpu_array, &gtpu_iter);
                        } else if (ogs_yaml_iter_type(&gtpu_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&gtpu_iter)) {
                            const char *gtpu_key =
                                ogs_yaml_iter_key(&gtpu_iter);
                            ogs_assert(gtpu_key);
                            if (!strcmp(gtpu_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&gtpu_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(gtpu_key, "addr") ||
                                    !strcmp(gtpu_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(
                                        &gtpu_iter, &hostname_iter);
                                ogs_assert(ogs_yaml_iter_type(&hostname_iter) !=
                                    YAML_MAPPING_NODE);

                                do {
                                    if (ogs_yaml_iter_type(&hostname_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&hostname_iter))
                                            break;
                                    }

                                    ogs_assert(num <= OGS_MAX_NUM_OF_HOSTNAME);
                                    hostname[num++] = 
                                        ogs_yaml_iter_value(&hostname_iter);
                                } while (
                                    ogs_yaml_iter_type(&hostname_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(gtpu_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&gtpu_iter);
                                if (v) {
                                    port = atoi(v);
                                    self.gtpu_port = port;
                                }
                            } else if (!strcmp(gtpu_key, "dev")) {
                                dev = ogs_yaml_iter_value(&gtpu_iter);
                            } else
                                ogs_warn("unknown key `%s`", gtpu_key);
                        }

                        addr = NULL;
                        for (i = 0; i < num; i++) {
                            rv = ogs_addaddrinfo(&addr,
                                    family, hostname[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        if (addr) {
                            if (ogs_config()->parameter.no_ipv4 == 0)
                                ogs_socknode_add(
                                        &self.gtpu_list, AF_INET, addr);
                            if (ogs_config()->parameter.no_ipv6 == 0)
                                ogs_socknode_add(
                                        &self.gtpu_list, AF_INET6, addr);
                            ogs_freeaddrinfo(addr);
                        }

                        if (dev) {
                            rv = ogs_socknode_probe(
                                    ogs_config()->parameter.no_ipv4 ?
                                        NULL : &self.gtpu_list,
                                    ogs_config()->parameter.no_ipv6 ?
                                        NULL : &self.gtpu_list,
                                    dev, self.gtpu_port);
                            ogs_assert(rv == OGS_OK);
                        }

                    } while (ogs_yaml_iter_type(&gtpu_array) == 
                            YAML_SEQUENCE_NODE);

                    if (ogs_list_first(&self.gtpu_list) == NULL) {
                        rv = ogs_socknode_probe(
                                ogs_config()->parameter.no_ipv4 ?
                                    NULL : &self.gtpu_list,
                                ogs_config()->parameter.no_ipv6 ?
                                    NULL : &self.gtpu_list,
                                NULL, self.gtpu_port);
                        ogs_assert(rv == OGS_OK);
                    }
                } else if (!strcmp(upf_key, "pdn")) {
                    /* handle config in pfcp library */
                }
            }
        }
    }

    rv = upf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

upf_sess_t *upf_sess_add(ogs_pfcp_f_seid_t *cp_f_seid,
        const char *apn, uint8_t pdn_type, ogs_pfcp_ue_ip_addr_t *ue_ip)
{
    char buf1[OGS_ADDRSTRLEN];
    char buf2[OGS_ADDRSTRLEN];
    upf_sess_t *sess = NULL;

    ogs_assert(cp_f_seid);
    ogs_assert(apn);
    ogs_assert(ue_ip);

    ogs_pool_alloc(&upf_sess_pool, &sess);
    ogs_assert(sess);
    memset(sess, 0, sizeof *sess);

    sess->index = ogs_pool_index(&upf_sess_pool, sess);
    ogs_assert(sess->index > 0 && sess->index <= ogs_config()->pool.sess);

    sess->pfcp.local_n4_seid = sess->index;
    sess->pfcp.remote_n4_seid = cp_f_seid->seid;
    ogs_hash_set(self.sess_hash, &sess->pfcp.remote_n4_seid,
            sizeof(sess->pfcp.remote_n4_seid), sess);

    /* Set APN */
    ogs_cpystrn(sess->pdn.apn, apn, OGS_MAX_APN_LEN+1);

    /* Set PDN-Type and UE IP Address */
    sess->pdn.pdn_type = pdn_type;
    if (pdn_type == OGS_GTP_PDN_TYPE_IPV4) {
        if (ue_ip->ipv4 == 0) {
            ogs_error("Cannot support PDN-Type[%d] != [IPv4:%d, IPv6:%d]",
                    pdn_type, ue_ip->ipv4, ue_ip->ipv6);
            goto cleanup;
        }
        sess->ipv4 = ogs_pfcp_ue_ip_alloc(
                AF_INET, apn, (uint8_t *)&(ue_ip->addr));
        ogs_assert(sess->ipv4);
        ogs_hash_set(self.ipv4_hash, sess->ipv4->addr, OGS_IPV4_LEN, sess);
    } else if (pdn_type == OGS_GTP_PDN_TYPE_IPV6) {
        if (ue_ip->ipv6 == 0) {
            ogs_error("Cannot support PDN-Type[%d] != [IPv4:%d, IPv6:%d]",
                    pdn_type, ue_ip->ipv4, ue_ip->ipv6);
            goto cleanup;
        }
        sess->ipv6 = ogs_pfcp_ue_ip_alloc(AF_INET6, apn, ue_ip->addr6);
        ogs_assert(sess->ipv6);
        ogs_hash_set(self.ipv6_hash, sess->ipv6->addr, OGS_IPV6_LEN, sess);
    } else if (pdn_type == OGS_GTP_PDN_TYPE_IPV4V6) {
        if (ue_ip->ipv4 == 0 || ue_ip->ipv6 == 0) {
            ogs_error("Cannot support PDN-Type[%d] != [IPv4:%d, IPv6:%d]",
                    pdn_type, ue_ip->ipv4, ue_ip->ipv6);
            goto cleanup;
        }
        sess->ipv4 = ogs_pfcp_ue_ip_alloc(
                AF_INET, apn, (uint8_t *)&(ue_ip->both.addr));
        ogs_assert(sess->ipv4);
        ogs_hash_set(self.ipv4_hash, sess->ipv4->addr, OGS_IPV4_LEN, sess);

        sess->ipv6 = ogs_pfcp_ue_ip_alloc(AF_INET6, apn, ue_ip->both.addr6);
        ogs_assert(sess->ipv6);
        ogs_hash_set(self.ipv6_hash, sess->ipv6->addr, OGS_IPV6_LEN, sess);
    } else {
        ogs_error("Cannot support PDN-Type[%d] != [IPv4:%d, IPv6:%d]",
                pdn_type, ue_ip->ipv4, ue_ip->ipv6);
        goto cleanup;
    }

    ogs_info("UE F-SEID[CP:%ld,UP:%ld] APN[%s] PDN-Type[%d] IPv4[%s] IPv6[%s]",
        (long)sess->pfcp.local_n4_seid, (long)sess->pfcp.remote_n4_seid,
        apn, pdn_type,
        sess->ipv4 ? INET_NTOP(&sess->ipv4->addr, buf1) : "",
        sess->ipv6 ? INET6_NTOP(&sess->ipv6->addr, buf2) : "");

    ogs_list_add(&ogs_pfcp_self()->sess_list, sess);
    
    stats_add_session();

    return sess;

cleanup:
    ogs_pool_free(&upf_sess_pool, sess);
    return NULL;
}

int upf_sess_remove(upf_sess_t *sess)
{
    ogs_assert(sess);

    ogs_list_remove(&ogs_pfcp_self()->sess_list, sess);
    ogs_pfcp_sess_clear(&sess->pfcp);

    OGS_MEM_CLEAR(sess->create_session_request);
    OGS_MEM_CLEAR(sess->delete_session_request);

    ogs_hash_set(self.sess_hash, &sess->pfcp.remote_n4_seid,
            sizeof(sess->pfcp.remote_n4_seid), NULL);

    if (sess->ipv4) {
        ogs_hash_set(self.ipv4_hash, sess->ipv4->addr, OGS_IPV4_LEN, NULL);
        ogs_pfcp_ue_ip_free(sess->ipv4);
    }
    if (sess->ipv6) {
        ogs_hash_set(self.ipv6_hash, sess->ipv6->addr, OGS_IPV6_LEN, NULL);
        ogs_pfcp_ue_ip_free(sess->ipv6);
    }

    upf_bearer_remove_all(sess);

    ogs_pool_free(&upf_sess_pool, sess);

    stats_remove_session();

    return OGS_OK;
}

void upf_sess_remove_all(void)
{
    upf_sess_t *sess = NULL, *next = NULL;;

    ogs_list_for_each_safe(&ogs_pfcp_self()->sess_list, next, sess)
        upf_sess_remove(sess);
}

upf_sess_t *upf_sess_find(uint32_t index)
{
    ogs_assert(index);
    return ogs_pool_find(&upf_sess_pool, index);
}

upf_sess_t *upf_sess_find_by_teid(uint32_t teid)
{
    return upf_sess_find(teid);
}

upf_sess_t *upf_sess_find_by_cp_seid(uint64_t seid)
{
    return (upf_sess_t *)ogs_hash_get(self.sess_hash, &seid, sizeof(seid));
}

upf_sess_t *upf_sess_find_by_up_seid(uint64_t seid)
{
    return upf_sess_find(seid);
}

upf_sess_t *upf_sess_find_by_ipv4(uint32_t addr)
{
    ogs_assert(self.ipv4_hash);
    return (upf_sess_t *)ogs_hash_get(self.ipv4_hash, &addr, OGS_IPV4_LEN);
}

upf_sess_t *upf_sess_find_by_ipv6(uint32_t *addr6)
{
    ogs_assert(self.ipv6_hash);
    ogs_assert(addr6);
    return (upf_sess_t *)ogs_hash_get(self.ipv6_hash, addr6, OGS_IPV6_LEN);
}

upf_sess_t *upf_sess_add_by_message(ogs_pfcp_message_t *message)
{
    upf_sess_t *sess = NULL;

    ogs_pfcp_f_seid_t *f_seid = NULL;
    char apn[OGS_MAX_APN_LEN];
    ogs_pfcp_ue_ip_addr_t *addr = NULL;

    ogs_pfcp_session_establishment_request_t *req =
        &message->pfcp_session_establishment_request;;
    int i;

    f_seid = req->cp_f_seid.data;
    if (req->cp_f_seid.presence == 0 || f_seid == NULL) {
        ogs_error("No CP F-SEID");
        return NULL;
    }
    f_seid->seid = be64toh(f_seid->seid);

    if (req->pdn_type.presence == 0) {
        ogs_error("No PDN Type");
        return NULL;
    }

    /* Check APN(Network Instance) and UE IP Address in Uplink PDR */
    memset(apn, 0, sizeof(apn));
    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        ogs_pfcp_tlv_create_pdr_t *message = &req->create_pdr[i];
        if (message->presence) {
            if (message->pdi.presence) {
                if (message->pdi.network_instance.presence)
                    ogs_fqdn_parse(apn,
                        message->pdi.network_instance.data,
                        message->pdi.network_instance.len);
                if (message->pdi.ue_ip_address.presence)
                    addr = message->pdi.ue_ip_address.data;
            } else {
                ogs_warn("No PDI in PDR-ID[%d]", message->pdr_id.u16);
            }
        } else {
            break;
        }
    }

    if (strlen(apn) == 0) {
        ogs_error("No APN in PDR");
        return NULL;
    }

    if (!addr) {
        ogs_error("No UE IP Address in PDR");
        return NULL;
    }

    sess = upf_sess_find_by_cp_seid(f_seid->seid);
    if (!sess) {
        sess = upf_sess_add(f_seid, apn, req->pdn_type.u8, addr);
        if (!sess) return NULL;
    }
    ogs_assert(sess);

    return sess;
}

upf_bearer_t *upf_bearer_add(upf_sess_t *sess)
{
    upf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    ogs_pool_alloc(&upf_bearer_pool, &bearer);
    ogs_assert(bearer);
    memset(bearer, 0, sizeof *bearer);

    bearer->index = ogs_pool_index(&upf_bearer_pool, bearer);
    ogs_assert(bearer->index > 0 && bearer->index <=
            ogs_config()->pool.bearer);

    ogs_list_init(&bearer->pf_list);

    bearer->upf_s5u_teid = bearer->index;
    
    bearer->sess = sess;

    ogs_list_add(&sess->bearer_list, bearer);

    return bearer;
}

int upf_bearer_remove(upf_bearer_t *bearer)
{
    ogs_assert(bearer);
    ogs_assert(bearer->sess);

    ogs_list_remove(&bearer->sess->bearer_list, bearer);

    if (bearer->name)
        ogs_free(bearer->name);

    upf_pf_remove_all(bearer);

    ogs_pool_free(&upf_bearer_pool, bearer);

    return OGS_OK;
}

void upf_bearer_remove_all(upf_sess_t *sess)
{
    upf_bearer_t *bearer = NULL, *next_bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each_safe(&sess->bearer_list, next_bearer, bearer)
        upf_bearer_remove(bearer);
}

upf_bearer_t *upf_bearer_find(uint32_t index)
{
    ogs_assert(index);
    return ogs_pool_find(&upf_bearer_pool, index);
}

upf_bearer_t *upf_bearer_find_by_upf_s5u_teid(uint32_t upf_s5u_teid)
{
    return upf_bearer_find(upf_s5u_teid);
}

upf_bearer_t *upf_bearer_find_by_ebi(upf_sess_t *sess, uint8_t ebi)
{
    upf_bearer_t *bearer = NULL;
    
    ogs_assert(sess);

    bearer = upf_bearer_first(sess);
    while (bearer) {
        if (bearer->ebi == ebi)
            break;

        bearer = upf_bearer_next(bearer);
    }

    return bearer;
}

upf_bearer_t *upf_bearer_find_by_name(upf_sess_t *sess, char *name)
{
    upf_bearer_t *bearer = NULL;
    
    ogs_assert(sess);
    ogs_assert(name);

    bearer = upf_bearer_first(sess);
    while (bearer) {
        if (bearer->name && strcmp(bearer->name, name) == 0)
            return bearer;

        bearer = upf_bearer_next(bearer);
    }

    return NULL;
}

upf_bearer_t *upf_bearer_find_by_qci_arp(upf_sess_t *sess, 
                                uint8_t qci,
                                uint8_t priority_level,
                                uint8_t pre_emption_capability,
                                uint8_t pre_emption_vulnerability)
{
    upf_bearer_t *bearer = NULL;

    ogs_assert(sess);

    bearer = upf_default_bearer_in_sess(sess);
    if (!bearer) return NULL;

    if (sess->pdn.qos.qci == qci &&
        sess->pdn.qos.arp.priority_level == priority_level &&
        sess->pdn.qos.arp.pre_emption_capability == 
            pre_emption_capability &&
        sess->pdn.qos.arp.pre_emption_vulnerability == 
            pre_emption_vulnerability) {
        return bearer;
    }

    bearer = upf_bearer_next(bearer);
    while (bearer) {
        if (bearer->qos.qci == qci &&
            bearer->qos.arp.priority_level == priority_level &&
            bearer->qos.arp.pre_emption_capability == 
                pre_emption_capability &&
            bearer->qos.arp.pre_emption_vulnerability == 
                pre_emption_vulnerability) {
            return bearer;
        }
        bearer = upf_bearer_next(bearer);
    }

    return NULL;
}

upf_bearer_t *upf_default_bearer_in_sess(upf_sess_t *sess)
{
    return upf_bearer_first(sess);
}

upf_bearer_t *upf_bearer_first(upf_sess_t *sess)
{
    ogs_assert(sess);
    return ogs_list_first(&sess->bearer_list);
}

upf_bearer_t *upf_bearer_next(upf_bearer_t *bearer)
{
    return ogs_list_next(bearer);
}

upf_pf_t *upf_pf_add(upf_bearer_t *bearer, uint32_t precedence)
{
    upf_pf_t *pf = NULL;

    ogs_assert(bearer);

    ogs_pool_alloc(&upf_pf_pool, &pf);
    ogs_assert(pf);
    memset(pf, 0, sizeof *pf);

    pf->identifier = OGS_NEXT_ID(bearer->pf_identifier, 1, 15);
    pf->bearer = bearer;

    ogs_list_add(&bearer->pf_list, pf);

    return pf;
}

int upf_pf_remove(upf_pf_t *pf)
{
    ogs_assert(pf);
    ogs_assert(pf->bearer);

    ogs_list_remove(&pf->bearer->pf_list, pf);
    ogs_pool_free(&upf_pf_pool, pf);

    return OGS_OK;
}

void upf_pf_remove_all(upf_bearer_t *bearer)
{
    upf_pf_t *pf = NULL, *next_pf = NULL;

    ogs_assert(bearer);
    ogs_list_for_each_safe(&bearer->pf_list, next_pf, pf)
        upf_pf_remove(pf);
}

upf_pf_t *upf_pf_find_by_id(upf_bearer_t *bearer, uint8_t id)
{
    upf_pf_t *pf = NULL;
    
    pf = upf_pf_first(bearer);
    while (pf) {
        if (pf->identifier == id)
            return pf;

        pf = upf_pf_next(pf);
    }

    return OGS_OK;
}

upf_pf_t *upf_pf_first(upf_bearer_t *bearer)
{
    return ogs_list_first(&bearer->pf_list);
}

upf_pf_t *upf_pf_next(upf_pf_t *pf)
{
    return ogs_list_next(pf);
}
