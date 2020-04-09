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

#ifndef UPF_IPFW_H
#define UPF_IPFW_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

int upf_compile_packet_filter(upf_rule_t *pf, char *description);
upf_bearer_t *upf_bearer_find_by_packet(ogs_pkbuf_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* UPF_IPFW_H */
