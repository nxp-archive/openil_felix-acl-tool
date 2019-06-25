/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#ifndef _FELIX_COMMON_H_
#define _FELIX_COMMON_H_

#include <netlink/netlink.h>
#include <felix/types.h>

int mscc_genl_start(const char *name,
		    uint8_t cmd,
		    uint8_t version,
		    struct nl_sock **skp,
		    struct nl_msg **msgp);

#endif // _FELIX_COMMON_H_
