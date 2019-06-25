/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "felix/common.h"
#include "felix/types.h"
#include "main.h"

felix_inst_t felix_inst;
felix_inst_t *inst = &felix_inst;

static struct felix_arg_element root[] = {
	{
		.syntax = "acl ...",
		.group_type = FELIX_ARG_ELEMENT_GROUP_ONE_OF,
		.group_cnt = 1,
		.group = acl_cli_root,
	},
};

static struct felix_arg_element top[] = {
	{
		FELIX_GROUP_PTR(ONE_OF, root),
		.help = "Usage: felix [OPTIONS] SUB-MODE {COMMAND|help}\n"
			"Where: SUB-MODE := {acl|qos|associate}\n",
	},
};

int main(int argc, char *argv[])
{
	int ret;

/*
	felix_inst.ifindex_master_device = mscc_instance_load();
	if (!felix_inst.ifindex_master_device) {
		printf("\nWARNING: Could not load persistent felix instance.\n"
		       "Most commands will fail until you run 'felix associate DEVICE CHIPID'!\n\n");
	}
*/

	argc--;
	argv++;

	ret = felix_arg_process_element(argc, argv, top);
	if (ret < 0) {
		printf("Parse error\n");
		return -1;
	}

	if (ret != argc) {
		printf("Parse incomplete\n");
		return -1;
	}

	return 0;
}
