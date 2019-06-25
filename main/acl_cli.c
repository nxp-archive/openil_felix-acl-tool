/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "felix/common.h"
#include "felix/acl.h"
#include "felix/types.h"
#include "main.h"

static int acl_port_set(struct felix_arg_element *element);
static int acl_port_cnt_get(struct felix_arg_element *e);
static int acl_port_cnt_clear(struct felix_arg_element *e);
static int acl_rule_add(struct felix_arg_element *e);
static int acl_rule_del(struct felix_arg_element *e);
static int acl_rule_cnt_get(struct felix_arg_element *e);
static int acl_rule_cnt_clear(struct felix_arg_element *e);

static struct felix_arg_element acl_action_type[] = {
	{ .name = "filter",
	  .help = "Allow forwarding only to ports in interface-list" },
	{ .name = "redirect",
	  .help = "Redirect frames to ports in interface-list" },
};

static struct felix_arg_element acl_action_cpu_flags[] = {
	{
		.name = "cpu",
		.help = "Enable CPU copy of frames",
	},
	{
		.name = "cpu-once",
		.help = "Enable CPU copy of first frame",
	},
};

static struct felix_arg_element acl_action_elements[] = {
	{
		FELIX_GROUP_PTR(ONE_OF, acl_action_type),
		.syntax = "filter|redirect",
	},
	{
		.name = "interface-list",
		.parser = felix_parse_int,
		.syntax = "interface-list LIST-OF-INTERFACES",
		.help = "Egress interface list used to filter/redirect frames",
		.example = "interface list mask,0x3f",
	},
	{
		FELIX_GROUP_PTR(ONE_OF, acl_action_cpu_flags),
		.syntax = "cpu|cpu-once",
	},
	{
		.name = "cpu-queue",
		.parser = felix_parse_int,
		.parser_max = 7,
		.syntax = "cpu-queue",
		.help = "CPU queue number used for CPU copy operations",
	},
	{
		.name = "lrn-dis",
		.syntax = "lrn-dis",
		.help = "Disable learning of frames",
	},
};

static struct felix_arg_element acl_action[] = {
	{
		.name = "action",
		FELIX_GROUP_PTR(ANY_OF, acl_action_elements),
		.help = "Set action applied to frames",
	},
};

static struct felix_arg_element acl_match_vlan[] = {
	{
		.name = "vid",
		.parser = felix_parse_vcap16,
		.parser_max = 4095,
		.help = "Classified VLAN ID",
		.example = "vid 400",
	},
	{
		.name = "pcp",
		.parser = felix_parse_vcap8,
		.parser_max = 7,
		.help = "Classified PCP",
		.example = "pcp 1",
	},
	{
		.name = "dei",
		.no_form = 1,
		.help = "Classified DEI",
	},
	{
		.name = "tagged",
		.no_form = 1,
		.help = "Tagged or untagged",
	},
};

#define HLP_DMAC                                                     \
	"MAC address and optional prefix/mask to match against the " \
	"destination MAC address"
#define EXM_DMAC "dmac 00:11:22:33:44:55 mask 00:ff:00:ff:ff:ff"
#define HLP_SMAC                                                     \
	"MAC address and optional prefix/mask to match against the " \
	"source MAC address"
#define EXM_SMAC "smac 00:11:22:33:44:55 mask 00:ff:00:ff:ff:ff"

#define EXM_SIP "sip 1.2.3.0/24"
#define EXM_DIP "dip 1.2.3.0/24"

static struct felix_arg_element acl_match_etype[] = {
	{
		.name = "dmac",
		.parser = felix_parse_vcap48,
		.example = EXM_DMAC,
		.help = HLP_DMAC,
	},
	{
		.name = "smac",
		.parser = felix_parse_vcap48,
		.example = EXM_SMAC,
		.help = HLP_SMAC,
	},
	{
		.name = "etype",
		.parser = felix_parse_vcap16,
		.help = "Ethernet Type field",
		.example = "etype 0xabcd",
	},
	{
		.name = "data",
		.parser = felix_parse_vcap16,
		.help = "Payload/data after Ethernet type field",
	},
};

static struct felix_arg_element acl_match_llc[] = {
	{
		.name = "dmac",
		.parser = felix_parse_vcap48,
		.example = EXM_DMAC,
		.help = HLP_DMAC,
	},
	{
		.name = "smac",
		.parser = felix_parse_vcap48,
		.example = EXM_SMAC,
		.help = HLP_SMAC,
	},
	{
		.name = "data",
		.parser = felix_parse_vcap32,
		.help = "LLC header/data after Ethernet length field",
	},
};

static struct felix_arg_element acl_match_snap[] = {
	{
		.name = "dmac",
		.parser = felix_parse_vcap48,
		.example = EXM_DMAC,
		.help = HLP_DMAC,
	},
	{
		.name = "smac",
		.parser = felix_parse_vcap48,
		.example = EXM_SMAC,
		.help = HLP_SMAC,
	},
	{
		.name = "data",
		.parser = felix_parse_vcap32,
		.help = "Payload/data after SNAP header",
	},
};

static struct felix_arg_element acl_match_arp[] = {
	{
		.name = "smac",
		.parser = felix_parse_vcap48,
		.example = EXM_SMAC,
		.help = HLP_SMAC,
	},
	{
		.name = "sip",
		.parser = felix_parse_vcap32,
		.example = EXM_SIP,
		.help = "Sender IP address and optional prefix/mask",
	},
	{
		.name = "dip",
		.parser = felix_parse_vcap32,
		.example = EXM_DIP,
		.help = "Target IP address and optional prefix/mask",
	},
	{
		.name = "arp",
		.no_form = 1,
		.help = "ARP/RARP selection",
	},
	{
		.name = "req",
		.no_form = 1,
		.help = "Request/reply",
	},
	{
		.name = "sha",
		.no_form = 1,
		.help = "Sender MAC address match selection",
	},
	{
		.name = "tha",
		.no_form = 1,
		.help = "Target MAC address match selection",
	},
	{
		.name = "ip",
		.no_form = 1,
		.help = "IP protocol address selection",
	},
	{
		.name = "eth",
		.no_form = 1,
		.help = "Ethernet hardware address selection",
	},
	{
		.name = "length",
		.no_form = 1,
		.help = "IP/Ethernet protocol/hardware address length selection",
	},
};

static struct felix_arg_element acl_match_ipv4[] = {
	{
		.name = "ttl",
		.no_form = 1,
		.help = "TTL greater than zero indication",
	},
	{
		.name = "fragment",
		.no_form = 1,
		.help = "IPv4 fragment",
	},
	{
		.name = "options",
		.no_form = 1,
		.help = "IPv4 header options present",
	},
	{
		.name = "ds",
		.parser = felix_parse_vcap8,
		.help = "IPv4 DS field",
	},
	{
		.name = "proto",
		.parser = felix_parse_vcap8,
		.help = "IPv4 protocol field",
	},
	{
		.name = "sip",
		.parser = felix_parse_vcap32,
		.example = EXM_SIP,
		.help = "Source IP address and optional prefix/mask",
	},
	{
		.name = "dip",
		.parser = felix_parse_vcap32,
		.example = EXM_DIP,
		.help = "Destination IP address and optional prefix/mask",
	},
	{
		.name = "sport",
		.parser = felix_parse_vcap16,
		.help = "Source UDP/TCP port number",
	},
	{
		.name = "dport",
		.parser = felix_parse_vcap16,
		.help = "Destination UDP/TCP port number",
	},
	{
		.name = "fin",
		.no_form = 1,
		.help = "TCP FIN field",
	},
	{
		.name = "syn",
		.no_form = 1,
		.help = "TCP SYN field",
	},
	{
		.name = "rst",
		.no_form = 1,
		.help = "TCP RST field",
	},
	{
		.name = "psh",
		.no_form = 1,
		.help = "TCP PSH field",
	},
	{
		.name = "ack",
		.no_form = 1,
		.help = "TCP ACK field",
	},
	{
		.name = "urg",
		.no_form = 1,
		.help = "TCP URG field",
	},
	{
		.name = "sip-eq-dip",
		.no_form = 1,
		.help = "SIP equal to DIP indication",
	},
	{
		.name = "sport-eq-dport",
		.no_form = 1,
		.help = "SPORT equal to DPORT indication",
	},
	{
		.name = "seq-zero",
		.no_form = 1,
		.help = "TCP sequence number zero indication",
	},
	{
		.name = "data",
		.parser = felix_parse_vcap48,
		.help = "Non-UDP/TCP frame payload/data",
	},
};

static struct felix_arg_element acl_match_ipv6[] = {
	{
		.name = "ttl",
		.no_form = 1,
		.help = "TTL greater than zero indication",
	},
	{
		.name = "ds",
		.parser = felix_parse_vcap8,
		.help = "IPv6 DS field",
	},
	{
		.name = "proto",
		.parser = felix_parse_vcap8,
		.help = "IPv6 protocol field",
	},
	{
		.name = "sip",
		.parser = felix_parse_vcap64,
		.help = "Source IP address (64 LSB) and optional prefix/mask",
	},
	{
		.name = "sport",
		.parser = felix_parse_vcap16,
		.help = "Source UDP/TCP port number",
	},
	{
		.name = "dport",
		.parser = felix_parse_vcap16,
		.help = "Destination UDP/TCP port number",
	},
	{
		.name = "fin",
		.no_form = 1,
		.help = "TCP FIN field",
	},
	{
		.name = "syn",
		.no_form = 1,
		.help = "TCP SYN field",
	},
	{
		.name = "rst",
		.no_form = 1,
		.help = "TCP RST field",
	},
	{
		.name = "psh",
		.no_form = 1,
		.help = "TCP PSH field",
	},
	{
		.name = "ack",
		.no_form = 1,
		.help = "TCP ACK field",
	},
	{
		.name = "urg",
		.no_form = 1,
		.help = "TCP URG field",
	},
	{
		.name = "sip-eq-dip",
		.no_form = 1,
		.help = "SIP equal to DIP indication",
	},
	{
		.name = "sport-eq-dport",
		.no_form = 1,
		.help = "SPORT equal to DPORT indication",
	},
	{
		.name = "seq-zero",
		.no_form = 1,
		.help = "TCP sequence number zero indication",
	},
	{
		.name = "data",
		.parser = felix_parse_vcap48,
		.help = "Non-UDP/TCP frame payload/data",
	},
};

static struct felix_arg_element acl_match_type[] = {
	{
		.name = "etype",
		FELIX_GROUP_PTR(ANY_OF, acl_match_etype),
		.help = "Ethernet Type frames, except IPv4, IPv6 and ARP",
	},
	{
		.name = "llc",
		FELIX_GROUP_PTR(ANY_OF, acl_match_llc),
		.help = "Ethernet LLC frames, except SNAP",
	},
	{
		.name = "snap",
		FELIX_GROUP_PTR(ANY_OF, acl_match_snap),
		.help = "Ethernet SNAP frames",
	},
	{
		.name = "arp",
		FELIX_GROUP_PTR(ANY_OF, acl_match_arp),
		.help = "ARP frame frames",
	},
	{
		.name = "ipv4",
		FELIX_GROUP_PTR(ANY_OF, acl_match_ipv4),
		.help = "IPv4 frames",
	},
	{
		.name = "ipv6",
		FELIX_GROUP_PTR(ANY_OF, acl_match_ipv6),
		.help = "IPv6 frames",
	},
};

static struct felix_arg_element acl_match[] = {
	{
		.name = "interface-list",
		.parser = felix_parse_int,
		.syntax = "interface-list LIST-OF-INTERFACES",
		.help = "Ingress interface list",
		.example = "eth_red,eth_green",
	},
	{
		.name = "vlan",
		FELIX_GROUP_PTR(ONE_OR_MORE_OF, acl_match_vlan),
		.help = "Match against the classified VLAN fields",
	},
	{
		.name = "l2-multicast",
		.no_form = 1,
		.help = "Match if DMAC is a multicast or not",
	},
	{
		.name = "l2-broadcast",
		.no_form = 1,
		.help = "Match if DMAC is a broadcast or not",
	},
	{
		.name = "type",
		FELIX_GROUP_PTR(ONE_OF, acl_match_type),
		.help = "Frame type",
	},
};

#define ACL_CLI_ACE_ID_MAX 100

static struct felix_arg_element acl_match_action[] = {
	{
		.name = "next",
		.parser = felix_parse_int,
		.parser_max = ACL_CLI_ACE_ID_MAX,
		.syntax = "next ID-NEXT",
		.help = "ID of the next ACE in the list or zero if adding last",
	},
	{
		.name = "action",
		FELIX_GROUP_PTR(ANY_OF, acl_action_elements),
		.help = "Action applied to frames",
	},
	{
		.name = "match",
		FELIX_GROUP_PTR(ANY_OF, acl_match),
		.help = "Frame match criteria",
	},
};

static struct felix_arg_element acl_ace_cnt[] = {
	{
		.name = "get",
		.cb = acl_rule_cnt_get,
		.help = "Get ACE counter",
	},
	{
		.name = "clear",
		.cb = acl_rule_cnt_clear,
		.help = "Clear ACE counter",
	},
};

static struct felix_arg_element acl_rule[] = {
	{
		.name = "add",
		FELIX_GROUP_PTR(ANY_OF, acl_match_action),
		.parser = felix_parse_int,
		.parser_min = 1,
		.parser_max = ACL_CLI_ACE_ID_MAX,
		.cb = acl_rule_add,
		.syntax = "add ID",
		.help = "Add ACE",
	},
	{
		.name = "del",
		.parser = felix_parse_int,
		.parser_min = 1,
		.parser_max = ACL_CLI_ACE_ID_MAX,
		.cb = acl_rule_del,
		.syntax = "del ID",
		.help = "Delete ACE",
	},
	{
		.name = "cnt",
		FELIX_GROUP_PTR(ONE_OF, acl_ace_cnt),
		.parser_min = 1,
		.parser_max = ACL_CLI_ACE_ID_MAX,
		.parser = felix_parse_int,
		.syntax = "cnt ID",
		.help = "Get or clear ACE counter",
	},
};

static struct felix_arg_element acl_port_cnt[] = {
	{
		.name = "get",
		.cb = acl_port_cnt_get,
		.help = "Get port counter",
	},
	{
		.name = "clear",
		.cb = acl_port_cnt_clear,
		.help = "Clear port counter",
	},
};

static struct felix_arg_element acl_port[] = {
	{
		.name = "set",
		FELIX_GROUP_PTR(ALL_OF, acl_action),
		.cb = acl_port_set,
		.help = "Set port action",
	},
	{
		.name = "cnt",
		FELIX_GROUP_PTR(ONE_OF, acl_port_cnt),
		.help = "Get or clear port counter",
	},
};

static struct felix_arg_element acl_cli[] = {
	{
		.name = "rule",
		FELIX_GROUP_PTR(ONE_OF, acl_rule),
		.help = "ACL rule command",
	},
	{
		.name = "port",
		.parser = felix_parse_ifname_as_idx,
		FELIX_GROUP_PTR(ONE_OF, acl_port),
		.syntax = "port INTERFACE",
		.help = "ACL port command",
	},
};

struct felix_arg_element acl_cli_root[] = {
	{
		.name = "device",
		FELIX_GROUP_PTR(ONE_OF, acl_cli),
		.parser = felix_parse_string32,
		.help = "acl sub-mode",
	},
};

static void felix_acl_action(felix_acl_action_t *action)
{
	struct felix_arg_element *e;

	ELEMENT_BY_NAME(acl_action_type, "filter")
	{
		action->port_action = FELIX_ACL_PORT_ACTION_FILTER;
	}
	ELEMENT_BY_NAME(acl_action_type, "redirect")
	{
		action->port_action = FELIX_ACL_PORT_ACTION_REDIR;
	}
	ELEMENT_BY_NAME(acl_action_elements, "interface-list")
	{
		action->ifmask = e->data.int32;
	}
	ELEMENT_BY_NAME(acl_action_cpu_flags, "cpu")
	{
		action->cpu = 1;
	}
	ELEMENT_BY_NAME(acl_action_cpu_flags, "cpu-once")
	{
		action->cpu_once = 1;
	}
	ELEMENT_BY_NAME(acl_action_elements, "cpu-queue")
	{
		action->cpu_queue = e->data.int32;
	}
	ELEMENT_BY_NAME(acl_action_elements, "lrn-dis")
	{
	}
	else
	{
		action->learn = 1;
	}
}

static int acl_port_set(struct felix_arg_element *element)
{
	int res, ifidx;
	char portname[32];
	struct felix_arg_element *e;
	felix_acl_action_t a = {};

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	ELEMENT_BY_NAME(acl_cli, "port")
	{
		ifidx = e->data.int32;
	}
	else
	{
		printf("No valid interface index\n");
		return -1;
	}

	felix_acl_action(&a);

	res = felix_acl_port_action_conf_set(portname, &a);
	if (res < 0) {
		printf("felix_acl_port_action_conf_set failed: %d\n", res);
	}

	return res;
}

static int acl_port_cnt_get(struct felix_arg_element *e)
{
	int res, ifidx;
	uint32_t counter = 0;
	char portname[32];

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	ELEMENT_BY_NAME(acl_cli, "port")
	{
		ifidx = e->data.int32;
	}
	else
	{
		printf("No valid interface index\n");
		return -1;
	}

	res = felix_acl_port_counter_get(portname, &counter);

	if (res != 0)
		return res;

	printf("Counter: %u\n", counter);

	return res;
}

static int acl_port_cnt_clear(struct felix_arg_element *e)
{
	int res, ifidx = -1;
	char portname[32];

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	ELEMENT_BY_NAME(acl_cli, "port")
	{
		ifidx = e->data.int32;
	}

	if (ifidx < 0) {
		printf("No valid interface index\n");
		return -1;
	}

	return felix_acl_port_counter_clear(inst, ifidx);
}

#define FELIX_VCAP_BIT(e) \
	(e->parsed_ok_no_form ? FELIX_VCAP_BIT_0 : FELIX_VCAP_BIT_1)

static void felix_ipv4_from_vcap32(felix_vcap_ipv4_t *ipv4,
				   felix_vcap_u32_t *vcap)
{
	int i;

	for (i = 0; i < 4; i++) {
		ipv4->value.addr[i] = vcap->value[i];
		ipv4->mask.addr[i] = vcap->mask[i];
	}
}

static void felix_l4_port(felix_vcap_udp_tcp_t *port,
			  struct felix_arg_element *e)
{
	port->value =
		((e->data.vcap16.value[0] << 8) + e->data.vcap16.value[1]);
	port->mask = ((e->data.vcap16.mask[0] << 8) + e->data.vcap16.mask[1]);
}

static int acl_rule_add(struct felix_arg_element *e)
{
	int i;
	char portname[32];
	felix_ace_t ace = {};
	felix_ace_frame_etype_t *etype = &ace.frame.etype;
	felix_ace_frame_llc_t *llc = &ace.frame.llc;
	felix_ace_frame_snap_t *snap = &ace.frame.snap;
	felix_ace_frame_arp_t *arp = &ace.frame.arp;
	felix_ace_frame_ipv4_t *ipv4 = &ace.frame.ipv4;
	felix_ace_frame_ipv6_t *ipv6 = &ace.frame.ipv6;
	felix_ace_id_t id_next = FELIX_ACE_ID_LAST;

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	// IDs
	ELEMENT_BY_NAME(acl_rule, "add")
	{
		ace.id = e->data.int32;
	}
	ELEMENT_BY_NAME(acl_match_action, "next")
	{
		id_next = e->data.int32;
	}

	// Ingress interfaces and DMAC flags */
	ELEMENT_BY_NAME(acl_match, "interface-list")
	{
		ace.ifmask = e->data.int32;
	}
	ELEMENT_BY_NAME(acl_match, "l2-multicast")
	{
		ace.dmac_mc = FELIX_VCAP_BIT(e);
	}
	ELEMENT_BY_NAME(acl_match, "l2-broadcast")
	{
		ace.dmac_bc = FELIX_VCAP_BIT(e);
	}

	// VLAN tag
	ELEMENT_BY_NAME(acl_match_vlan, "vid")
	{
		ace.vlan.vid.value = ((e->data.vcap16.value[0] << 8) +
				      e->data.vcap16.value[1]);
		ace.vlan.vid.mask = ((e->data.vcap16.mask[0] << 8) +
				     e->data.vcap16.mask[1]);
		ace.vlan.vid.mask >>= 4; // Change mask from 16 to 12 bits
	}
	ELEMENT_BY_NAME(acl_match_vlan, "pcp")
	{
		ace.vlan.pcp = e->data.vcap8;
	}
	ELEMENT_BY_NAME(acl_match_vlan, "dei")
	{
		ace.vlan.dei = FELIX_VCAP_BIT(e);
	}
	ELEMENT_BY_NAME(acl_match_vlan, "tagged")
	{
		ace.vlan.tagged = FELIX_VCAP_BIT(e);
	}

	// Ethernet Type frame
	ELEMENT_BY_NAME(acl_match_type, "etype")
	{
		ace.type = FELIX_ACE_TYPE_ETYPE;
		ELEMENT_BY_NAME(acl_match_etype, "dmac")
		{
			etype->dmac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_etype, "smac")
		{
			etype->smac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_etype, "etype")
		{
			etype->etype = e->data.vcap16;
		}
		ELEMENT_BY_NAME(acl_match_etype, "data")
		{
			etype->data = e->data.vcap16;
		}
	}

	// LLC frame
	ELEMENT_BY_NAME(acl_match_type, "llc")
	{
		ace.type = FELIX_ACE_TYPE_LLC;
		ELEMENT_BY_NAME(acl_match_llc, "dmac")
		{
			llc->dmac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_llc, "smac")
		{
			llc->smac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_llc, "data")
		{
			llc->llc = e->data.vcap32;
		}
	}

	// SNAP frame
	ELEMENT_BY_NAME(acl_match_type, "snap")
	{
		ace.type = FELIX_ACE_TYPE_SNAP;
		ELEMENT_BY_NAME(acl_match_snap, "dmac")
		{
			snap->dmac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_snap, "smac")
		{
			snap->smac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_snap, "data")
		{
			for (i = 0; i < 4; i++) {
				snap->snap.value[i] = e->data.vcap32.value[i];
				snap->snap.mask[i] = e->data.vcap32.mask[i];
			}
		}
	}

	// ARP frame
	ELEMENT_BY_NAME(acl_match_type, "arp")
	{
		ace.type = FELIX_ACE_TYPE_ARP;
		ELEMENT_BY_NAME(acl_match_arp, "smac")
		{
			arp->smac = e->data.vcap48;
		}
		ELEMENT_BY_NAME(acl_match_arp, "sip")
		{
			felix_ipv4_from_vcap32(&arp->sip, &e->data.vcap32);
		}
		ELEMENT_BY_NAME(acl_match_arp, "dip")
		{
			felix_ipv4_from_vcap32(&arp->dip, &e->data.vcap32);
		}
		ELEMENT_BY_NAME(acl_match_arp, "arp")
		{
			arp->arp = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_arp, "req")
		{
			arp->req = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_arp, "sha")
		{
			arp->smac_match = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_arp, "tha")
		{
			arp->dmac_match = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_arp, "ip")
		{
			arp->ip = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_arp, "eth")
		{
			arp->ethernet = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_arp, "length")
		{
			arp->length = FELIX_VCAP_BIT(e);
		}
	}

	// IPv4 frame
	ELEMENT_BY_NAME(acl_match_type, "ipv4")
	{
		ace.type = FELIX_ACE_TYPE_IPV4;
		ELEMENT_BY_NAME(acl_match_ipv4, "ttl")
		{
			ipv4->ttl = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "fragment")
		{
			ipv4->fragment = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "options")
		{
			ipv4->options = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "ds")
		{
			ipv4->ds = e->data.vcap8;
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "proto")
		{
			ipv4->proto = e->data.vcap8;
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "sip")
		{
			felix_ipv4_from_vcap32(&ipv4->sip, &e->data.vcap32);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "dip")
		{
			felix_ipv4_from_vcap32(&ipv4->dip, &e->data.vcap32);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "sport")
		{
			felix_l4_port(&ipv4->sport, e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "dport")
		{
			felix_l4_port(&ipv4->dport, e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "fin")
		{
			ipv4->tcp_fin = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "syn")
		{
			ipv4->tcp_syn = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "rst")
		{
			ipv4->tcp_rst = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "psh")
		{
			ipv4->tcp_psh = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "ack")
		{
			ipv4->tcp_ack = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "urg")
		{
			ipv4->tcp_urg = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "sip-eq-dip")
		{
			ipv4->sip_eq_dip = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "sport-eq-dport")
		{
			ipv4->sport_eq_dport = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "seq-zero")
		{
			ipv4->seq_zero = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv4, "data")
		{
			ipv4->data = e->data.vcap48;
		}
	}

	// IPv6 frame
	ELEMENT_BY_NAME(acl_match_type, "ipv6")
	{
		ace.type = FELIX_ACE_TYPE_IPV6;
		ELEMENT_BY_NAME(acl_match_ipv6, "ttl")
		{
			ipv6->ttl = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "ds")
		{
			ipv6->ds = e->data.vcap8;
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "proto")
		{
			ipv6->proto = e->data.vcap8;
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "sip")
		{
			for (i = 0; i < 8; i++) {
				ipv6->sip.value[i + 8] =
					e->data.vcap64.value[i];
				ipv6->sip.mask[i + 8] = e->data.vcap64.mask[i];
			}
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "sport")
		{
			felix_l4_port(&ipv6->sport, e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "dport")
		{
			felix_l4_port(&ipv6->dport, e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "fin")
		{
			ipv6->tcp_fin = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "syn")
		{
			ipv6->tcp_syn = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "rst")
		{
			ipv6->tcp_rst = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "psh")
		{
			ipv6->tcp_psh = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "ack")
		{
			ipv6->tcp_ack = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "urg")
		{
			ipv6->tcp_urg = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "sip-eq-dip")
		{
			ipv6->sip_eq_dip = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "sport-eq-dport")
		{
			ipv6->sport_eq_dport = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "seq-zero")
		{
			ipv6->seq_zero = FELIX_VCAP_BIT(e);
		}
		ELEMENT_BY_NAME(acl_match_ipv6, "data")
		{
			ipv6->data = e->data.vcap48;
		}
	}

	felix_acl_action(&ace.action);

	return felix_ace_add(portname, &ace, id_next);
}

static int acl_rule_del(struct felix_arg_element *e)
{
	int id = 0;
	char portname[32];

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	ELEMENT_BY_NAME(acl_rule, "del")
	{
		id = e->data.int32;
	}
	return felix_ace_del(portname, id);
}


static int acl_rule_cnt_get(struct felix_arg_element *e)
{
	int res, id = 0;
	uint32_t counter = 0;
	char portname[32];

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	ELEMENT_BY_NAME(acl_rule, "cnt")
	{
		id = e->data.int32;
	}

	res = felix_ace_counter_get(portname, id, &counter);

	if (res != 0)
		return res;

	printf("Counter: %u\n", counter);

	return res;
}

static int acl_rule_cnt_clear(struct felix_arg_element *e)
{
	int id = 0;
	char portname[32];

	ELEMENT_BY_NAME(acl_cli_root, "device")
	{
		strncpy(portname, e->data.char32, 32);
	}
	ELEMENT_BY_NAME(acl_rule, "cnt")
	{
		id = e->data.int32;
	}
	return felix_ace_counter_clear(portname, id);
}
