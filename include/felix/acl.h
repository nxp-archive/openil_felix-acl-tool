/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#ifndef _FELIX_ACL_H_
#define _FELIX_ACL_H_

#ifndef __KERNEL__
#include <felix/types.h>
#endif

typedef enum {
	// Ifindex list is not used
	FELIX_ACL_PORT_ACTION_NONE,

	// The list of interfaces is 'anded' with the list of interfaces from
	// the mac-table
	FELIX_ACL_PORT_ACTION_FILTER,

	// The list of interaces is used as-is regardless of what the mac-table
	// says
	FELIX_ACL_PORT_ACTION_REDIR
} felix_acl_port_action_t;

typedef struct {
	/* Forward to CPU */
	felix_bool_t cpu;

	/* Only first frame forwarded to CPU */
	felix_bool_t cpu_once;

	/* CPU queue */
	uint32_t cpu_queue;

	/* Allow learning */
	felix_bool_t learn;

	/* Port action */
	felix_acl_port_action_t port_action;

	/* Egress port list */
	uint8_t ifmask;
} felix_acl_action_t;

typedef enum {
	FELIX_ACE_TYPE_ANY,
	FELIX_ACE_TYPE_ETYPE,
	FELIX_ACE_TYPE_LLC,
	FELIX_ACE_TYPE_SNAP,
	FELIX_ACE_TYPE_ARP,
	FELIX_ACE_TYPE_IPV4,
	FELIX_ACE_TYPE_IPV6
} felix_ace_type_t;

typedef struct {
	felix_vcap_vid_t vid;    /* VLAN ID (12 bit) */
	felix_vcap_u8_t  pcp;    /* PCP (3 bit) */
	felix_vcap_bit_t dei;    /* DEI */
	felix_vcap_bit_t tagged; /* Tagged/untagged frame */
} felix_ace_vlan_t;

typedef struct {
	felix_vcap_u48_t dmac;
	felix_vcap_u48_t smac;
	felix_vcap_u16_t etype;
	felix_vcap_u16_t data; /* MAC data */
} felix_ace_frame_etype_t;

typedef struct {
	felix_vcap_u48_t dmac;
	felix_vcap_u48_t smac;

	/* LLC header: DSAP at byte 0, SSAP at byte 1, Control at byte 2 */
	felix_vcap_u32_t llc;
} felix_ace_frame_llc_t;

typedef struct {
	felix_vcap_u48_t dmac;
	felix_vcap_u48_t smac;

	/* SNAP header: Organization Code at byte 0, Type at byte 3 */
	felix_vcap_u40_t snap;
} felix_ace_frame_snap_t;

typedef struct {
	felix_vcap_u48_t smac;
	felix_vcap_bit_t arp;	/* Opcode ARP/RARP */
	felix_vcap_bit_t req;	/* Opcode request/reply */
	felix_vcap_bit_t unknown;    /* Opcode unknown */
	felix_vcap_bit_t smac_match; /* Sender MAC matches SMAC */
	felix_vcap_bit_t dmac_match; /* Target MAC matches DMAC */

	/**< Protocol addr. length 4, hardware length 6 */
	felix_vcap_bit_t length;

	felix_vcap_bit_t ip;       /* Protocol address type IP */
	felix_vcap_bit_t ethernet; /* Hardware address type Ethernet */
	felix_vcap_ipv4_t sip;     /* Sender IP address */
	felix_vcap_ipv4_t dip;     /* Target IP address */
} felix_ace_frame_arp_t;

typedef struct {
	felix_vcap_bit_t ttl;      /* TTL zero */
	felix_vcap_bit_t fragment; /* Fragment */
	felix_vcap_bit_t options;  /* Header options */
	felix_vcap_u8_t ds;
	felix_vcap_u8_t proto;      /* Protocol */
	felix_vcap_ipv4_t sip;      /* Source IP address */
	felix_vcap_ipv4_t dip;      /* Destination IP address */
	felix_vcap_u48_t data;      /* Not UDP/TCP: IP data */
	felix_vcap_udp_tcp_t sport; /* UDP/TCP: Source port */
	felix_vcap_udp_tcp_t dport; /* UDP/TCP: Destination port */
	felix_vcap_bit_t tcp_fin;
	felix_vcap_bit_t tcp_syn;
	felix_vcap_bit_t tcp_rst;
	felix_vcap_bit_t tcp_psh;
	felix_vcap_bit_t tcp_ack;
	felix_vcap_bit_t tcp_urg;
	felix_vcap_bit_t sip_eq_dip;     /* SIP equals DIP  */
	felix_vcap_bit_t sport_eq_dport; /* SPORT equals DPORT  */
	felix_vcap_bit_t seq_zero;       /* TCP sequence number is zero */
} felix_ace_frame_ipv4_t;

typedef struct {
	felix_vcap_u8_t proto; /* IPv6 protocol */
	felix_vcap_u128_t sip; /* IPv6 source address (byte 0-7 ignored) */
	felix_vcap_bit_t ttl;  /* TTL zero */
	felix_vcap_u8_t ds;
	felix_vcap_u48_t data; /* Not UDP/TCP: IP data */
	felix_vcap_udp_tcp_t sport;
	felix_vcap_udp_tcp_t dport;
	felix_vcap_bit_t tcp_fin;
	felix_vcap_bit_t tcp_syn;
	felix_vcap_bit_t tcp_rst;
	felix_vcap_bit_t tcp_psh;
	felix_vcap_bit_t tcp_ack;
	felix_vcap_bit_t tcp_urg;
	felix_vcap_bit_t sip_eq_dip;     /* SIP equals DIP  */
	felix_vcap_bit_t sport_eq_dport; /* SPORT equals DPORT  */
	felix_vcap_bit_t seq_zero;       /* TCP sequence number is zero */
} felix_ace_frame_ipv6_t;

#define FELIX_ACE_ID_LAST 0
#define FELIX_ACE_IDX_NONE 0xffff

typedef uint16_t felix_ace_id_t;

typedef struct {
	felix_ace_id_t id; /* ID of rule */

	felix_acl_action_t action;

	uint8_t ifmask;
	felix_vcap_bit_t dmac_mc;
	felix_vcap_bit_t dmac_bc;
	felix_ace_vlan_t vlan;

	felix_ace_type_t type;

	union {
		/* FELIX_ACE_TYPE_ANY: No specific fields */
		felix_ace_frame_etype_t etype;
		felix_ace_frame_llc_t llc;
		felix_ace_frame_snap_t snap;
		felix_ace_frame_arp_t arp;
		felix_ace_frame_ipv4_t ipv4;
		felix_ace_frame_ipv6_t ipv6;
	} frame;
} felix_ace_t;

int felix_acl_port_action_conf_set(char *portname,
				   const felix_acl_action_t *const conf);

int felix_acl_port_counter_get(char *portname,
			       uint32_t *const counter);

int felix_acl_port_counter_clear(felix_inst_t *inst, int ifindex);

int felix_ace_init(felix_inst_t *inst, const felix_ace_type_t type,
		   felix_ace_t *const ace);

int felix_ace_add(char *portname, const felix_ace_t *const ace,
		  felix_ace_id_t id_next);

int felix_ace_del(char *portname, felix_ace_id_t id);

int felix_ace_counter_get(char *portname, felix_ace_id_t id,
			  uint32_t *const counter);

int felix_ace_counter_clear(char *portname, felix_ace_id_t id);

#endif /* _FELIX_ACL_H_ */
