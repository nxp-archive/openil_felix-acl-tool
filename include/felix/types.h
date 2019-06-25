/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#ifndef _FELIX_TYPES_H_
#define _FELIX_TYPES_H_

#ifndef __KERNEL__
#include <stdint.h>
#include <time.h>
#endif

#define FELIX_PRIO_CNT 8
#define FELIX_QUEUE_CNT 8
#define FELIX_PCP_CNT 8
#define FELIX_DEI_CNT 2
#define FELIX_DSCP_CNT 64
#define FELIX_COSID_CNT 8

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned short u16;

typedef enum boolean {
	FALSE,
	TRUE,
} bool;

typedef uint8_t felix_bool_t;
typedef struct {
	int fd;
	unsigned int ifindex_master_device;
} felix_inst_t;

/* Value in percentage */
typedef uint8_t felix_pct_t;

/* Policer/Shaper bit rate in kbps (1000 bits per second).
 * The rate will be rounded to the nearest value supported by the chip */
typedef uint32_t felix_bitrate_t;

/* Dual leaky buckets policer configuration */
typedef enum {
	/* MEF bandwidth profile */
	FELIX_POLICER_TYPE_MEF,

	/* Single bucket policer (CIR/CBS) */
	FELIX_POLICER_TYPE_SINGLE
} felix_policer_type_t;

typedef enum {
	FELIX_VCAP_KEY_TYPE_NORMAL,     /**< Half key, SIP only */
	FELIX_VCAP_KEY_TYPE_DOUBLE_TAG, /**< Quarter key, two tags */
	FELIX_VCAP_KEY_TYPE_IP_ADDR,    /**< Half key, SIP and DIP */
	FELIX_VCAP_KEY_TYPE_MAC_IP_ADDR /**< Full key, MAC and IP addresses */
} felix_vcap_key_type_t;

typedef struct {
	uint8_t addr[6];
} felix_mac_t;

typedef struct {
	uint16_t vid;
	felix_mac_t mac;
} felix_vid_mac_t;

typedef struct {
	uint8_t addr[4];
} felix_ipv4_t;

typedef struct {
	uint8_t addr[16];
} felix_ipv6_t;

typedef enum {
	FELIX_IP_TYPE_NONE = 0,
	FELIX_IP_TYPE_IPV4 = 1,
	FELIX_IP_TYPE_IPV6 = 2,
} felix_ip_type_t;

typedef struct {
	felix_ip_type_t type;

	union {
		felix_ipv4_t ipv4;
		felix_ipv6_t ipv6;
	} addr;
} felix_ip_addr_t;

typedef struct {
	felix_ipv4_t address;
	uint32_t prefix_size;
} felix_ipv4_network_t;

typedef struct {
	felix_ipv6_t address;
	uint32_t prefix_size;
} felix_ipv6_network_t;

typedef struct {
	felix_ip_addr_t address;
	uint32_t prefix_size;
} felix_ip_network_t;

#define FELIX_IFINDEX_MAX 12
typedef struct {
	int ifindex[FELIX_IFINDEX_MAX];
	int cnt;
} felix_ifindex_list_t;

typedef enum {
	FELIX_VCAP_BIT_ANY,
	FELIX_VCAP_BIT_0,
	FELIX_VCAP_BIT_1
} felix_vcap_bit_t;

typedef struct {
	uint8_t value[1];
	uint8_t mask[1];
} felix_vcap_u8_t;

typedef struct {
	uint8_t value[2];
	uint8_t mask[2];
} felix_vcap_u16_t;

typedef struct {
	uint8_t value[3];
	uint8_t mask[3];
} felix_vcap_u24_t;

typedef struct {
	uint8_t value[4];
	uint8_t mask[4];
} felix_vcap_u32_t;

typedef struct {
	uint8_t value[5];
	uint8_t mask[5];
} felix_vcap_u40_t;

typedef struct {
	uint8_t value[6];
	uint8_t mask[6];
} felix_vcap_u48_t;

typedef struct {
	uint8_t value[8];
	uint8_t mask[8];
} felix_vcap_u64_t;

typedef struct {
	uint8_t value[16];
	uint8_t mask[16];
} felix_vcap_u128_t;

typedef struct {
	uint16_t value;
	uint16_t mask;
} felix_vcap_vid_t;

typedef struct {
	felix_ipv4_t value;
	felix_ipv4_t mask;
} felix_vcap_ipv4_t;

typedef struct {
	uint16_t value;
	uint16_t mask;
} felix_vcap_udp_tcp_t;


#endif // _FELIX_TYPES_H_
