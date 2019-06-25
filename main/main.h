/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#ifndef _FELIX_MAIN_H_
#define _FELIX_MAIN_H_

#include "felix/types.h"

#define MSCC_RC(expr)					\
	{						\
		int __rc__ = (expr);			\
		if (__rc__ < 0) {			\
			printf("%s failed!\n", #expr);	\
			return __rc__;			\
		}					\
	}

struct felix_arg_element;

/* Function pointer to parse the values followed by the 'name' token. Returns
 * the number of arguments it has consumed, in case of error returns -1 */
typedef int (*felix_arg_element_parser_t)(int argc, char *argv[],
					  struct felix_arg_element *e);

typedef int (*felix_arg_cb)(struct felix_arg_element *e);

typedef enum {
	FELIX_ARG_ELEMENT_GROUP_NONE,
	FELIX_ARG_ELEMENT_GROUP_ONE_OF,
	FELIX_ARG_ELEMENT_GROUP_ANY_OF,
	FELIX_ARG_ELEMENT_GROUP_ALL_OF,
	FELIX_ARG_ELEMENT_GROUP_ONE_OR_MORE_OF,
	FELIX_ARG_ELEMENT_GROUP_ZERO_OR_ONE_OF,
} felix_arg_element_group_t;

enum { FELIX_ARG_ELEMENT_TYPE_NONE,
       FELIX_ARG_ELEMENT_TYPE_UINT32,
       FELIX_ARG_ELEMENT_TYPE_INT32,
       FELIX_ARG_ELEMENT_TYPE_VCAP8,
       FELIX_ARG_ELEMENT_TYPE_VCAP16,
       FELIX_ARG_ELEMENT_TYPE_VCAP32,
       FELIX_ARG_ELEMENT_TYPE_VCAP48,
       FELIX_ARG_ELEMENT_TYPE_VCAP64,
       FELIX_ARG_ELEMENT_TYPE_MAC,
       FELIX_ARG_ELEMENT_TYPE_CHAR32,
};

#define FELIX_GROUP_PTR(x, y)                                                  \
	.group_type = FELIX_ARG_ELEMENT_GROUP_##x,                             \
	.group_cnt = (sizeof(y) / sizeof(y[0])), .group = y

struct felix_arg_element {
	/* Name of the element to parse. If name is empty, then it is only
	 * parsing the group. */
	const char *name;

	/* Enable automatic parsing of the no-form variant. */
	int no_form;

	/* Be silent during parsing (no printouts). */
	int silent;

	/* Help text to the user */
	const char *help, *syntax, *example;

	/* How to handle the group of sub elements */
	felix_arg_element_group_t group_type;

	/* Function pointer to do the parsing. If null, then it will be parsing
	 * a flag only. */
	felix_arg_element_parser_t parser;
	/* Min and max values used in parsing of numbers.
	 * Only used if at least one of them is non-zero. */
	long parser_min;
	long parser_max;

	felix_arg_cb cb;

	/* ***** OUTPUT BELOW THIS POINT ***** */

	/* Indicates if matched */
	int parsed_ok;
	int parsed_ok_no_form;

	uint32_t data_type;
	felix_ifindex_list_t ifindex_list;

	union {
		uint32_t uint32;
		int32_t int32;
		felix_vcap_u8_t vcap8;
		felix_vcap_u16_t vcap16;
		felix_vcap_u32_t vcap32;
		felix_vcap_u48_t vcap48;
		felix_vcap_u64_t vcap64;
		felix_mac_t mac;
		char char32[32];
	} data;

	int group_cnt;
	struct felix_arg_element *group;
};

int felix_arg_process_element(int argc, char **argv,
			      struct felix_arg_element *e);

struct felix_arg_element *felix_arg_element_by_name(struct felix_arg_element *e,
						    int size, const char *name);
#define ELEMENT_BY_NAME(ARR, NAME)                                           \
	if (e = felix_arg_element_by_name(ARR, sizeof(ARR) / sizeof(ARR[0]), \
					  NAME))

struct felix_arg_element *felix_arg_element_by_index(struct felix_arg_element *e,
						     int size, int index);
#define ELEMENT_BY_INDEX(ARR, INDEX)                                          \
	if (e = felix_arg_element_by_index(ARR, sizeof(ARR) / sizeof(ARR[0]), \
					   INDEX))

int felix_parse_interface_list(int argc, char **argv,
			       struct felix_arg_element *e);
int felix_parse_int(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_uint(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_uint_hex(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_vcap8(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_vcap16(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_vcap32(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_vcap48(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_vcap64(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_mac(int argc, char **argv, struct felix_arg_element *e);
int felix_parse_ifname_as_idx(int argc, char **argv,
			      struct felix_arg_element *e);
int felix_parse_string32(int argc, char **argv, struct felix_arg_element *e);

extern felix_inst_t *inst;
extern struct felix_arg_element acl_cli_root[];

#endif /*  _FELIX_MAIN_H_ */
