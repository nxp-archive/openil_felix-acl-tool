/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <net/if.h>

#include "felix/types.h"
#include "main.h"

static int felix_arg_process_group_generic_once(int argc, char **argv,
						int one_match_only,
						struct felix_arg_element *e)
{
	int ret, arg_cnt = 0;

	for (int i = 0; i < e->group_cnt; ++i) {
		if (e->group[i].parsed_ok)
			continue;

		ret = felix_arg_process_element(argc, argv, &e->group[i]);

		if (ret >= 0) {
			arg_cnt += ret;
			argc -= ret;
			argv += ret;

			if (one_match_only)
				return arg_cnt;
		}
	}

	return arg_cnt;
}

static int felix_arg_process_group(int argc, char **argv,
				   struct felix_arg_element *e)
{
	int one_match_only = 0;
	int ret, element_cnt = 0, arg_cnt = 0;
	int got_one = 1; // hack to get started

	if (e->group_type == FELIX_ARG_ELEMENT_GROUP_ONE_OF ||
	    e->group_type == FELIX_ARG_ELEMENT_GROUP_ZERO_OR_ONE_OF)
		one_match_only = 1;

	while (got_one) {
		got_one = 0;

		ret = felix_arg_process_group_generic_once(argc, argv,
							   one_match_only, e);

		if (ret > 0) {
			arg_cnt += ret;
			got_one = 1;
			argc -= ret;
			argv += ret;

			if (one_match_only)
				break;
		}
	}

	// Count matched elements
	for (int i = 0; i < e->group_cnt; ++i)
		if (e->group[i].parsed_ok)
			element_cnt++;

	// Check counts
	switch (e->group_type) {
	case FELIX_ARG_ELEMENT_GROUP_ONE_OF:
		if (element_cnt != 1) {
			// printf("ONE_OF: Group %s not fully matched: %d/%d\n",
			//       e->name, element_cnt, e->group_cnt);
			return -1;
		}
		break;

	case FELIX_ARG_ELEMENT_GROUP_ANY_OF:
		// Can not fail
		break;

	case FELIX_ARG_ELEMENT_GROUP_ALL_OF:
		if (element_cnt != e->group_cnt) {
			// printf("ALL_OF: Group %s not fully matched: %d/%d\n",
			//       e->name, element_cnt, e->group_cnt);
			return -1;
		}
		break;

	case FELIX_ARG_ELEMENT_GROUP_ONE_OR_MORE_OF:
		if (element_cnt == 0) {
			// printf("ONE_OR_MORE_OF: Group %s not fully matched: "
			//       "%d/%d\n",
			//       e->name, element_cnt, e->group_cnt);
			return -1;
		}
		break;

	case FELIX_ARG_ELEMENT_GROUP_ZERO_OR_ONE_OF:
		if (element_cnt > 1) {
			// printf("ZERO_OR_ONE: Group %s not fully matched: "
			//       "%d/%d\n",
			//       e->name, element_cnt, e->group_cnt);
			return -1;
		}
		break;

	default:
		assert(0);
		return -1;
	}

	// success
	return arg_cnt;
}

static int felix_print_syntax(const char *txt, struct felix_arg_element *e,
			      int nl)
{
	int rc = 1, cnt = 0, i, len;

	if (e->syntax) {
		printf("%s%s", txt, e->syntax);
	} else if (e->name == NULL) {
		rc = 0;
	} else if (e->no_form) {
		printf("%s%s|no-%s", txt, e->name, e->name);
	} else if (e->parser == felix_parse_vcap8) {
		cnt = 1;
	} else if (e->parser == felix_parse_vcap16) {
		cnt = 2;
	} else if (e->parser == felix_parse_vcap32) {
		cnt = 4;
	} else if (e->parser == felix_parse_vcap48) {
		cnt = 6;
	} else if (e->parser == felix_parse_vcap64) {
		cnt = 8;
	} else {
		rc = 0;
	}

	if (cnt) {
		len = strlen(e->name);
		printf("%s%s ", txt, e->name);
		for (i = 0; i < len; i++) {
			printf("%c", toupper(e->name[i]));
		}
		printf("[/PREFIX|mask ");
		for (i = 0; i < len; i++) {
			printf("%c", toupper(e->name[i]));
		}
		if (e->parser_max) {
			for (i = 0; i < 16; i++) {
				if ((e->parser_max & (1 << i)) == 0) {
					break;
				}
			}
		} else {
			i = (cnt * 8);
		}
		printf("-MASK] (match %u bits)", i);
	}
	if (rc && nl) {
		printf("\n");
	}
	return rc;
}

static void felix_arg_process_element_help(struct felix_arg_element *e)
{
	int stx = felix_print_syntax("Usage:       ", e, 1);

	if (e->example)
		printf("Example:     %s\n", e->example);

	if (e->help)
		printf("Description: %s.\n", e->help);

	if (!stx && !e->example && !e->help &&
	    e->group_type == FELIX_ARG_ELEMENT_GROUP_NONE) {
		printf("No help here\n");
	}

	if (e->group_type == FELIX_ARG_ELEMENT_GROUP_NONE) {
		exit(0);
		return;
	}

	if (e->syntax || e->example || e->help)
		printf("\n");

	switch (e->group_type) {
	case FELIX_ARG_ELEMENT_GROUP_ONE_OF:
		printf("One and only one of the following sub-options must be "
		       "specified:\n");
		break;

	case FELIX_ARG_ELEMENT_GROUP_ANY_OF:
		printf("Zero or more of the following sub-options may be "
		       "specified:\n");
		break;

	case FELIX_ARG_ELEMENT_GROUP_ALL_OF:
		printf("All of the following sub-options must be specified:\n");
		break;

	case FELIX_ARG_ELEMENT_GROUP_ONE_OR_MORE_OF:
		printf("One or more of the following sub-options must be "
		       "specified:\n");
		break;

	case FELIX_ARG_ELEMENT_GROUP_ZERO_OR_ONE_OF:
		printf("Zero or one, of the following sub-options may be "
		       "specified\n");
		break;

	default:;
	}

	for (int i = 0; i < e->group_cnt; ++i) {
		struct felix_arg_element *g = &e->group[i];

		if (felix_print_syntax("    ", g, 0)) {
		} else if (g->name)
			printf("    %s", g->name);
		else
			printf("    ");
		printf("%s\n", g->group_cnt && g->help ? " ..." : "");
	}

	exit(0);
}

int felix_arg_process_element(int argc, char **argv,
			      struct felix_arg_element *e)
{
	const char *level = *argv;
	int ret = 0, no_form = 0;
	int argc_original = argc;

	//	printf("%s #%d %s %s\n", __FUNCTION__, argc, *argv, e->name);
	if (e->parsed_ok) {
		printf("BUG: Element has been processed already!!!");
		assert(0);
		return -1;
	}

	if (argc <= 0) {
		return -1;
	}

	// If a name is defined, then it must match
	if (e->name) {
		// printf("Try match: %s <=> %s\n", (*argv), e->name);
		char buf[128];

		snprintf(buf, 127, "no-%s", e->name);

		if (strcmp((*argv), e->name) == 0) {
			// Nothing to do
		} else if (e->no_form && strcmp((*argv), buf) == 0) {
			no_form = 1;
		} else {
			return -1;
		}

		//  printf("Consume name: %s\n", *argv);

		argc--;
		argv++;
	}

	// Look-ahead to see if the user is really asking for help
	if (argc && strcmp(argv[0], "help") == 0) {
		felix_arg_process_element_help(e);
		return argc_original; // consume all remaining arguments!
	}

	if (e->parser && argc == 0) {
		if (!e->silent)
			printf("Missing value\n");
		return -1;
	}

	// If a parser is defined, then it must be able to parse
	// printf("%s %d\n", level, __LINE__);
	if (e->parser) {
		ret = e->parser(argc, argv, e);
		if (ret < 0) {
			if (!e->silent)
				printf("Invalid value!\n");
			return -1;
		}

		// printf("Parser OK: %d\n", ret);
		assert(ret <= argc);
		argc -= ret;
		argv += ret;

		// Look-ahead to see if the user is really asking for help
		if (argc && strcmp(argv[0], "help") == 0) {
			felix_arg_process_element_help(e);
			return argc_original; // consume all remaining arguments!
		}
	}

	// Parsed succesfully
	e->parsed_ok = 1;

	// printf("%s %d\n", level, __LINE__);

	// Process the sub-groups
	switch (e->group_type) {
	case FELIX_ARG_ELEMENT_GROUP_NONE:
		ret = 0;
		break;

	case FELIX_ARG_ELEMENT_GROUP_ONE_OF:
	case FELIX_ARG_ELEMENT_GROUP_ANY_OF:
	case FELIX_ARG_ELEMENT_GROUP_ALL_OF:
	case FELIX_ARG_ELEMENT_GROUP_ONE_OR_MORE_OF:
	case FELIX_ARG_ELEMENT_GROUP_ZERO_OR_ONE_OF:
		ret = felix_arg_process_group(argc, argv, e);
		break;

	default:
		printf("Invalid group type: %d\n", e->group_type);
		ret = -1;
		break;
	}

	// printf("%s %d\n", level, __LINE__);

	if (ret < 0) {
		e->parsed_ok = 0;
		return -1;
	}

	// printf("%s %d\n", level, __LINE__);
	assert(ret <= argc);
	argc -= ret;
	argv += ret;

	// Look-ahead to see if the user is really asking for help
	if (argc && strcmp(argv[0], "help") == 0) {
		felix_arg_process_element_help(e);
		return argc_original; // consume all remaining arguments!
	}

	if (e->cb) {
		if (argc) {
			// callbacks is not allowed with pending elements to
			// parse
			return -1;
		}

		if (e->cb(e) < 0)
			return -1;
	}

	if (no_form) {
		e->parsed_ok_no_form = 1;
	}

	return argc_original - argc;
}

/* Interface list, for example "eth_red,eth_green" */
int felix_parse_interface_list(int argc, char **argv,
			       struct felix_arg_element *e)
{
	int rc = -1;
	unsigned int idx;
	char c, *p = *argv, *name = p;

	for (;; p++) {
		c = *p;
		if (c == ',' || c == '\0') {
			*p = '\0';
			idx = if_nametoindex(name);
			*p = c;
			name = (p + 1);
			if (idx && e->ifindex_list.cnt < FELIX_IFINDEX_MAX) {
				e->ifindex_list.ifindex[e->ifindex_list.cnt++] =
					idx;
				rc = 1;
			} else {
				rc = -1;
				break;
			}
		}
		if (c == '\0') {
			break;
		}
	}
	return rc;
}

int felix_parse_int(int argc, char **argv, struct felix_arg_element *e)
{
	char *end;
	long i = strtol(*argv, &end, 10);

	if (end == *argv + strlen(*argv)) {
		if (e->parser_min || e->parser_max) {
			if (i < e->parser_min) {
				if (!e->silent)
					printf("Invalid value (< %ld)\n",
					       e->parser_min);
				return -1;
			}
			if (i > e->parser_max) {
				if (!e->silent)
					printf("Invalid value (> %ld)\n",
					       e->parser_max);
				return -1;
			}
		}
		e->data.int32 = i;
		e->data_type = FELIX_ARG_ELEMENT_TYPE_INT32;
		return 1;
	}

	return -1;
}

static int __felix_parse_uint(int argc, char **argv,
			      struct felix_arg_element *e, int base)
{
	char *end;
	unsigned long u = strtoul(*argv, &end, base);
	unsigned long parser_min = (unsigned long)e->parser_min;
	unsigned long parser_max = (unsigned long)e->parser_max;

	if (end == *argv + strlen(*argv)) {
		if (parser_min || parser_max) {
			if (u < parser_min) {
				if (!e->silent)
					printf("Invalid value (< %ld)\n",
					       parser_min);
				return -1;
			}
			if (u > parser_max) {
				if (!e->silent)
					printf("Invalid value (> %ld)\n",
					       parser_max);
				return -1;
			}
		}
		e->data.uint32 = u;
		e->data_type = FELIX_ARG_ELEMENT_TYPE_UINT32;
		return 1;
	}

	return -1;
}

int felix_parse_uint(int argc, char **argv, struct felix_arg_element *e)
{
	return __felix_parse_uint(argc, argv, e, 10);
}

int felix_parse_uint_hex(int argc, char **argv, struct felix_arg_element *e)
{
	return __felix_parse_uint(argc, argv, e, 16);
}

int felix_parse_ifname_as_idx(int argc, char **argv,
			      struct felix_arg_element *e)
{
	unsigned int idx = if_nametoindex(*argv);
	if (!idx) {
		if (!e->silent)
			printf("Failed to parse '%s' as ifindex (%m)\n", *argv);
		return -1;
	}

	e->data.uint32 = idx;
	e->data_type = FELIX_ARG_ELEMENT_TYPE_UINT32;

	return 1;
}

int felix_parse_string32(int argc, char **argv, struct felix_arg_element *e)
{
	if (strnlen(*argv, 32) >= 32)
		return -1;

	strncpy(e->data.char32, *argv, 32);
	e->data_type = FELIX_ARG_ELEMENT_TYPE_CHAR32;

	return 1;
}

static int felix_parser_bytes_num(const char *str, int length, uint8_t *out,
				  long max)
{
	int base;
	char *end;
	uint64_t uint64;

	if (strncmp(str, "0x", 2) == 0) {
		base = 16;
	} else if (strncmp(str, "0b", 2) == 0) {
		base = 2;
	} else {
		base = 10;
	}

	if (length > 8) {
		printf("Use a seperator to parse numbers bigger than 8 bytes");
		return -1;
	} else if (length > 4) {
		uint64 = strtoull(str, &end, base);
	} else {
		uint64 = strtoul(str, &end, base);
	}

	if (max != 0 && uint64 > max) {
		return -1;
	}

	if (str == end) {
		return -1;
	}

	while (length) {
		length--;
		*out = (uint8_t)((uint64 >> (length * 8)) & 0xff);
		out++;
	}

	return end - str;
}

static int felix_parser_bytes(const char *str, int length, uint8_t *out,
			      long max)
{
	char *p, sep = '\0';
	uint32_t i, cnt = 0, values[32] = {};
	const char *str_original = str;
	int sep_dot, sep_col;

	sep_dot = strchr(str, '.') ? 1 : 0;
	sep_col = strchr(str, ':') ? 1 : 0;

	assert(length <= 32);

	int base = 10;

	if (sep_dot && sep_col) {
		printf("Do not combine '.' and ':' as seperators in byte "
		       "strings");
		return -1;
	}

	if (sep_dot) {
		base = 10;
		sep = '.';
	}

	if (sep_col) {
		base = 16;
		sep = ':';
	}

	if (!sep_dot && !sep_col) {
		return felix_parser_bytes_num(str, length, out, max);
	}

	for (i = 0; i < length; ++i) {
		if (i != 0)
			str++;

		values[i] = strtoul(str, &p, base);

		if (values[i] > 255) {
			printf("Failed to parse '%s' as %d bytes\n",
			       str_original, length);
			return -1;
		}

		if (p == str) {
			printf("Failed to parse '%s' as %d bytes\n",
			       str_original, length);
			return -1;
		}

		cnt++;

		str = p;
		if (*str) {
			if (*str != sep)
				break;
		}
	}

	if (cnt != length) {
		printf("Failed to parse '%s' as %d bytes\n", str_original,
		       length);
		return -1;
	}

	for (i = 0; i < length; ++i) {
		*out++ = (uint32_t)values[i];
	}

	return str - str_original;
}

static void felix_prefix_to_mask(uint8_t *mask, int length, uint32_t prefix)
{
	int i;

	memset(mask, length, 0);
	for (i = 0; i < prefix; i++) {
		mask[i / 8] |= (1 << (7 - (i % 8)));
	}
}

static int felix_parse_vcapx(int argc, char **argv, struct felix_arg_element *e,
			     int length, int type, uint8_t *value,
			     uint8_t *mask)
{
	int res;

	res = felix_parser_bytes(*argv, length, value, e->parser_max);
	if (res <= 0) {
		return -1;
	}

	const char *s = *argv + res;
	if (s && *s == '/') {
		s++;
		if (!s) {
			if (!e->silent)
				printf("Prefix is missing\n");
		}

		char *end;
		uint32_t prefix = strtoul(s, &end, 10);

		if (s + strlen(s) != end) {
			if (!e->silent)
				printf("Parse error\n");
		}

		felix_prefix_to_mask(mask, length, prefix);
		e->data_type = type;

		return 1;
	}

	argc--;
	argv++;

	if (!argc) {
		// assume full mask
		felix_prefix_to_mask(mask, length, length * 8);
		return 1;
	}

	if (strcmp("mask", *argv) != 0) {
		// assume full mask
		felix_prefix_to_mask(mask, length, length * 8);
		return 1;
	}

	argc--;
	argv++;

	// mask key-word, but no mask defined
	if (!argc)
		return -1;

	res = felix_parser_bytes(*argv, length, mask, e->parser_max);

	e->data_type = type;

	return 3;
}

int felix_parse_vcap8(int argc, char **argv, struct felix_arg_element *e)
{
	return felix_parse_vcapx(argc, argv, e, 1, FELIX_ARG_ELEMENT_TYPE_VCAP8,
				 e->data.vcap8.value, e->data.vcap8.mask);
}

int felix_parse_vcap16(int argc, char **argv, struct felix_arg_element *e)
{
	return felix_parse_vcapx(argc, argv, e, 2,
				 FELIX_ARG_ELEMENT_TYPE_VCAP16,
				 e->data.vcap16.value, e->data.vcap16.mask);
}

int felix_parse_vcap32(int argc, char **argv, struct felix_arg_element *e)
{
	return felix_parse_vcapx(argc, argv, e, 4,
				 FELIX_ARG_ELEMENT_TYPE_VCAP32,
				 e->data.vcap32.value, e->data.vcap32.mask);
}

int felix_parse_vcap48(int argc, char **argv, struct felix_arg_element *e)
{
	return felix_parse_vcapx(argc, argv, e, 6,
				 FELIX_ARG_ELEMENT_TYPE_VCAP48,
				 e->data.vcap48.value, e->data.vcap48.mask);
}

int felix_parse_vcap64(int argc, char **argv, struct felix_arg_element *e)
{
	return felix_parse_vcapx(argc, argv, e, 8,
				 FELIX_ARG_ELEMENT_TYPE_VCAP64,
				 e->data.vcap64.value, e->data.vcap64.mask);
}

int felix_parse_mac(int argc, char **argv, struct felix_arg_element *e)
{
	int res;

	res = felix_parser_bytes(*argv, 6, e->data.mac.addr, 0);
	if (res != 17) {
		return -1;
	}
	e->data_type = FELIX_ARG_ELEMENT_TYPE_MAC;
#if 0
	printf("parsing as mac res %d mac %02x:%02x:%02x:%02x:%02x:%02x\n",
	       res, e->data.mac.addr[0], e->data.mac.addr[1], e->data.mac.addr[2],
		e->data.mac.addr[3], e->data.mac.addr[4], e->data.mac.addr[5]);
#endif
	return 1;
}

struct felix_arg_element *felix_arg_element_by_name(struct felix_arg_element *e,
						    int size, const char *name)
{
	for (int i = 0; i < size; ++i) {
		if (e[i].name && strcmp(name, e[i].name) == 0) {
			if (e[i].parsed_ok) {
				return e + i;
			} else {
				return 0;
			}
		}
	}

	return 0;
}

struct felix_arg_element *
	felix_arg_element_by_index(struct felix_arg_element *e, int size,
				   int index)
{
	if (index < size && e[index].parsed_ok)
		return e + index;
	else
		return NULL;
}
