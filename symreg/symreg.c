#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "ocelot.h"

#define FATAL do { fprintf(stderr, "Error at line %d, file %s (%d) [%s]\n", \
  __LINE__, __FILE__, errno, strerror(errno)); exit(1); } while(0)

#define MAP_SIZE 4096UL
#define MAP_MASK (MAP_SIZE - 1)

typedef enum {
    SYMREG_COMPONENTS_TGT,
    SYMREG_COMPONENTS_GRP,
    SYMREG_COMPONENTS_REG,
    SYMREG_COMPONENTS_LAST
} symreg_components_t;

typedef enum {
    SYMREG_QUERY_SZ,
    SYMREG_QUERY_QUERY,
    SYMREG_QUERY_READ,
    SYMREG_QUERY_LAST
} symreg_query_t;

int fd = -1;
unsigned long phys;
void *map_base;

static unsigned long read_reg(unsigned long addr) {

	if (fd < 0)
		if((fd = open("/dev/mem", O_RDWR | O_SYNC)) == -1) FATAL;

	if (addr < phys || addr >= (phys + MAP_SIZE)) {
		if (phys)
			if(munmap(map_base, MAP_SIZE) == -1) FATAL;
	} else {
		return *((unsigned long *) (map_base + addr - phys));
	}

	fflush(stdout);

	phys = addr & ~MAP_MASK;
	map_base = mmap(0, MAP_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, phys);
	if(map_base == (void *) -1) FATAL;

	return *((unsigned long *) (map_base + addr - phys));
}

struct component_info {
	int idx;
	int repl;
};

static int find_target(struct component_info *info, char *pattern)
{
	int t;

	for (t = 0; vtss_symreg_targets[t].name; t++) {
		int repl = info[SYMREG_COMPONENTS_TGT].repl;

		if (repl >=0 && repl != vtss_symreg_targets[t].repl_number)
			continue;

		if (!strcmp(pattern, vtss_symreg_targets[t].name))
			break;
	}

	if (!vtss_symreg_targets[t].name)
		return -1;

	info[SYMREG_COMPONENTS_TGT].idx = t;

	return 0;
}

static int find_grp(struct component_info *info, char *pattern)
{
	int t = info[SYMREG_COMPONENTS_TGT].idx;
	const vtss_symreg_reggrp_t *groups;
	int g;

	groups = vtss_symreg_targets[t].reggrps;
	for (g = 0; groups[g].name; g++) {
		if (!strcmp(pattern, groups[g].name))
			break;
	}

	if (!groups[g].name)
		return -1;

	info[SYMREG_COMPONENTS_GRP].idx = g;

	return 0;
}

static int find_reg(struct component_info *info, char *pattern)
{
	int t = info[SYMREG_COMPONENTS_TGT].idx;
	int g = info[SYMREG_COMPONENTS_GRP].idx;
	int r;
	const vtss_symreg_target_t *tgt = &vtss_symreg_targets[t];
	const vtss_symreg_reggrp_t *grp = &tgt->reggrps[g];
	const vtss_symreg_reg_t *regs = grp->regs;

	for (r = 0; regs[r].name; r++) {
		if (!strcmp(pattern, regs[r].name))
			break;
	}

	if (!regs[r].name)
		return -1;

	info[SYMREG_COMPONENTS_REG].idx = r;

	return 0;
}

static int find_component(struct component_info *info, int i, char *pattern)
{
	switch (i) {
		case SYMREG_COMPONENTS_TGT:
			return find_target(info, pattern);
			break;

		case SYMREG_COMPONENTS_GRP:
			return find_grp(info, pattern);
			break;

		case SYMREG_COMPONENTS_REG:
			return find_reg(info, pattern);
			break;
	}

	return -1;
}

static int match_regs(char *pattern, struct component_info *info)
{
	int i;
	char *str1 = pattern, *str2;
	size_t cnt;

	for (i = 0; i < SYMREG_COMPONENTS_LAST; i++) {
		info[i].idx = -1;
		info[i].repl = -1;
	}

	for (i = 0; i < SYMREG_COMPONENTS_LAST; i++) {
		if (str1 == NULL) {
			break;
		}

		str2 = strstr(str1, ":");
		if (str2) {
			if (i == SYMREG_COMPONENTS_REG)
				return -1;

			cnt = str2 - str1;
		} else {
			cnt = strlen(str1);
		}

		if (str2)
			*str2 = '\0';

		if (cnt > 0) {
			if (str1[cnt-1] == ']') {
				char *b_end = &str1[cnt - 1];
				char *b_start = b_end;
				while (b_start > str1) {
					if (*b_start == '[')
						break;
					b_start--;
				}

				if (b_start == str1)
					return -1;

				*b_start++ = '\0';
				*b_end = '\0';

				info[i].repl = strtoul(b_start, NULL, 10);
			}

			if (find_component(info, i, str1))
				return -1;
		}

		if (str2)
			str1 = str2 + 1;
		else
			str1 = NULL;
	}

	return 0;
}

static void print_regr(struct component_info *info, int *max_width, int query)
{
	int t = info[SYMREG_COMPONENTS_TGT].idx;
	int g = info[SYMREG_COMPONENTS_GRP].idx;
	int gr = info[SYMREG_COMPONENTS_GRP].repl;
	int r = info[SYMREG_COMPONENTS_REG].idx;
	int rr = info[SYMREG_COMPONENTS_REG].repl;
	const vtss_symreg_target_t *tgt = &vtss_symreg_targets[t];
	const vtss_symreg_reggrp_t *grp = &tgt->reggrps[g];
	const vtss_symreg_reg_t *reg = &grp->regs[r];

	unsigned int addr;

	char name[256];
	char grptmp[50];
	const char *grpname = grptmp;

	char tgttmp[50];
	const char *tgtname = tgttmp;

	if (grp->repl_cnt > 1)
		snprintf(grptmp, sizeof(grptmp), "%s[%u]", grp->name, gr);
	else
		grpname = grp->name;

	if (tgt->repl_number >= 0)
		snprintf(tgttmp, sizeof(tgttmp), "%s[%u]", tgt->name, tgt->repl_number);
	else
		tgtname = tgt->name;

	addr = tgt->base_addr + (grp->base_addr << 2) + gr * 4 * grp->repl_width + (reg->addr + rr) * 4;

	if (reg->repl_cnt > 1)
		snprintf(name, sizeof(name), "%s:%s:%s[%u]", tgtname, grpname, reg->name, rr);
	else
		snprintf(name, sizeof(name), "%s:%s:%s", tgtname, grpname, reg->name);

	if (query == SYMREG_QUERY_SZ) {
		int len = strlen(name);

		if (len > *max_width)
			*max_width = len;

		return;
	}

	if (query == SYMREG_QUERY_QUERY)
		printf("%-*s 0x%08x\n", *max_width, name, addr);
	else {
		unsigned int v = read_reg(addr);
		int j;

		printf("%-*s 0x%08x %10u ", *max_width, name, v, v);
		for (j = 31; j >= 0; j--) {
			printf("%d%s", v & (1 << j) ? 1 : 0, j == 0 ? "\n" : (j % 4) ? "" : ".");
		}
	}
}

static int print_reg(struct component_info *info, int *max_width, int query)
{
	int t = info[SYMREG_COMPONENTS_TGT].idx;
	int g = info[SYMREG_COMPONENTS_GRP].idx;
	int r = info[SYMREG_COMPONENTS_REG].idx;
	const vtss_symreg_target_t *tgt = &vtss_symreg_targets[t];
	const vtss_symreg_reggrp_t *grp = &tgt->reggrps[g];
	const vtss_symreg_reg_t *reg = &grp->regs[r];

	int repl = info[SYMREG_COMPONENTS_REG].repl;

	int rp;

	if (repl < 0) {
		for (rp = 0; rp < reg->repl_cnt; rp++) {
			info[SYMREG_COMPONENTS_REG].repl = rp;
			print_regr(info, max_width, query);
		}
		info[SYMREG_COMPONENTS_REG].repl = -1;
	} else {
		print_regr(info, max_width, query);
	}
	return 0;
}

static int print_grpr(struct component_info *info, int *max_width, int query)
{
	int t = info[SYMREG_COMPONENTS_TGT].idx;
	int g = info[SYMREG_COMPONENTS_GRP].idx;
	const vtss_symreg_target_t *tgt = &vtss_symreg_targets[t];
	const vtss_symreg_reggrp_t *grp = &tgt->reggrps[g];
	const vtss_symreg_reg_t *regs = grp->regs;

	if (info[SYMREG_COMPONENTS_REG].idx < 0) {
		int r;

		for (r = 0; regs[r].name; r++) {
			info[SYMREG_COMPONENTS_REG].idx = r;
			info[SYMREG_COMPONENTS_REG].repl = -1;
			print_reg(info, max_width, query);
		}
		info[SYMREG_COMPONENTS_REG].idx = -1;
	} else {
		print_reg(info, max_width, query);
	}

	return 0;
}

static int print_grp(struct component_info *info, int *max_width, int query)
{
	int t = info[SYMREG_COMPONENTS_TGT].idx;
	int g = info[SYMREG_COMPONENTS_GRP].idx;
	const vtss_symreg_target_t *tgt = &vtss_symreg_targets[t];
	const vtss_symreg_reggrp_t *grp = &tgt->reggrps[g];
	int repl = info[SYMREG_COMPONENTS_GRP].repl;

	int rp;

	if (repl < 0) {
		for (rp = 0; rp < grp->repl_cnt; rp++) {
			info[SYMREG_COMPONENTS_GRP].repl = rp;
			print_grpr(info, max_width, query);
		}
		info[SYMREG_COMPONENTS_GRP].repl = -1;
	} else {
		print_grpr(info, max_width, query);
	}

	return 0;
}

static int print_target(struct component_info *info, int *max_width, int query)
{
	const vtss_symreg_reggrp_t *groups;
	int t, g;

	t = info[SYMREG_COMPONENTS_TGT].idx;

	groups = vtss_symreg_targets[t].reggrps;

	if (info[SYMREG_COMPONENTS_GRP].idx < 0) {
		for (g = 0; groups[g].name; g++) {
			info[SYMREG_COMPONENTS_GRP].idx = g;
			info[SYMREG_COMPONENTS_GRP].repl = -1;
			print_grp(info, max_width, query);
		}
		info[SYMREG_COMPONENTS_GRP].idx = -1;
	} else {
		print_grp(info, max_width, query);
	}

	return 0;
}

static int print_targets(struct component_info *info, int *max_width, int query)
{
	int tgt;

	if (query == SYMREG_QUERY_QUERY)
		printf("%-*s %-10s\n", *max_width, "Register", "Address");
	else if (query == SYMREG_QUERY_READ)
		printf("%-*s %-10s %-10s 31     24 23     16 15      8 7       0\n", *max_width, "Register", "Value", "Decimal");

	tgt = info[SYMREG_COMPONENTS_TGT].idx;

	if (info[SYMREG_COMPONENTS_TGT].repl < 0) {
		int t;

		for (t = tgt; !strcmp(vtss_symreg_targets[t].name, vtss_symreg_targets[tgt].name) ; t++) {
			info[SYMREG_COMPONENTS_TGT].idx = t;
			print_target(info, max_width, query);
		}
		info[SYMREG_COMPONENTS_TGT].idx = tgt;
	} else {
		print_target(info, max_width, query);
	}

	return 0;
}

int main(int argc, char **argv) {
	int query = SYMREG_QUERY_QUERY;

	struct component_info info[SYMREG_COMPONENTS_LAST];
	int max_width = 0;

	if(argc < 3) {
		fprintf(stderr, "\nUsage:\t%s <read|query> <target>\n"
			"\ttarget : name of the target to dump\n",
			argv[0]);
		exit(1);
	}

	if (!strcmp(argv[1], "read"))
			query = SYMREG_QUERY_READ;

	if (match_regs(argv[2], info))
		exit(1);

	print_targets(info, &max_width, SYMREG_QUERY_SZ);
	print_targets(info, &max_width, query);

    close(fd);
    return 0;
}
