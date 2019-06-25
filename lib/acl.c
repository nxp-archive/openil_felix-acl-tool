/*
 * License: Dual MIT/GPL
 * Copyright (c) 2017 Microsemi Corporation
 */

#include "felix/acl.h"
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/netlink.h>

#define MSCC_EF_POLICY_DECLARE
#include <linux/tsn.h>
#include <felix/common.h>
#include <felix/acl.h>

struct nla_policy mscc_ef_acl_genl_policy[SWITCH_ACL_ATTR_MAX + 1] = {
	[SWITCH_ACL_ATTR_UNSPEC] = { .type = NLA_UNSPEC },
	[SWITCH_ACL_ATTR_IFNAME] = { .type = NLA_STRING },
	[SWITCH_ACL_ATTR_ID] = { .type = NLA_U32 },

	[SWITCH_ACL_ATTR_ACTION] = { .type = NLA_BINARY,
				      .minlen = sizeof(felix_acl_action_t),
				      .maxlen = sizeof(felix_acl_action_t) },
	[SWITCH_ACL_ATTR_CNT] = { .type = NLA_U32 },
	[SWITCH_ACL_ATTR_ACE] = { .type = NLA_BINARY,
				   .minlen = sizeof(felix_ace_t),
				   .maxlen = sizeof(felix_ace_t) },
};

struct cb_info {
	int ack;
	int valid;
	int finish;
	int err;
	int err_code;
};

static int cb_ack(struct nl_msg *msg, void *arg)
{
	// printf("cb-ack\n");
	struct cb_info *info = arg;
	info->ack = 1;
	return 0;
}

static int cb_valid(struct nl_msg *msg, void *arg)
{
	// printf("cb-valid\n");
	struct cb_info *info = arg;
	info->valid = 1;
	return 0;
}

static int cb_finish(struct nl_msg *msg, void *arg)
{
	// printf("cb-finish\n");
	struct cb_info *info = arg;
	info->finish = 1;
	return 0;
}

int cb_err(struct sockaddr_nl *nla, struct nlmsgerr *nlerr, void *arg)
{
	// printf("cb-err\n");
	struct cb_info *info = arg;
	info->err = 1;
	info->err_code = nlerr->error;

	return 0;
}

static int req_set(struct nl_msg *msg)
{
	int err = 0, fam;
	struct nl_sock *sk;
	struct cb_info info;

	sk = nl_socket_alloc();

	nl_socket_modify_cb(sk, NL_CB_ACK, NL_CB_CUSTOM, cb_ack, &info);
	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, cb_valid, &info);
	nl_socket_modify_cb(sk, NL_CB_FINISH, NL_CB_CUSTOM, cb_finish, &info);
	nl_socket_modify_err_cb(sk, NL_CB_CUSTOM, cb_err, &info);

	err = genl_connect(sk);
	if (err < 0) {
		printf("genl_connect failed\n");
		goto error;
	}

	fam = genl_ctrl_resolve(sk, "felix");
	if (fam < 0) {
		printf("Failed to resolve generic netlink family\n");
		goto error;
	}
	nlmsg_hdr(msg)->nlmsg_type = fam;

	err = nl_send_auto(sk, msg);
	if (err < 0) {
		printf("nl_send_auto failed\n");
		goto error;
	}

	err = nl_recvmsgs_default(sk);
	if (err < 0) {
		printf("nl_send_auto failed\n");
		goto error;
	}

	if (info.err)
		err = info.err_code;

error:
	nl_socket_free(sk);
	return err;
}

static struct nl_msg *alloc_msg_req(int cmd)
{
	struct nl_msg *msg = nlmsg_alloc();

	genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ,
		    999 /* Family updated later */, 0 /*Custom header length*/,
		    NLM_F_REQUEST | NLM_F_ACK, cmd, 1 /* Version */);

	return msg;
}

int felix_acl_port_action_conf_set(char *portname,
				   const felix_acl_action_t *const conf)
{
/*
	struct nl_sock *sk;
	struct nl_msg *msg;
	struct nlattr *attr;
	int rc, i;

	rc = mscc_genl_start(TSN_GENL_NAME,
			     SWITCH_CMD_ACL_ACTION_CONF_SET,
			     TSN_GENL_VERSION, &sk, &msg);
	if (rc < 0) {
		printf("mscc_genl_start() failed\n");
		return rc;
	}

        NLA_PUT_STRING(msg, SWITCH_ACL_ATTR_IFNAME, portname);
	NLA_PUT(msg, SWITCH_ACL_ATTR_ACTION, sizeof(*conf), conf);

	rc = nl_send_auto(sk, msg);
	if (rc < 0) {
		printf("nl_send_auto() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	rc = nl_recvmsgs_default(sk);
	if (rc < 0) {
		printf("nl_recvmsgs_default() failed, rc %d\n", rc);
	}

nla_put_failure:
	nlmsg_free(msg);
	nl_socket_free(sk);
	return rc;
*/
	return -1;
}

int felix_acl_cnt_get_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *hdr = nlmsg_data(nlmsg_hdr(msg));
	uint32_t *cnt = arg;
	struct nlattr *attrs[SWITCH_ACL_ATTR_MAX + 1];
	struct nlattr *attr;

	if (nla_parse(attrs, SWITCH_ACL_ATTR_MAX, genlmsg_attrdata(hdr, 0),
		      genlmsg_attrlen(hdr, 0), mscc_ef_acl_genl_policy)) {
		printf("nla_parse() failed\n");
		return NL_STOP;
	}
	if (!attrs[SWITCH_ACL_ATTR_CNT]) {
		printf("MSCC_EF_ATTR_ACL_CNT not found\n");
		return -1;
	}

	*cnt = nla_get_u32(attrs[SWITCH_ACL_ATTR_CNT]);

	return NL_OK;
}

int felix_acl_port_counter_get(char *portname, uint32_t *const counter)
{
/*
	struct nl_sock *sk;
	struct nl_msg *msg;
	int rc, i;
	uint32_t tmp_cnt;

	rc = mscc_genl_start(TSN_GENL_NAME, SWITCH_CMD_ACL_PORT_COUNTER_GET,
			     TSN_GENL_VERSION, &sk, &msg);

	if (rc < 0) {
		printf("mscc_genl_start() failed\n");
		return rc;
	}

	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, felix_acl_cnt_get_cb,
			    &tmp_cnt);

	NLA_PUT_STRING(msg, SWITCH_ACL_ATTR_IFNAME, portname);

	rc = nl_send_auto(sk, msg);
	if (rc < 0) {
		printf("nl_send_auto() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	rc = nl_recvmsgs_default(sk);
	if (rc < 0) {
		printf("nl_recvmsgs_default() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	*counter = tmp_cnt;

nla_put_failure:
	nlmsg_free(msg);
	nl_socket_free(sk);
	return rc;
*/
	return -1;
}

int felix_acl_port_counter_clear(felix_inst_t *inst, int ifindex)
{
	return -1;
}

int felix_ace_init(felix_inst_t *inst, const felix_ace_type_t type,
		   felix_ace_t *const ace)
{
	return -1;
}

int felix_ace_add(char *portname, const felix_ace_t *const ace,
		  felix_ace_id_t id_next)
{
	struct nl_sock *sk;
	struct nl_msg *msg;
	struct nlattr *attr;
	int rc, i;

	rc = mscc_genl_start(TSN_GENL_NAME, SWITCH_CMD_ACL_ADD,
			     TSN_GENL_VERSION, &sk, &msg);
	if (rc < 0) {
		printf("mscc_genl_start() failed\n");
		return rc;
	}

	NLA_PUT_STRING(msg, SWITCH_ACL_ATTR_IFNAME, portname);
	NLA_PUT(msg, SWITCH_ACL_ATTR_ACE, sizeof(*ace), ace);

	rc = nl_send_auto(sk, msg);
	if (rc < 0) {
		printf("nl_send_auto() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	rc = nl_recvmsgs_default(sk);
	if (rc < 0) {
		printf("nl_recvmsgs_default() failed, rc %d\n", rc);
	}

nla_put_failure:
	nlmsg_free(msg);
	nl_socket_free(sk);
	return rc;
}

int felix_ace_del(char *portname, felix_ace_id_t id)
{
	struct nl_sock *sk;
	struct nl_msg *msg;
	struct nlattr *attr;
	int rc, i;

	rc = mscc_genl_start(TSN_GENL_NAME, SWITCH_CMD_ACL_DEL,
			     TSN_GENL_VERSION, &sk, &msg);
	if (rc < 0) {
		printf("mscc_genl_start() failed\n");
		return rc;
	}

	NLA_PUT_STRING(msg, SWITCH_ACL_ATTR_IFNAME, portname);
	NLA_PUT_U32(msg, SWITCH_ACL_ATTR_ID, id);

	rc = nl_send_auto(sk, msg);
	if (rc < 0) {
		printf("nl_send_auto() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	rc = nl_recvmsgs_default(sk);
	if (rc < 0) {
		printf("nl_recvmsgs_default() failed, rc %d\n", rc);
	}

nla_put_failure:
	nlmsg_free(msg);
	nl_socket_free(sk);
	return rc;
}

int felix_ace_counter_get(char *portname, felix_ace_id_t id,
			  uint32_t *const counter)
{
	struct nl_sock *sk;
	struct nl_msg *msg;
	int rc, i;
	uint32_t tmp_cnt;

	rc = mscc_genl_start(TSN_GENL_NAME, SWITCH_CMD_ACL_GET,
			     TSN_GENL_VERSION, &sk, &msg);

	if (rc < 0) {
		printf("mscc_genl_start() failed\n");
		return rc;
	}

	nl_socket_modify_cb(sk, NL_CB_VALID, NL_CB_CUSTOM, felix_acl_cnt_get_cb,
			    &tmp_cnt);

	NLA_PUT_STRING(msg, SWITCH_ACL_ATTR_IFNAME, portname);
	NLA_PUT_U32(msg, SWITCH_ACL_ATTR_ID, id);

	rc = nl_send_auto(sk, msg);
	if (rc < 0) {
		printf("nl_send_auto() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	rc = nl_recvmsgs_default(sk);
	if (rc < 0) {
		printf("nl_recvmsgs_default() failed, rc %d\n", rc);
		goto nla_put_failure;
	}

	*counter = tmp_cnt;

nla_put_failure:
	nlmsg_free(msg);
	nl_socket_free(sk);
	return rc;
}

int felix_ace_counter_clear(char *portname, felix_ace_id_t id)
{
	return -1;
}
