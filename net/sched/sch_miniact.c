// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2018 Covalent IO, Inc. http://covalent.io

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>
#include <linux/bpf.h>

#include <net/netlink.h>
#include <net/pkt_sched.h>
#include <net/pkt_cls.h>

#define MINIACT_MAX_PROGS	16

struct miniact_miniq {
	struct mini_Qdisc_pair miniqp;
	bool offloaded;
};

struct miniact_data {
	struct miniact_miniq ingress;
	struct miniact_miniq egress;
	u32 gencnt;
};

enum miniact_type {
	MINIACT_INGRESS,
	MINIACT_EGRESS,
};

struct miniact_swap_req {
	enum miniact_type type;
	struct bpf_prog *prog;
	struct bpf_prog_array *array;
	bool offload;
};

static void miniact_put_any(bool single, struct bpf_prog *prog,
			    struct bpf_prog_array *array)
{
	if (!prog && !array)
		return;
	if (single) {
		bpf_prog_put(prog);
	} else {
		struct bpf_prog **pprog = array->progs, *prog;

		while ((prog = *pprog)) {
			bpf_prog_put(prog);
			pprog++;
		}
		bpf_prog_array_free_no_rcu(array);
	}
}

static void miniact_rcu_cb(struct mini_Qdisc *miniq)
{
	miniact_put_any(miniq->single, miniq->entry, miniq->entry);
}

static void miniact_set_miniq_cbs(struct Qdisc *qdisc,
				  struct mini_Qdisc_pair *miniqp)
{
	mini_qdisc_pair_set_cbs(miniqp, miniact_rcu_cb);
}

static bool miniact_prep_offload(struct tc_bpf_offload *off,
				 struct miniact_miniq *mq,
				 struct miniact_swap_req *req,
				 struct netlink_ext_ack *extack)
{
	struct mini_Qdisc *miniq = mini_qdisc_get_active(&mq->miniqp);

	memset(off, 0, sizeof(*off));
	if (req->prog && bpf_prog_is_dev_bound(req->prog->aux))
		off->prog = req->prog;
	if (miniq && miniq->single)
		off->oldprog = miniq->entry;
	off->extack = extack;

	return off->prog;
}

static int miniact_swap_offload(struct net_device *dev,
				struct miniact_miniq *mq,
				struct tc_bpf_offload *off)
{
	int ret = dev->netdev_ops->ndo_setup_tc(dev, TC_SETUP_BPF, &off);

	if (!ret)
		mq->offloaded = off->prog;
	return ret;
}

static int miniact_swap_one(struct net_device *dev, struct miniact_miniq *mq,
			    struct miniact_swap_req *req,
			    struct netlink_ext_ack *extack)
{
	bool before, single = !!req->prog || (!req->prog && !req->array);
	bool swap_offload = mq->offloaded || req->offload;
	struct tc_bpf_offload off;
	void *entry;
	int ret = 0;

	ASSERT_RTNL();

	before = miniact_prep_offload(&off, mq, req, extack);
	if (before && swap_offload)
		ret = miniact_swap_offload(dev, mq, &off);
	if (!ret) {
		entry = req->prog;
		if (!single)
			entry = req->array;
		mini_qdisc_pair_swap(&mq->miniqp, NULL, entry, single);
		if (!before && swap_offload)
			WARN_ON_ONCE(miniact_swap_offload(dev, mq, &off));
	}

	return ret;
}

static int miniact_dump_progs(struct sk_buff *skb,
			      const struct miniact_miniq *miniact,
			      const struct mini_Qdisc *miniq)
{
	u32 ids[MINIACT_MAX_PROGS] = {};
	u64 flags = 0;
	int num = 0;

	if (miniq->single) {
		struct bpf_prog *prog = miniq->entry;

		ids[num++] = prog->aux->id;
	} else {
		struct bpf_prog_array *array = miniq->entry;
		struct bpf_prog *prog, **pprog;

		for (pprog = array->progs; (prog = *pprog); pprog++)
			ids[num++] = prog->aux->id;
	}

	if (nla_put(skb, TCA_MINIACT_PARMS_PROGS, num * sizeof(ids[0]), ids))
		return -1;
	if (miniact->offloaded)
		flags |= TCA_MINIACT_OFFLOAD;
	if (flags && nla_put_u32(skb, TCA_MINIACT_PARMS_FLAGS, flags))
		return -1;

	return 0;
}

static int miniact_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct miniact_data *q = qdisc_priv(sch);
	struct nlattr *nest, *nest_inner;
	struct mini_Qdisc *miniq;

	ASSERT_RTNL();

	nest = nla_nest_start(skb, TCA_OPTIONS);
	if (nest == NULL)
		goto nla_put_failure;

	if (nla_put_u32(skb, TCA_MINIACT_PARMS_GENCNT, q->gencnt))
		goto nla_put_failure;

	nest_inner = nla_nest_start(skb, TCA_MINIACT_PARMS_INGRESS);
	if (nest_inner == NULL)
		goto nla_put_failure;
	miniq = mini_qdisc_get_active(&q->ingress.miniqp);
	if (miniq && miniact_dump_progs(skb, &q->ingress, miniq))
		goto nla_put_failure;
	nla_nest_end(skb, nest_inner);

	nest_inner = nla_nest_start(skb, TCA_MINIACT_PARMS_EGRESS);
	if (nest_inner == NULL)
		goto nla_put_failure;
	miniq = mini_qdisc_get_active(&q->egress.miniqp);
	if (miniq && miniact_dump_progs(skb, &q->egress, miniq))
		goto nla_put_failure;
	nla_nest_end(skb, nest_inner);

	return nla_nest_end(skb, nest);

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -1;
}

static const struct nla_policy bpf_parms_policy[TCA_MINIACT_PARMS_MAX + 1] = {
	[TCA_MINIACT_PARMS_PROGS]	= {
		.type	= NLA_BINARY,
		.len	= MINIACT_MAX_PROGS * sizeof(u32),
	},
	[TCA_MINIACT_PARMS_FLAGS]	= { .type = NLA_U32 },
};

static const struct nla_policy bpf_policy[TCA_MINIACT_MAX + 1] = {
	[TCA_MINIACT_PARMS_INGRESS]	= { .type = NLA_NESTED },
	[TCA_MINIACT_PARMS_EGRESS]	= { .type = NLA_NESTED },
	[TCA_MINIACT_PARMS_GENCNT]	= { .type = NLA_U32 },
};

static int miniact_get_progs_single(struct net_device *dev,
				    struct miniact_swap_req *req,
				    struct nlattr *progs)
{
	int prog_fd = nla_get_u32(progs);

	req->array = NULL;
	req->prog  = bpf_prog_get_type_dev(prog_fd, BPF_PROG_TYPE_SCHED_CLS,
					   req->offload);
	if (!IS_ERR(req->prog) && req->offload &&
	    !bpf_prog_is_dev_bound(req->prog->aux)) {
		bpf_prog_put(req->prog);
		req->prog = ERR_PTR(-EINVAL);
	}

	return PTR_ERR_OR_ZERO(req->prog);
}

static int miniact_get_progs_array(struct miniact_swap_req *req,
				   struct nlattr *progs, int progs_num)
{
	u32 *progs_raw = nla_data(progs);
	struct bpf_prog *tmp;
	int i, ret;

	req->prog  = NULL;
	req->array = bpf_prog_array_alloc_no_rcu(progs_num, GFP_KERNEL);
	if (!req->array)
		return -ENOMEM;

	for (i = 0; i < progs_num; i++) {
		tmp = bpf_prog_get_type(progs_raw[i], BPF_PROG_TYPE_SCHED_CLS);
		if (IS_ERR(tmp)) {
			ret = PTR_ERR(tmp);
			goto teardown;
		}

		req->array->progs[i] = tmp;
	}

	return 0;
teardown:
	for (i = 0; i < progs_num; i++) {
		tmp = req->array->progs[i];
		if (!tmp)
			break;
		bpf_prog_put(tmp);
	}

	bpf_prog_array_free_no_rcu(req->array);
	return ret;
}

static int miniact_get_progs(struct net_device *dev, struct nlattr *opt,
			     struct miniact_swap_req *req,
			     struct netlink_ext_ack *extack)
{
	struct nlattr *tb[TCA_MINIACT_PARMS_MAX + 1];
	struct nlattr *progs;
	int ret, progs_num;
	u64 flags;

	ret = nla_parse_nested(tb, TCA_MINIACT_PARMS_MAX, opt,
			       bpf_parms_policy, NULL);
	if (ret < 0)
		return ret;
	if (!tb[TCA_MINIACT_PARMS_PROGS] && tb[TCA_MINIACT_PARMS_FLAGS])
		return -EINVAL;
	if (!tb[TCA_MINIACT_PARMS_PROGS])
		return 0;

	progs = tb[TCA_MINIACT_PARMS_PROGS];
	if (nla_len(progs) < sizeof(u32) || nla_len(progs) % sizeof(u32))
		return -EINVAL;

	progs_num = nla_len(progs) / sizeof(u32);
	if (tb[TCA_MINIACT_PARMS_FLAGS]) {
		flags = nla_get_u32(tb[TCA_MINIACT_PARMS_FLAGS]);
		if (flags & ~TCA_MINIACT_OFFLOAD)
			return -EINVAL;

		req->offload = flags & TCA_MINIACT_OFFLOAD;
		if (req->offload) {
			if (!dev->netdev_ops->ndo_setup_tc) {
				NL_SET_ERR_MSG_MOD(extack,
						   "offload not supported for netdevice");
				return -EOPNOTSUPP;
			}
			if (progs_num != 1) {
				NL_SET_ERR_MSG_MOD(extack,
						   "offload not supported in multi-prog mode");
				return -EOPNOTSUPP;
			}
			if (req->type != MINIACT_INGRESS) {
				NL_SET_ERR_MSG_MOD(extack,
						   "offload not supported on egress");
				return -EOPNOTSUPP;
			}
		}
	}

	if (progs_num == 1)
		return miniact_get_progs_single(dev, req, progs);
	else
		return miniact_get_progs_array(req, progs, progs_num);
}

static int miniact_change(struct Qdisc *sch, struct nlattr *opt,
			  struct netlink_ext_ack *extack)
{
	bool swap_ingress = false, swap_egress = false;
	struct miniact_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct nlattr *tb[TCA_MINIACT_MAX + 1];
	struct miniact_swap_req ingress = {
		.type = MINIACT_INGRESS,
	}, egress = {
		.type = MINIACT_EGRESS,
	};
	int ret;

	ASSERT_RTNL();
	if (!opt) {
		NL_SET_ERR_MSG_MOD(extack, "no miniact config provided");
		return -EINVAL;
	}

	ret = nla_parse_nested(tb, TCA_MINIACT_MAX, opt, bpf_policy, NULL);
	if (ret < 0)
		return ret;
	if (!tb[TCA_MINIACT_PARMS_INGRESS] && !tb[TCA_MINIACT_PARMS_EGRESS]) {
		NL_SET_ERR_MSG_MOD(extack, "no miniact config provided");
		return -EINVAL;
	}

	if (tb[TCA_MINIACT_PARMS_GENCNT]) {
		u32 gencnt = nla_get_u32(tb[TCA_MINIACT_PARMS_GENCNT]);

		if (q->gencnt != gencnt) {
			NL_SET_ERR_MSG_MOD(extack, "generation count mismatch");
			return -ESTALE;
		}
	}

	if (tb[TCA_MINIACT_PARMS_INGRESS]) {
		ret = miniact_get_progs(dev, tb[TCA_MINIACT_PARMS_INGRESS],
					&ingress, extack);
		if (ret)
			return ret;
		swap_ingress = true;
	}
	if (tb[TCA_MINIACT_PARMS_EGRESS]) {
		ret = miniact_get_progs(dev, tb[TCA_MINIACT_PARMS_EGRESS],
					&egress, extack);
		if (ret) {
			if (swap_ingress)
				miniact_put_any(!!ingress.prog, ingress.prog,
						ingress.array);
			return ret;
		}
		swap_egress = true;
	}

	if (swap_ingress)
		ret = miniact_swap_one(dev, &q->ingress, &ingress, extack);
	if (swap_egress && !ret) {
		ret = miniact_swap_one(dev, &q->egress, &egress, extack);
		WARN_ON_ONCE(ret);
	}
	if (!ret)
		q->gencnt++;
	return ret;
}

static int miniact_init(struct Qdisc *sch, struct nlattr *opt,
			struct netlink_ext_ack *extack)
{
	struct miniact_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);

	mini_qdisc_pair_init(&q->ingress.miniqp, sch, &dev->miniq_ingress);
	mini_qdisc_pair_init(&q->egress.miniqp, sch, &dev->miniq_egress);

	net_inc_ingress_queue();
	net_inc_egress_queue();

	return miniact_change(sch, opt, extack);
}

static void miniact_destroy(struct Qdisc *sch)
{
	struct miniact_data *q = qdisc_priv(sch);
	struct net_device *dev = qdisc_dev(sch);
	struct miniact_swap_req ingress = {
		.type = MINIACT_INGRESS,
	}, egress = {
		.type = MINIACT_EGRESS,
	};

	net_dec_ingress_queue();
	net_dec_egress_queue();

	miniact_swap_one(dev, &q->ingress, &ingress, NULL);
	miniact_swap_one(dev, &q->egress, &egress, NULL);

	mini_qdisc_pair_destroy();
}

static struct Qdisc_ops miniact_qdisc_ops __read_mostly = {
	.id		= "miniact",
	.priv_size	= sizeof(struct miniact_data),
	.static_flags	= TCQ_F_CPUSTATS,
	.init		= miniact_init,
	.set_miniq_cbs	= miniact_set_miniq_cbs,
	.destroy	= miniact_destroy,
	.change		= miniact_change,
	.dump		= miniact_dump,
	.owner		= THIS_MODULE,
};

static int __init miniact_module_init(void)
{
	return register_qdisc(&miniact_qdisc_ops);
}

static void __exit miniact_module_exit(void)
{
	unregister_qdisc(&miniact_qdisc_ops);
}

module_init(miniact_module_init);
module_exit(miniact_module_exit);

MODULE_ALIAS("sch_miniact");
MODULE_AUTHOR("Daniel Borkmann");
MODULE_LICENSE("GPL");
