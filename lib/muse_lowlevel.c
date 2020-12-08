/*
 * MUSE: MTD in userspace
 * Copyright (C) 2020 sigma star gmbh
 * Author: Richard Weinberger <richard@nod.at>
 *
 * This code is based on CUSE:
 * CUSE: Character device in Userspace
 * Copyright (C) 2008       SUSE Linux Products GmbH
 * Copyright (C) 2008       Tejun Heo <teheo@suse.de>
 *
 * This program can be distributed under the terms of the GNU LGPLv2.
 * See the file COPYING.LIB.
 */

#define _GNU_SOURCE

#include "config.h"
#include "fuse_i.h"
#include "fuse_kernel.h"
#include "fuse_opt.h"
#include "muse_lowlevel.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct muse_data {
	const struct muse_lowlevel_ops *mlop;
	size_t params_len;
	char *params;
};

static const struct muse_lowlevel_ops *req_mlop(fuse_req_t req)
{
	return req->se->muse_data->mlop;
}

static void muse_fll_erase(fuse_req_t req, uint64_t addr, uint64_t len)
{
	req_mlop(req)->erase(req, addr, len);
}

static void muse_fll_read(fuse_req_t req, uint64_t addr, uint64_t len, uint32_t flags)
{
	req_mlop(req)->read(req, addr, len, flags);
}

static void muse_fll_write(fuse_req_t req, uint64_t addr, uint64_t len, uint32_t flags, const char *buf)
{
	req_mlop(req)->write(req, addr, len, flags, buf);
}

static void muse_fll_sync(fuse_req_t req)
{
	req_mlop(req)->sync(req);
}

static void muse_fll_block_isbad(fuse_req_t req, uint64_t addr)
{
	req_mlop(req)->block_isbad(req, addr);
}

static void muse_fll_block_markbad(fuse_req_t req, uint64_t addr)
{
	req_mlop(req)->block_markbad(req, addr);
}

static int create_param_page(const struct mtd_desc *desc, char **buf)
{
	int len, i;
	char *s;

	len = asprintf(buf,
		"TYPE=%u\t"
		"FLAGS=%u\t"
		"SIZE=%lu\t"
		"WRITESIZE=%u\t"
		"WRITEBUFSIZE=%u\t"
		"ERASESIZE=%u\t"
		"OOBSIZE=%u\t"
		"OOBAVAIL=%u\t"
		"SUBPAGESHIFT=%u\t"
		"NAME=muse-pid%u\t"
		"PARTSCMDLINE=%s\t",
		desc->type, desc->flags, desc->size, desc->writesize,
		desc->writebufsize, desc->erasesize, desc->oobsize,
		desc->oobavail, desc->subpage_shift, getpid(),
		desc->mtdparts ?: ""
	);

	s = *buf;

	if (len == -1)
		return -errno;

	if (len >= MUSE_INIT_INFO_MAX) {
		free(s);
		return -ENOMEM;
	}

	/*
	 * Kernel side of MUSE wants each key/value pair separated by a NUL byte.
	 */
	for (i = 0; i < len; i++) {
		if (s[i] == '\t')
			s[i] = '\0';
	}

	return len;
}

static struct muse_data *muse_prep_data(const struct muse_setup_info *mi,
					const struct muse_lowlevel_ops *mlop)
{
	struct muse_data *md;
	char *params;
	int ret;

	ret = create_param_page(&mi->mtd_desc, &params);
	if (ret <= 0) {
		fuse_log(FUSE_LOG_ERR, "muse: failed to create parameter page\n");
		return NULL;
	}

	md = calloc(1, sizeof(*md));
	if (!md) {
		free(params);
		fuse_log(FUSE_LOG_ERR, "muse: failed to allocate muse_data\n");
		return NULL;
	}

	//memcpy(&md->mlop, mlop, sizeof(md->mlop));
	md->mlop = mlop;
	md->params = params;
	md->params_len = ret;

	return md;
}

struct fuse_session *muse_lowlevel_new(const struct muse_setup_info *mi,
				       const struct muse_lowlevel_ops *mlop)
{
	struct fuse_lowlevel_ops lop;
	struct muse_data *md;
	struct fuse_session *se;

	/*
	 * Fake argc/argv for FUSE. We don't need any parameter parsing from it.
	 */
	struct fuse_args args = FUSE_ARGS_INIT(1, (char **)((const char *[]){"muse"}));

	md = muse_prep_data(mi, mlop);
	if (!md)
		return NULL;

	memset(&lop, 0, sizeof(lop));
	lop.muse_read = mlop->read ? muse_fll_read : NULL;
	lop.muse_write = mlop->write ? muse_fll_write : NULL;
	lop.muse_erase = mlop->erase ? muse_fll_erase : NULL;
	lop.muse_sync = mlop->sync ? muse_fll_sync : NULL;
	lop.muse_block_isbad = mlop->block_isbad ? muse_fll_block_isbad : NULL;
	lop.muse_block_markbad = mlop->block_markbad ? muse_fll_block_markbad : NULL;

	se = fuse_session_new(&args, &lop, sizeof(lop), NULL);
	if (!se) {
		free(md->params);
		free(md);
		return NULL;
	}
	se->muse_data = md;

	return se;
}

int muse_send_read_reply(fuse_req_t req, int error, const void *buf,
		      size_t bufsize)
{
	struct iovec iov[3];
	struct muse_read_out out =  {
		.len = bufsize,
		.soft_error = 0,
	};
	int ret;

	iov[1].iov_base = (void *)&out;
	iov[1].iov_len = sizeof(out);

	iov[2].iov_base = (void *)buf;
	iov[2].iov_len = bufsize;

	ret = fuse_send_reply_iov_nofree(req, error, iov, 3);
	fuse_free_req(req);

	return ret;
}

int muse_send_write_reply(fuse_req_t req, int error, size_t len)
{
	struct iovec iov[2];
	struct muse_write_out out =  {
		.len = len,
		.soft_error = 0,
	};
	int ret;

	iov[1].iov_base = (void *)&out;
	iov[1].iov_len = sizeof(out);

	ret = fuse_send_reply_iov_nofree(req, error, iov, 2);
	fuse_free_req(req);

	return ret;
}

int muse_send_block_markbad_reply(fuse_req_t req, int error, int isbad)
{
	struct iovec iov[2];
	struct muse_isbad_out out =  {
		.result = isbad,
	};
	int ret;

	iov[1].iov_base = (void *)&out;
	iov[1].iov_len = sizeof(out);

	ret = fuse_send_reply_iov_nofree(req, error, iov, 2);
	fuse_free_req(req);

	return ret;
}

static int muse_reply_init(fuse_req_t req, struct muse_init_out *arg,  struct muse_data *md)
{
	struct iovec iov[3];

	iov[1].iov_base = arg;
	iov[1].iov_len = sizeof(struct muse_init_out);
	iov[2].iov_base = md->params;
	iov[2].iov_len = md->params_len;

	return fuse_send_reply_iov_nofree(req, 0, iov, 3);
}

void muse_lowlevel_init(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct fuse_init_in *arg = (struct fuse_init_in *) inarg;
	struct muse_init_out outarg;
	struct fuse_session *se = req->se;
	struct muse_data *md = se->muse_data;
	size_t bufsize = se->bufsize;

	(void) nodeid;
	if (se->debug)
		fuse_log(FUSE_LOG_DEBUG, "MUSE_INIT: %u.%u\n", arg->major, arg->minor);

	se->conn.proto_major = arg->major;
	se->conn.proto_minor = arg->minor;
	se->conn.capable = 0;
	se->conn.want = 0;

	if (arg->major < 7) {
		fuse_log(FUSE_LOG_ERR, "muse: unsupported protocol version: %u.%u\n",
			arg->major, arg->minor);
		fuse_reply_err(req, EPROTO);
		return;
	}

	if (bufsize < FUSE_MIN_READ_BUFFER) {
		fuse_log(FUSE_LOG_ERR, "muse: warning: buffer size too small: %zu\n",
			bufsize);
		bufsize = FUSE_MIN_READ_BUFFER;
	}

	bufsize -= MUSE_INIT_INFO_MAX;
	if (bufsize < se->conn.max_write)
		se->conn.max_write = bufsize;

	se->got_init = 1;

	memset(&outarg, 0, sizeof(outarg));
	outarg.fuse_major = FUSE_KERNEL_VERSION;
	outarg.fuse_minor = FUSE_KERNEL_MINOR_VERSION;

	/*
	 * Use the same buffer size for both read and write.
	 * It is 1MiB. This works for every MTD.
	 */
	outarg.max_write = se->conn.max_write;
	outarg.max_read = se->conn.max_write;

	if (se->debug) {
		fuse_log(FUSE_LOG_DEBUG, "   MUSE_INIT: %u.%u\n",
			 outarg.fuse_major, outarg.fuse_minor);
		fuse_log(FUSE_LOG_DEBUG, "   max_read=0x%08x\n", outarg.max_read);
		fuse_log(FUSE_LOG_DEBUG, "   max_write=0x%08x\n", outarg.max_write);
	}

	muse_reply_init(req, &outarg, md);
	fuse_free_req(req);

	/*
	 * We don't need params anymore.
	 */
	free(md->params);
	md->params = NULL;
	md->params_len = 0;
}

void do_muse_erase(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct muse_erase_in *arg = (struct muse_erase_in *)inarg;

	(void)nodeid;

	if (req->se->op.muse_erase)
		req->se->op.muse_erase(req, arg->addr, arg->len);
	else
		fuse_reply_err(req, ENOSYS);
}

void do_muse_isbad(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct muse_isbad_in *arg = (struct muse_isbad_in *)inarg;

	(void)nodeid;

	if (req->se->op.muse_block_isbad)
		req->se->op.muse_block_isbad(req, arg->addr);
	else
		fuse_reply_err(req, ENOSYS);
}

void do_muse_markbad(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct muse_markbad_in *arg = (struct muse_markbad_in *)inarg;

	(void)nodeid;

	if (req->se->op.muse_block_markbad)
		req->se->op.muse_block_markbad(req, arg->addr);
	else
		fuse_reply_err(req, ENOSYS);
}

void do_muse_read(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct muse_read_in *arg = (struct muse_read_in *) inarg;

	(void)nodeid;

	if (req->se->op.muse_read)
		req->se->op.muse_read(req, arg->addr, arg->len, arg->flags);
	else
		fuse_reply_err(req, ENOSYS);
}

void do_muse_write(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	struct muse_write_in *arg = (struct muse_write_in *) inarg;
	const char *buf = inarg + sizeof(*arg);

	(void)nodeid;

	if (req->se->op.muse_write)
		req->se->op.muse_write(req, arg->addr, arg->len, arg->flags, buf);
	else
		fuse_reply_err(req, ENOSYS);
}

void do_muse_sync(fuse_req_t req, fuse_ino_t nodeid, const void *inarg)
{
	(void)nodeid;
	(void)inarg;

	if (req->se->op.muse_sync)
		req->se->op.muse_sync(req);
	else
		fuse_reply_err(req, ENOSYS);
}

struct fuse_session *muse_lowlevel_setup(const struct muse_setup_info *mi,
					 const struct muse_lowlevel_ops *mlop)
{
	const char *devname = "/dev/muse";
	struct fuse_session *se;
	int fd;
	int res;

	/*
	 * Make sure file descriptors 0, 1 and 2 are open, otherwise chaos
	 * would ensue.
	 */
	do {
		fd = open("/dev/null", O_RDWR);
		if (fd > 2)
			close(fd);
	} while (fd >= 0 && fd <= 2);

	se = muse_lowlevel_new(mi, mlop);
	if (se == NULL)
		goto out1;

	fd = open(devname, O_RDWR);
	if (fd == -1) {
		if (errno == ENODEV || errno == ENOENT)
			fuse_log(FUSE_LOG_ERR, "muse: %s not found, try 'modprobe muse' first\n", devname);
		else
			fuse_log(FUSE_LOG_ERR, "muse: failed to open %s: %s\n",
				devname, strerror(errno));
		goto err_se;
	}
	se->fd = fd;

	res = fuse_set_signal_handlers(se);
	if (res == -1)
		goto err_se;

	res = fuse_daemonize(1);
	if (res == -1)
		goto err_sig;

	return se;

err_sig:
	fuse_remove_signal_handlers(se);
err_se:
	fuse_session_destroy(se);
out1:
	return NULL;
}

void muse_lowlevel_teardown(struct fuse_session *se)
{
	fuse_remove_signal_handlers(se);
	fuse_session_destroy(se);
}

int muse_lowlevel_main(const struct muse_setup_info *mi, const struct muse_lowlevel_ops *mlop)
{
	struct fuse_session *se;
	int res;

	se = muse_lowlevel_setup(mi, mlop);
	if (se == NULL)
		return 1;

	if (mi->multithreaded) {
		struct fuse_loop_config config;
		config.clone_fd = 0;
		config.max_idle_threads = 10;
		res = fuse_session_loop_mt_32(se, &config);
	} else {
		res = fuse_session_loop(se);
	}

	muse_lowlevel_teardown(se);
	if (res == -1)
		return 1;

	return 0;
}
