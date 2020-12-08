#define _GNU_SOURCE
#define FUSE_USE_VERSION 33

#include <fuse_opt.h>
#include <mtd/mtd-abi.h>
#include <muse_lowlevel.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *mtdbuf;

static unsigned int erasesize = 128 << 10; /* 128KiB */ 
static unsigned int writesize = 1; 
static unsigned int writebufsize = 64;
static unsigned int mtdsize = 4 << 20; /* 4MiB */

static void muse_mtd_read(fuse_req_t req, uint64_t addr, uint64_t len, uint32_t flags)
{
	(void)flags;

	muse_send_read_reply(req, 0, mtdbuf + addr, len);
}

static void muse_mtd_write(fuse_req_t req, uint64_t addr, uint64_t len, uint32_t flags, const char *buf)
{
	(void)flags;

	memcpy(mtdbuf + addr, buf, len);
	muse_send_write_reply(req, 0, len);
}

static void muse_mtd_erase(fuse_req_t req, uint64_t addr, uint64_t len)
{
	memset(mtdbuf + addr, 0xff, len);
	fuse_reply_err(req, 0);
}

static void muse_mtd_sync(fuse_req_t req)
{
	/* NOP */
	fuse_reply_err(req, 0);
}

static struct muse_setup_info *build_muse_setup_info(void)
{
	struct muse_setup_info *mi = calloc(1, sizeof(*mi));

	mi->mtd_desc.type = MTD_RAM;
	mi->mtd_desc.flags = MTD_CAP_RAM;
	mi->mtd_desc.size = mtdsize;
	mi->mtd_desc.erasesize = erasesize;
	mi->mtd_desc.writesize = writesize;
	mi->mtd_desc.writebufsize = writebufsize;

	return mi;
}

static const struct muse_lowlevel_ops mtd_ops = {
	.read = muse_mtd_read,
	.write = muse_mtd_write,
	.erase = muse_mtd_erase,
	.sync = muse_mtd_sync,
};

int main(void)
{
	struct muse_setup_info *mi = build_muse_setup_info();

	if (!mi) {
		fprintf(stderr, "Unable to allocate MUSE setup info object: %m\n");
		exit(1);
	}
	mi->multithreaded = 0;

	mtdbuf = malloc(mtdsize);
	if (!mtdbuf) {
		fprintf(stderr, "Unable to allocate buffer (%u): %m\n", mtdsize);
		exit(1);
	}

	memset(mtdbuf, 0xFF, mtdsize);

	return muse_lowlevel_main(mi, &mtd_ops);
}
