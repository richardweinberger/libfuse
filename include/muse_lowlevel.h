/*
 *  MUSE: MTD in Userspace
 */

#ifndef MUSE_LOWLEVEL_H_
#define MUSE_LOWLEVEL_H_

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 35
#endif

#include "fuse_lowlevel.h"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct fuse_session;

struct mtd_desc {
	const char *mtdparts;
	unsigned int type;
	uint32_t flags;
	uint64_t size;
	uint32_t writesize;
	uint32_t writebufsize;
	uint32_t erasesize;
	uint32_t oobsize;
	uint32_t oobavail;
	unsigned int subpage_shift;
};

struct muse_setup_info {
	unsigned req_argc;
	char **req_argv;
	struct mtd_desc mtd_desc;
	int multithreaded;
};

#define MUSE_IO_INBAND		(1 << 0)
#define MUSE_IO_OOB_AUTO	(1 << 1)
#define MUSE_IO_OOB_PLACE	(1 << 2)
#define MUSE_IO_RAW		(1 << 3)

struct muse_lowlevel_ops {
	void (*read) (fuse_req_t req, uint64_t addr, uint64_t len, uint32_t flags);
	void (*write) (fuse_req_t req, uint64_t addr, uint64_t len, uint32_t flags,
		       const char *buf);
	void (*erase) (fuse_req_t req, uint64_t addr, uint64_t len);
	void (*block_isbad) (fuse_req_t req, uint64_t addr);
	void (*block_markbad) (fuse_req_t req, uint64_t addr);
	void (*sync) (fuse_req_t req);
};

struct fuse_session *muse_lowlevel_new(const struct muse_setup_info *mi,
				       const struct muse_lowlevel_ops *mlop);

struct fuse_session *muse_lowlevel_setup(const struct muse_setup_info *mi,
					 const struct muse_lowlevel_ops *mlop);

void muse_lowlevel_teardown(struct fuse_session *se);

int muse_lowlevel_main(const struct muse_setup_info *mi,
		       const struct muse_lowlevel_ops *mlop);

int muse_send_read_reply(fuse_req_t req, int error, const void *buf,
		      size_t bufsize);
int muse_send_write_reply(fuse_req_t req, int error, size_t len);
int muse_send_block_markbad_reply(fuse_req_t req, int error, int isbad);

#ifdef __cplusplus
}
#endif

#endif /* MUSE_LOWLEVEL_H_ */
