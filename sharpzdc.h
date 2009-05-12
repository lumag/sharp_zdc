#ifndef SHARPZDC_H
#define SHARPZDC_H

#include <media/videobuf-vmalloc.h>

struct sharpzdc_info {
	struct kref		ref;
	struct pcmcia_device	*p_dev;
	struct video_device	*vdev;

	struct videobuf_queue	vb_vidq;
	struct list_head	queued;
	spinlock_t		lock; /* guards video buffs */

	struct task_struct	*thread;

	void __iomem		*io;
	int	readmode;
	int	image_size;
	unsigned short	width;
	unsigned short	height;
	unsigned short	line_stride;

};

void sharpzdc_info_release(struct kref *ref);
int sharpzdc_vdev_init(struct device *parent, struct sharpzdc_info *info);
void sharpzdc_vdev_exit(struct sharpzdc_info *info);
int sharpzdc_get(struct sharpzdc_info *zdcinfo, char *buf);

int sharpzdc_kthread(void *data);

#endif

