#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/freezer.h>

#include <media/v4l2-dev.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf-vmalloc.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>

static unsigned int vid_limit = 16;	/* Video memory limit, in Mb */
module_param(vid_limit, int, 0644);
MODULE_PARM_DESC(vid_limit, "capture memory limit in megabytes");

struct sharpzdc_info {
	struct kref		ref;
	struct pcmcia_device	*p_dev;
	struct video_device	*vdev;



	struct videobuf_queue	vb_vidq;
	struct list_head	queued;
	spinlock_t		lock;

	struct task_struct	*thread;
	wait_queue_head_t	wq;

	unsigned int		width, height;
	unsigned int		bpl, size;
};

#define to_zdcinfo(r)	container_of(r, struct sharpzdc_info, ref)

static void sharpzdc_fillbuff(struct sharpzdc_info* info, struct videobuf_buffer *vb)
{
	int h , pos = 0;
	int hmax  = vb->height;
	int wmax  = vb->width;
	void *vbuf = videobuf_to_vmalloc(vb);

	pr_debug("%s\n", __func__);

	if (!vbuf)
		return;

	for (h = 0; h < hmax; h++) {
		memset(vbuf + pos, 0xcc, wmax * 2);
		pos += wmax*2;
	}

	/* Advice that buffer was filled */
	vb->field_count += 2; /* two fields */
	do_gettimeofday(&vb->ts);
	vb->state = VIDEOBUF_DONE;
}

static void sharpzdc_thread_tick(struct sharpzdc_info *info)
{
	struct videobuf_buffer *vb;

	unsigned long flags = 0;

	pr_debug("%s\n", __func__);

	spin_lock_irqsave(&info->lock, flags);
	if (list_empty(&info->queued))
		goto unlock;

	vb = list_entry(info->queued.next,
			 struct videobuf_buffer, queue);

	list_del(&vb->queue);

	do_gettimeofday(&vb->ts);

	/* Fill buffer */
	sharpzdc_fillbuff(info, vb);

	wake_up(&vb->done);
unlock:
	spin_unlock_irqrestore(&info->lock, flags);
	return;
}

int sharpzdc_kthread(void *data)
{
	struct sharpzdc_info *info = data;
	DECLARE_WAITQUEUE(wait, current);

	pr_debug("%s\n", __func__);
//	set_user_nice(current, -20);

	set_freezable();
	add_wait_queue(&info->wq, &wait);

	for(;;) {
		if (kthread_should_stop())
			break;

		wait_event_freezable(info->wq, !list_empty(&info->queued) || kthread_should_stop());

		if (kthread_should_stop())
			break;
		sharpzdc_thread_tick(info);
	}


	remove_wait_queue(&info->wq, &wait);
	pr_debug("%s exiting\n", __func__);

	return 0;
}

static void sharpzdc_buf_release(struct videobuf_queue *q,
		struct videobuf_buffer *vb)
{
	pr_debug("%s\n", __func__);
	BUG_ON(in_interrupt());

	videobuf_vmalloc_free(vb);
	vb->state = VIDEOBUF_NEEDS_INIT;
}

static int sharpzdc_buf_setup(struct videobuf_queue *q,
		unsigned int *count, unsigned int *size)
{
	struct sharpzdc_info  *info = q->priv_data;
	pr_debug("%s\n", __func__);

	*size = info->width * info->height*2;

	if (*count == 0)
		*count = 32;

	while (*size * *count > vid_limit * 1024 * 1024)
		(*count)--;

	return 0;
}

static int sharpzdc_buf_prepare(struct videobuf_queue *q,
		struct videobuf_buffer *vb,
		enum v4l2_field field)
{
	struct sharpzdc_info     *info  = q->priv_data;
	int rc;
	pr_debug("%s\n", __func__);

	/* FIXME: width/height IRT rotation and zoom */
	if (info->width  < 32 || info->width  > 640 ||
	    info->height < 32 || info->height > 480)
		return -EINVAL;

	vb->size = info->width*info->height*2;
	if (0 != vb->baddr  &&  vb->bsize < vb->size)
		return -EINVAL;

	/* These properties only change when queue is idle, see s_fmt */
	vb->width  = info->width;
	vb->height = info->height;
	vb->field  = field;

	if (vb->state == VIDEOBUF_NEEDS_INIT) {
		rc = videobuf_iolock(q, vb, NULL);
		if (rc < 0)
			goto fail;
	}

	vb->state = VIDEOBUF_PREPARED;

	return 0;

fail:
	sharpzdc_buf_release(q, vb);
	return rc;
}

static void sharpzdc_buf_queue(struct videobuf_queue *q,
		struct videobuf_buffer *vb)
{
	struct sharpzdc_info *info = q->priv_data;

	pr_debug("%s\n", __func__);

	vb->state = VIDEOBUF_QUEUED;

	list_add_tail(&vb->queue, &info->queued);
	wake_up(&info->wq);
}

static struct videobuf_queue_ops sharpzdc_video_qops = {
	.buf_setup      = sharpzdc_buf_setup,
	.buf_prepare    = sharpzdc_buf_prepare,
	.buf_queue      = sharpzdc_buf_queue,
	.buf_release    = sharpzdc_buf_release,
};


static void sharpzdc_info_release(struct kref *ref)
{
	struct sharpzdc_info *info = to_zdcinfo(ref);

	pr_debug("%s\n", __func__);

	kfree(info);
}

static void sharpzdc_vdev_release(struct video_device *vdev)
{
	struct sharpzdc_info *info = video_get_drvdata(vdev);

	pr_debug("%s\n", __func__);

	video_device_release(vdev);

	kref_put(&info->ref, sharpzdc_info_release);
}

static ssize_t
sharpzdc_read(struct file *file, char __user *data, size_t count, loff_t *ppos)
{
	struct sharpzdc_info *info = file->private_data;
	pr_debug("%s\n", __func__);

	return videobuf_read_stream(&info->vb_vidq, data, count, ppos, 0,
					file->f_flags & O_NONBLOCK);
}

static unsigned int
sharpzdc_poll(struct file *file, struct poll_table_struct *wait)
{
	struct sharpzdc_info *info = file->private_data;
	int ret;

	pr_debug("%s\n", __func__);

	ret = videobuf_poll_stream(file, &info->vb_vidq, wait);

	return ret;
}

static int sharpzdc_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct sharpzdc_info  *info = file->private_data;
	pr_debug("%s\n", __func__);

	return videobuf_mmap_mapper(&info->vb_vidq, vma);
}


static int sharpzdc_open(struct inode *inode, struct file *fp)
{
	struct video_device *vdev = video_devdata(fp);
	struct sharpzdc_info *info = video_get_drvdata(vdev);

	pr_debug("%s\n", __func__);

	kref_get(&info->ref);
	fp->private_data = info;

	videobuf_queue_vmalloc_init(&info->vb_vidq, &sharpzdc_video_qops,
			NULL, &info->lock, V4L2_BUF_TYPE_VIDEO_CAPTURE, V4L2_FIELD_NONE,
			sizeof(struct videobuf_buffer), info);


	return 0;
}

static int sharpzdc_release(struct inode *inode, struct file *fp)
{
	struct sharpzdc_info *info = fp->private_data;

	pr_debug("%s\n", __func__);

	videobuf_stop(&info->vb_vidq);
	videobuf_mmap_free(&info->vb_vidq);

	kref_put(&info->ref, sharpzdc_info_release);
	return 0;
}

static struct file_operations sharpzdc_fops = {
	.owner		= THIS_MODULE,
	.open		= sharpzdc_open,
	.release	= sharpzdc_release,
	.read		= sharpzdc_read,
	.poll		= sharpzdc_poll,
	.mmap		= sharpzdc_mmap,
	.ioctl		= video_ioctl2,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= v4l_compat_ioctl32,
#endif
	.llseek		= no_llseek,
};

static int sharpzdc_querycap(struct file *file, void *private_data,
		struct v4l2_capability *cap)
{
	struct sharpzdc_info *info = private_data;

	pr_debug("%s\n", __func__);
	strcpy(cap->driver, "sharpzdc_cs");
	strcpy(cap->card, "CE-AG06");
	snprintf(cap->bus_info, sizeof(cap->bus_info),
			"pcmcia:%s", dev_name(&info->p_dev->dev));
	cap->version = KERNEL_VERSION(0, 0, 1);
	cap->capabilities = V4L2_CAP_VIDEO_CAPTURE |
				V4L2_CAP_STREAMING |
				V4L2_CAP_READWRITE;
	return 0;
}

static int sharpzdc_enum_input(struct file *file, void *private_data,
		struct v4l2_input *input)
{
	pr_debug("%s\n", __func__);
	if (input->index > 0)
		return -EINVAL;

	strcpy(input->name, "Camera");
	input->type = V4L2_INPUT_TYPE_CAMERA;
	input->std = V4L2_STD_UNKNOWN;

	return 0;
}

static int sharpzdc_g_input(struct file *file, void *private_data,
		unsigned int *index)
{
	pr_debug("%s\n", __func__);
	*index = 0;
	return 0;
}

static int sharpzdc_s_input(struct file *file, void *private_data,
		unsigned int index)
{
	pr_debug("%s\n", __func__);
	if (index != 0)
		return -EINVAL;

	return 0;
}

static int sharpzdc_enum_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_fmtdesc *f)
{
	pr_debug("%s\n", __func__);
	if (f->index > 0)
		return -EINVAL;

	f->pixelformat = V4L2_PIX_FMT_RGB565;
	strcpy(f->description, "RGB565");

	return 0;
}

static int sharpzdc_g_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_format *f)
{
	struct sharpzdc_info *info = private_data;

	pr_debug("%s\n", __func__);

	f->fmt.pix.width = info->width;
	f->fmt.pix.height = info->height;
	f->fmt.pix.bytesperline = info->bpl;
	f->fmt.pix.sizeimage = info->size;

	f->fmt.pix.pixelformat = V4L2_PIX_FMT_RGB565;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	return 0;
}

static int sharpzdc_try_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_format *f)
{
	pr_debug("%s\n", __func__);
	// FIXME: width, height, bytesperline, sizeimage limitation wrt rotating and zoom.
	if (f->fmt.pix.width < 32)
		f->fmt.pix.width = 32;
	if (f->fmt.pix.width > 640)
		f->fmt.pix.width = 640;
	if (f->fmt.pix.height < 32)
		f->fmt.pix.height = 32;
	if (f->fmt.pix.height > 480)
		f->fmt.pix.height = 480;

	if (f->fmt.pix.bytesperline < (f->fmt.pix.width * 2))
		f->fmt.pix.bytesperline = f->fmt.pix.width * 2;

	if (f->fmt.pix.sizeimage < (f->fmt.pix.bytesperline * f->fmt.pix.height))
		f->fmt.pix.sizeimage = f->fmt.pix.bytesperline * f->fmt.pix.height;

	f->fmt.pix.pixelformat = V4L2_PIX_FMT_RGB565;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	return 0;
}

static int sharpzdc_s_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_format *f)
{
	struct sharpzdc_info *info = private_data;
	int ret;

	pr_debug("%s\n", __func__);
	ret = sharpzdc_try_fmt_vid_cap(file, private_data, f);
	if (ret < 0)
		return ret;

	mutex_lock(&info->vb_vidq.vb_lock);
	mutex_unlock(&info->vb_vidq.vb_lock);

	// FIXME: width, height, bytesperline, sizeimage limitation wrt rotating and zoom.
	info->width = f->fmt.pix.width;
	info->height = f->fmt.pix.height;
	info->bpl = f->fmt.pix.bytesperline;
	info->size = f->fmt.pix.sizeimage;

	return 0;
}

static int sharpzdc_reqbufs(struct file *file, void *private_data,
		struct v4l2_requestbuffers *p)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return (videobuf_reqbufs(&info->vb_vidq, p));
}

static int sharpzdc_querybuf(struct file *file, void *private_data,
		struct v4l2_buffer *p)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return (videobuf_querybuf(&info->vb_vidq, p));
}

static int sharpzdc_qbuf(struct file *file, void *private_data, struct v4l2_buffer *p)
{
	struct sharpzdc_info *info = private_data;

	pr_debug("%s\n", __func__);
	return (videobuf_qbuf(&info->vb_vidq, p));
}

static int sharpzdc_dqbuf(struct file *file, void *private_data, struct v4l2_buffer *p)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return (videobuf_dqbuf(&info->vb_vidq, p,
				file->f_flags & O_NONBLOCK));
}

#ifdef CONFIG_VIDEO_V4L1_COMPAT
static int sharpzdc_cgmbuf(struct file *file, void *private_data, struct video_mbuf *mbuf)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return videobuf_cgmbuf(&info->vb_vidq, mbuf, 8);
}
#endif

static int sharpzdc_streamon(struct file *file, void *private_data, enum v4l2_buf_type i)
{
	struct sharpzdc_info  *info = private_data;

	if (i != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	pr_debug("%s\n", __func__);
	return videobuf_streamon(&info->vb_vidq);
}

static int sharpzdc_streamoff(struct file *file, void *private_data, enum v4l2_buf_type i)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	if (i != V4L2_BUF_TYPE_VIDEO_CAPTURE)
		return -EINVAL;

	return videobuf_streamoff(&info->vb_vidq);
}


static struct v4l2_ioctl_ops sharpzdc_ioctl_ops = {
	.vidioc_querycap	= sharpzdc_querycap,
	.vidioc_enum_input	= sharpzdc_enum_input,
	.vidioc_g_input		= sharpzdc_g_input,
	.vidioc_s_input		= sharpzdc_s_input,
	.vidioc_enum_fmt_vid_cap = sharpzdc_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap	= sharpzdc_g_fmt_vid_cap,
	.vidioc_s_fmt_vid_cap	= sharpzdc_s_fmt_vid_cap,
	.vidioc_try_fmt_vid_cap	= sharpzdc_try_fmt_vid_cap,

	.vidioc_reqbufs		= sharpzdc_reqbufs,
	.vidioc_querybuf	= sharpzdc_querybuf,
	.vidioc_qbuf		= sharpzdc_qbuf,
	.vidioc_dqbuf		= sharpzdc_dqbuf,
	.vidioc_streamon	= sharpzdc_streamon,
	.vidioc_streamoff	= sharpzdc_streamoff,
#ifdef CONFIG_VIDEO_V4L1_COMPAT
	.vidiocgmbuf		= sharpzdc_cgmbuf,
#endif
};

#define CS_CHECK(fn, ret) \
do { last_fn = (fn); if ((last_ret = (ret)) != 0) goto cs_failed; } while (0)

#define CFG_CHECK(fn, ret) \
do { last_fn = (fn); if ((last_ret = (ret)) != 0) goto next_entry; } while (0)

static int sharpzdc_config(struct pcmcia_device *link)
{
	tuple_t tuple;
	cisparse_t parse;
	cistpl_cftable_entry_t dflt = { 0 };
	cistpl_cftable_entry_t *cfg = &parse.cftable_entry;
	config_info_t conf;
	u_short buf[64];
	int last_fn, last_ret;
	win_req_t req;
	memreq_t map;

	pr_debug("%s\n", __func__);

	tuple.TupleData = (cisdata_t *)buf;
	tuple.TupleDataMax = sizeof(buf);
	tuple.TupleOffset = 0;

	/* Not sure if this is right... look up the current Vcc */
	CS_CHECK(GetConfigurationInfo, pcmcia_get_configuration_info(link, &conf));

	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;
	CS_CHECK(GetFirstTuple, pcmcia_get_first_tuple(link, &tuple));
	while (1) {
		CFG_CHECK(GetTupleData, pcmcia_get_tuple_data(link, &tuple));
		CFG_CHECK(ParseTuple, pcmcia_parse_tuple(link, &tuple, &parse));

		if (cfg->flags & CISTPL_CFTABLE_DEFAULT)
			dflt = *cfg;
		if (cfg->index == 0)
			goto next_entry;
		link->conf.ConfigIndex = cfg->index;

		/* Use power settings for Vcc and Vpp if present */
		/*  Note that the CIS values need to be rescaled */
		if (cfg->vcc.present & (1<<CISTPL_POWER_VNOM)) {
			if (conf.Vcc != cfg->vcc.param[CISTPL_POWER_VNOM]/10000)
				goto next_entry;
		} else if (dflt.vcc.present & (1<<CISTPL_POWER_VNOM)) {
			if (conf.Vcc != dflt.vcc.param[CISTPL_POWER_VNOM]/10000)
				goto next_entry;
		}

		if (cfg->vpp1.present & (1<<CISTPL_POWER_VNOM))
			link->conf.Vpp =
				cfg->vpp1.param[CISTPL_POWER_VNOM]/10000;
		else if (dflt.vpp1.present & (1<<CISTPL_POWER_VNOM))
			link->conf.Vpp =
				dflt.vpp1.param[CISTPL_POWER_VNOM]/10000;

		/* Do we need to allocate an interrupt? */
		if (cfg->irq.IRQInfo1 || dflt.irq.IRQInfo1) {
			link->conf.Attributes |= CONF_ENABLE_IRQ;
		}

		/* IO window settings */
		link->io.NumPorts1 = link->io.NumPorts2 = 0;
		if ((cfg->io.nwin > 0) || (dflt.io.nwin > 0)) {
			cistpl_io_t *io = (cfg->io.nwin) ? &cfg->io : &dflt.io;
			link->io.Attributes1 = IO_DATA_PATH_WIDTH_AUTO;
			if (!(io->flags & CISTPL_IO_8BIT))
				link->io.Attributes1 = IO_DATA_PATH_WIDTH_16;
			if (!(io->flags & CISTPL_IO_16BIT))
				link->io.Attributes1 = IO_DATA_PATH_WIDTH_8;
			link->io.IOAddrLines = io->flags & CISTPL_IO_LINES_MASK;
			link->io.BasePort1 = io->win[0].base;
			link->io.NumPorts1 = io->win[0].len;
			if (io->nwin > 1) {
				link->io.Attributes2 = link->io.Attributes1;
				link->io.BasePort2 = io->win[1].base;
				link->io.NumPorts2 = io->win[1].len;
			}
			/* This reserves IO space but doesn't actually enable it */
			CFG_CHECK(RequestIO, pcmcia_request_io(link, &link->io));
		}

		if ((cfg->mem.nwin > 0) || (dflt.mem.nwin > 0)) {
			cistpl_mem_t *mem =
				(cfg->mem.nwin) ? &cfg->mem : &dflt.mem;
			req.Attributes = WIN_DATA_WIDTH_16|WIN_MEMORY_TYPE_CM;
			req.Attributes |= WIN_ENABLE;
			req.Base = mem->win[0].host_addr;
			req.Size = mem->win[0].len;
			if (req.Size < 0x1000)
				req.Size = 0x1000;
			req.AccessSpeed = 0;
			CFG_CHECK(RequestWindow, pcmcia_request_window(&link, &req, &link->win));
			map.Page = 0; map.CardOffset = mem->win[0].card_addr;
			CFG_CHECK(MapMemPage, pcmcia_map_mem_page(link->win, &map));
		}

		break;
next_entry:
		CS_CHECK(GetNextTuple, pcmcia_get_next_tuple(link, &tuple));
	}

	if (link->conf.Attributes & CONF_ENABLE_IRQ)
		CS_CHECK(RequestIRQ, pcmcia_request_irq(link, &link->irq));

	CS_CHECK(RequestConfiguration, pcmcia_request_configuration(link, &link->conf));

	/* Finally, report what we've done */
	printk(KERN_INFO "%s: index 0x%02x: Vcc %d.%d",
		   link->dev.bus_id, link->conf.ConfigIndex,
		   conf.Vcc/10, conf.Vcc%10);
	if (link->conf.Vpp)
		printk(", Vpp %d.%d", link->conf.Vpp/10, link->conf.Vpp%10);
	if (link->conf.Attributes & CONF_ENABLE_IRQ)
		printk(", irq %d", link->irq.AssignedIRQ);
	if (link->io.NumPorts1)
		printk(", io 0x%04lx-0x%04lx", (long int)link->io.BasePort1,
			   (long int)link->io.BasePort1+link->io.NumPorts1-1);
	if (link->io.NumPorts2)
		printk(" & 0x%04lx-0x%04lx", (long int)link->io.BasePort2,
			   (long int)link->io.BasePort2+link->io.NumPorts2-1);
	if (link->win)
		printk(", mem 0x%06lx-0x%06lx", req.Base,
			   req.Base+req.Size-1);
	printk("\n");

	return 0;
cs_failed:
	cs_error(link, last_fn, last_ret);
	pcmcia_disable_device(link);
	return -ENODEV;
}

static int sharpzdc_probe(struct pcmcia_device *link)
{
	struct sharpzdc_info *info;
	int ret;

	pr_debug("%s\n", __func__);

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	kref_init(&info->ref);
	spin_lock_init(&info->lock);
	INIT_LIST_HEAD(&info->queued);
	init_waitqueue_head(&info->wq);

	info->p_dev = link;
	link->priv = info;

	link->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
	link->irq.IRQInfo1 = IRQ_LEVEL_ID;
	link->conf.Attributes = 0;
	link->conf.IntType = INT_MEMORY_AND_IO;

	ret = sharpzdc_config(link);
	if (ret)
		goto err_config;

	info->vdev = video_device_alloc();
	if (info->vdev == NULL) {
		ret = -ENOMEM;
		goto err_vdev;
	}
	kref_get(&info->ref);
	video_set_drvdata(info->vdev, info);

	info->width = 320;
	info->height = 240;
	info->bpl = info->width * 2;
	info->size = info->bpl * info->height;

	info->vdev->parent = &link->dev;
	info->vdev->fops = &sharpzdc_fops;
	info->vdev->release = sharpzdc_vdev_release;
	info->vdev->ioctl_ops = &sharpzdc_ioctl_ops;
	info->vdev->tvnorms = V4L2_STD_UNKNOWN;
	info->vdev->current_norm = V4L2_STD_UNKNOWN;
	strncpy(info->vdev->name, "sharpzdc", sizeof(info->vdev->name));

	info->thread = kthread_run(sharpzdc_kthread, info,
		      "sharpzdc: %s", dev_name(&link->dev));
	if (IS_ERR(info->thread)) {
		ret = PTR_ERR(info->thread);
		goto err_thread;
	}

	ret = video_register_device(info->vdev, VFL_TYPE_GRABBER, -1);
	if (ret < 0)
		goto err_register;

	return 0;
err_register:
	kthread_stop(info->thread);
err_thread:
	if (info->vdev) {
		sharpzdc_vdev_release(info->vdev);
		info->vdev = NULL;
	}
err_vdev:
	pcmcia_disable_device(link);
err_config:
	kref_put(&info->ref, sharpzdc_info_release);
	return ret;
}

static void sharpzdc_remove(struct pcmcia_device *link)
{
	struct sharpzdc_info *info = link->priv;
	pr_debug("%s\n", __func__);

	video_unregister_device(info->vdev);

	kthread_stop(info->thread);

	pcmcia_disable_device(link);
	kref_put(&info->ref, sharpzdc_info_release);
}

static struct pcmcia_device_id sharpzdc_ids[] = {
	PCMCIA_DEVICE_CIS_PROD_ID12("SHARP", "CEAG06  ", 0xb3ad4c1c, 0xe1d1a7a9, "CE-AG06.dat"),
//	PCMCIA_DEVICE_PROD_ID12("SHARP", "CEAG06  ", 0xb3ad4c1c, 0xe1d1a7a9),
	PCMCIA_DEVICE_NULL,
};

MODULE_DEVICE_TABLE(pcmcia, sharpzdc_ids);

static struct pcmcia_driver sharpzdc_driver = {
	.owner		= THIS_MODULE,
	.drv.name	= "sharpzdc_cs",
	.id_table	= sharpzdc_ids,
	.probe		= sharpzdc_probe,
	.remove		= sharpzdc_remove,
};

static int __init sharpzdc_init(void)
{
	return pcmcia_register_driver(&sharpzdc_driver);
}

static void __exit sharpzdc_exit(void)
{
	pcmcia_unregister_driver(&sharpzdc_driver);
}

module_init(sharpzdc_init);
module_exit(sharpzdc_exit);

MODULE_AUTHOR("Dmitry Baryshkov");
MODULE_DESCRIPTION("Sharp CE-AG06 camera driver");
MODULE_LICENSE("GPL");

