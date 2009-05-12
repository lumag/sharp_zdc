//#define DEBUG
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include <media/v4l2-dev.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf-vmalloc.h>

#include "sharpzdc.h"

static unsigned int vid_limit = 16;	/* Video memory limit, in Mb */
module_param(vid_limit, int, 0644);
MODULE_PARM_DESC(vid_limit, "capture memory limit in megabytes");

static void sharpzdc_thread_tick(struct sharpzdc_info *info)
{
	struct videobuf_buffer *vb;
	void *vbuf;
	unsigned long flags = 0;

	pr_debug("%s\n", __func__);

	spin_lock_irqsave(&info->lock, flags);
	if (list_empty(&info->queued))
		goto unlock;

	vb = list_entry(info->queued.next,
			 struct videobuf_buffer, queue);

	list_del(&vb->queue);

	vbuf = videobuf_to_vmalloc(vb);
	if (!vbuf) {
		vb->state = VIDEOBUF_ERROR;
		goto wake;
	}

	/* Fill buffer */
	sharpzdc_get(info, vbuf);

	/* Advice that buffer was filled */
	vb->field_count += 1; /* two fields */
	do_gettimeofday(&vb->ts);
	vb->state = VIDEOBUF_DONE;

wake:
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
	add_wait_queue(&info->vb_vidq.wait, &wait);

	for (;;) {
		if (kthread_should_stop())
			break;

		try_to_freeze();
		schedule_timeout_interruptible(1000 * 30 / 1001);
//		wait_event_freezable(info->wq, !list_empty(&info->queued) || kthread_should_stop());

		if (kthread_should_stop())
			break;
		sharpzdc_thread_tick(info);
	}

	remove_wait_queue(&info->vb_vidq.wait, &wait);
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

	*size = info->image_size;

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
}

static struct videobuf_queue_ops sharpzdc_video_qops = {
	.buf_setup      = sharpzdc_buf_setup,
	.buf_prepare    = sharpzdc_buf_prepare,
	.buf_queue      = sharpzdc_buf_queue,
	.buf_release    = sharpzdc_buf_release,
};


static void sharpzdc_vdev_release(struct video_device *vdev)
{
	struct sharpzdc_info *info = video_get_drvdata(vdev);

	pr_debug("%s\n", __func__);

	video_device_release(vdev);

	kref_put(&info->ref, sharpzdc_info_release); /* vdev->drvdata = info */
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


static int sharpzdc_open(struct file *fp)
{
	struct video_device *vdev = video_devdata(fp);
	struct sharpzdc_info *info = video_get_drvdata(vdev);

	pr_debug("%s\n", __func__);

	kref_get(&info->ref); /* as we store info in fp */
	fp->private_data = info;

	videobuf_queue_vmalloc_init(&info->vb_vidq, &sharpzdc_video_qops,
			NULL, &info->lock, V4L2_BUF_TYPE_VIDEO_CAPTURE, V4L2_FIELD_NONE,
			sizeof(struct videobuf_buffer), info);


	return 0;
}

static int sharpzdc_release(struct file *fp)
{
	struct sharpzdc_info *info = fp->private_data;

	pr_debug("%s\n", __func__);

	videobuf_stop(&info->vb_vidq);
	videobuf_mmap_free(&info->vb_vidq);

	kref_put(&info->ref, sharpzdc_info_release); /* pair to kref_get in sharpzdc_open */
	return 0;
}

static const struct v4l2_file_operations sharpzdc_fops = {
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
};

static int sharpzdc_querycap(struct file *file, void *private_data,
		struct v4l2_capability *cap)
{
	pr_debug("%s\n", __func__);
	strcpy(cap->driver, "sharpzdc_cs");
	strcpy(cap->card, "CE-AG06");
	strncpy(cap->bus_info, "pcmcia:sharpzdc", sizeof(cap->bus_info));
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
	f->fmt.pix.bytesperline = info->line_stride;
	f->fmt.pix.sizeimage = info->image_size;

	f->fmt.pix.pixelformat = V4L2_PIX_FMT_RGB565;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	return 0;
}

static int sharpzdc_try_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_format *f)
{
	pr_debug("%s\n", __func__);
	/* FIXME: width, height, bytesperline, sizeimage limitation wrt rotating and zoom. */
	if (f->fmt.pix.width < 32)
		f->fmt.pix.width = 32;
	if (f->fmt.pix.width > 640)
		f->fmt.pix.width = 640;
	f->fmt.pix.width = (f->fmt.pix.width + 1)&~1;

	if (f->fmt.pix.height < 32)
		f->fmt.pix.height = 32;
	if (f->fmt.pix.height > 480)
		f->fmt.pix.height = 480;
	f->fmt.pix.height = (f->fmt.pix.height + 1)&~1;

	if (f->fmt.pix.bytesperline < (f->fmt.pix.width * 2))
		f->fmt.pix.bytesperline = f->fmt.pix.width * 2;
	f->fmt.pix.bytesperline = (f->fmt.pix.bytesperline + 3)&~3;

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
	int ret = 0;

	pr_debug("%s\n", __func__);
	ret = sharpzdc_try_fmt_vid_cap(file, private_data, f);
	if (ret < 0)
		return ret;

	mutex_lock(&info->vb_vidq.vb_lock);
	if (videobuf_queue_is_busy(&info->vb_vidq)) {
		pr_debug("%s queue busy\n", __func__);
		ret = -EBUSY;
		goto out;
	}

	/* FIXME: width, height, bytesperline, sizeimage limitation wrt rotating and zoom. */
	info->width = f->fmt.pix.width;
	info->height = f->fmt.pix.height;
	info->line_stride = f->fmt.pix.bytesperline;
	info->image_size = f->fmt.pix.sizeimage;

out:
	mutex_unlock(&info->vb_vidq.vb_lock);
	return ret;
}

static int sharpzdc_reqbufs(struct file *file, void *private_data,
		struct v4l2_requestbuffers *p)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return videobuf_reqbufs(&info->vb_vidq, p);
}

static int sharpzdc_querybuf(struct file *file, void *private_data,
		struct v4l2_buffer *p)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return videobuf_querybuf(&info->vb_vidq, p);
}

static int sharpzdc_qbuf(struct file *file, void *private_data, struct v4l2_buffer *p)
{
	struct sharpzdc_info *info = private_data;

	pr_debug("%s\n", __func__);
	return videobuf_qbuf(&info->vb_vidq, p);
}

static int sharpzdc_dqbuf(struct file *file, void *private_data, struct v4l2_buffer *p)
{
	struct sharpzdc_info  *info = private_data;

	pr_debug("%s\n", __func__);
	return videobuf_dqbuf(&info->vb_vidq, p,
				file->f_flags & O_NONBLOCK);
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


static const struct v4l2_ioctl_ops sharpzdc_ioctl_ops = {
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

int sharpzdc_vdev_init(struct device *parent, struct sharpzdc_info *info)
{
	int rc;

	info->vdev = video_device_alloc();
	if (info->vdev == NULL)
		return -ENOMEM;

	kref_get(&info->ref); /* vdev->drvdata = info */
	video_set_drvdata(info->vdev, info);
	info->vdev->fops = &sharpzdc_fops;
	info->vdev->fops = &sharpzdc_fops;
	info->vdev->release = sharpzdc_vdev_release;
	info->vdev->ioctl_ops = &sharpzdc_ioctl_ops;
	info->vdev->tvnorms = V4L2_STD_UNKNOWN;
	info->vdev->current_norm = V4L2_STD_UNKNOWN;
	info->vdev->parent = parent;

	strncpy(info->vdev->name, "sharpzdc", sizeof(info->vdev->name));

	rc = video_register_device(info->vdev, VFL_TYPE_GRABBER, -1);
	if (rc) {
		sharpzdc_vdev_release(info->vdev);
		info->vdev = NULL;
	}

	return rc;
}

void sharpzdc_vdev_exit(struct sharpzdc_info *info)
{
	video_unregister_device(info->vdev);
}
