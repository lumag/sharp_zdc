#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/version.h>

#include <media/v4l2-dev.h>
#include <media/v4l2-ioctl.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>

struct sharpzdc_info {
	struct kref		ref;
	struct pcmcia_device	*p_dev;
	struct video_device	*vdev;
};

#define to_zdcinfo(r)	container_of(r, struct sharpzdc_info, ref)

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

static int sharpzdc_open(struct inode *inode, struct file *fp)
{
	struct video_device *vdev = video_devdata(fp);
	struct sharpzdc_info *info = video_get_drvdata(vdev);

	pr_debug("%s\n", __func__);

	kref_get(&info->ref);
	fp->private_data = info;

	return 0;
}

static int sharpzdc_release(struct inode *inode, struct file *fp)
{
	struct sharpzdc_info *info = fp->private_data;

	pr_debug("%s\n", __func__);

	kref_put(&info->ref, sharpzdc_info_release);
	return 0;
}

static struct file_operations sharpzdc_fops = {
	.owner		= THIS_MODULE,
	.open		= sharpzdc_open,
	.release	= sharpzdc_release,
	.ioctl		= video_ioctl2,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= v4l_compat_ioctl32,
#endif
	.llseek		= no_llseek,
};

static int sharpzdc_querycap(struct file *file, void *priv,
		struct v4l2_capability *cap)
{
	struct sharpzdc_info *info = priv;

	strcpy(cap->driver, "sharpzdc_cs");
	strcpy(cap->card, "CE-AG06");
	snprintf(cap->bus_info, sizeof(cap->bus_info),
			"pcmcia:%s", dev_name(&info->p_dev->dev));
	cap->version = KERNEL_VERSION(0, 0, 1);
	cap->capabilities = V4L2_CAP_VIDEO_CAPTURE;
	return 0;
}

static int sharpzdc_querystd(struct file *file, void *priv, v4l2_std_id *id)
{
	*id = V4L2_STD_UNKNOWN;
	return 0;
}

static int sharpzdc_enum_input(struct file *file, void *private_data,
		struct v4l2_input *input)
{
	if (input->index > 0)
		return -EINVAL;

	strcpy(input->name, "Camera");
	input->type = V4L2_INPUT_TYPE_CAMERA;
	input->std = V4L2_STD_UNKNOWN;

	return 0;
}

static int sharpzdc_s_input(struct file *file, void *private_data,
		unsigned int index)
{
	if (index != 0)
		return -EINVAL;

	return 0;
}

static int sharpzdc_g_input(struct file *file, void *private_data,
		unsigned int *index)
{
	*index = 0;
	return 0;
}

static int sharpzdc_enum_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_fmtdesc *f)
{
	if (f->index > 0)
		return -EINVAL;

	f->pixelformat = V4L2_PIX_FMT_RGB565;
	strcpy(f->description, "RGB565");

	return 0;
}

static int sharpzdc_g_fmt_vid_cap(struct file *file, void *private_data,
		struct v4l2_format *f)
{
	// FIXME: width, height, bytesperline, sizeimage,
#if 1
	f->fmt.pix.width = 320;
	f->fmt.pix.height = 240;
	f->fmt.pix.bytesperline = f->fmt.pix.width * 2;
	f->fmt.pix.sizeimage = f->fmt.pix.bytesperline * f->fmt.pix.height;
#endif
	f->fmt.pix.pixelformat = V4L2_PIX_FMT_RGB565;
	f->fmt.pix.field = V4L2_FIELD_NONE;
	f->fmt.pix.colorspace = V4L2_COLORSPACE_SRGB;

	return 0;
}

static struct v4l2_ioctl_ops sharpzdc_ioctl_ops = {
	.vidioc_querycap	= sharpzdc_querycap,
	.vidioc_querystd	= sharpzdc_querystd,
	.vidioc_enum_input	= sharpzdc_enum_input,
	.vidioc_s_input		= sharpzdc_s_input,
	.vidioc_g_input		= sharpzdc_g_input,
	.vidioc_enum_fmt_vid_cap = sharpzdc_enum_fmt_vid_cap,
	.vidioc_g_fmt_vid_cap	= sharpzdc_g_fmt_vid_cap,
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

	info->p_dev = link;
	link->priv = info;

	link->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
	link->irq.IRQInfo1 = IRQ_LEVEL_ID;
	link->conf.Attributes = 0;
	link->conf.IntType = INT_MEMORY_AND_IO;

	ret = sharpzdc_config(link);
	if (ret)
		goto err;

	info->vdev = video_device_alloc();
	if (info->vdev == NULL) {
		ret = -ENOMEM;
		goto err2;
	}
	kref_get(&info->ref);
	video_set_drvdata(info->vdev, info);

	info->vdev->parent = &link->dev;
	info->vdev->fops = &sharpzdc_fops;
	info->vdev->release = sharpzdc_vdev_release;
	info->vdev->ioctl_ops = &sharpzdc_ioctl_ops;
	info->vdev->tvnorms = V4L2_STD_UNKNOWN;
	info->vdev->current_norm = V4L2_STD_UNKNOWN;
	strncpy(info->vdev->name, "sharpzdc", sizeof(info->vdev->name));

	ret = video_register_device(info->vdev, VFL_TYPE_GRABBER, -1);
	if (ret < 0)
		goto err3;

	return 0;
err3:
	if (info->vdev) {
		sharpzdc_vdev_release(info->vdev);
		info->vdev = NULL;
	}
err2:
	pcmcia_disable_device(link);
err:
	kref_put(&info->ref, sharpzdc_info_release);
	return ret;
}

static void sharpzdc_remove(struct pcmcia_device *link)
{
	struct sharpzdc_info *info = link->priv;
	pr_debug("%s\n", __func__);

	video_unregister_device(info->vdev);

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

