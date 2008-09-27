#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>

static int dev_maj;

typedef struct {
	struct pcmcia_device	*p_dev;
	struct miscdevice	mdev;
} sharpzdc_info_t;

static struct file_operations zdc_ops = {
	.owner		= THIS_MODULE,
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
	sharpzdc_info_t *info;
	int ret;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return -ENOMEM;

	info->p_dev = link;
	link->priv = info;

	link->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
	link->irq.IRQInfo1 = IRQ_LEVEL_ID;
	link->conf.Attributes = 0;
	link->conf.IntType = INT_MEMORY_AND_IO;

	ret = sharpzdc_config(link);
	if (ret)
		goto err;

	info->mdev.minor = 148;
	info->mdev.name = "sharpzdc";
	info->mdev.fops = &zdc_ops;
	info->mdev.parent = &link->dev;
	ret = misc_register(&info->mdev);
	if (ret)
		goto err2;

	return 0;
err2:
	pcmcia_disable_device(link);
err:
	kfree(info);
	return ret;
}

static void sharpzdc_detach(struct pcmcia_device *link)
{
	sharpzdc_info_t *info = link->priv;
	misc_deregister(&info->mdev);
	pcmcia_disable_device(link);
	kfree(info);
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
	.remove		= sharpzdc_detach,
};

static int __init sharpzdc_init(void)
{
	/* XXX */
	dev_maj = register_chrdev(0, "sharpzdc", &zdc_ops);

	return pcmcia_register_driver(&sharpzdc_driver);
}

static void __exit sharpzdc_exit(void)
{
	pcmcia_unregister_driver(&sharpzdc_driver);
	unregister_chrdev(dev_maj, "sharpzdc");
}

module_init(sharpzdc_init);
module_exit(sharpzdc_exit);

MODULE_AUTHOR("Dmitry Baryshkov");
MODULE_DESCRIPTION("Sharp CE-AG06 camera driver");
MODULE_LICENSE("GPL");

