//#define DEBUG
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/delay.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/ds.h>

#include "sharpzdc.h"

#define to_zdcinfo(r)	container_of(r, struct sharpzdc_info, ref)

#define SZDC_FLAGS1		0x0	/* bw */
#define SZDC_FLAGS1_CAPTURING	BIT(0)
#define SZDC_FLAGS1_RESET_PTR	BIT(1)
#define SZDC_FLAGS1_REVERSE_DETECTED BIT(2)
#define SZDC_FLAGS1_SHUTTER	BIT(3)

#define SZDC_FLAGS2		0x2	/* bw */
#define SZDC_FLAGS2_XFLIP	BIT(3)

#define SZDC_DATA		0x4	/* l */

#define SZDC_SET_DATA_BUS	0x6	/* bw */

#define SZDC_MCON		0x8	/* bw */
#define SZDC_MCON_RO		BIT(0) /* at least it seems so */
#define SZDC_MCON_STROBE	BIT(1)
#define SZDC_MCON_DISABLED	BIT(3)
#define SZDC_MCON_ENABLED2	BIT(4) /* seems to depend on !MCON_DISABLED */
#define SZDC_MCON_READY		BIT(5)
#define SZDC_MCON_RESET		BIT(6) /* toggled to start program */

#define SZDC_EEPROM		0xA	/* b */
#define SZDC_EEPROM_ENABLE	BIT(7)
#define SZDC_EEPROM_CLOCK	BIT(3)
#define SZDC_EEPROM_CS		BIT(2)
#define SZDC_EEPROM_DATA_IN	BIT(1)
#define SZDC_EEPROM_DATA_OUT	BIT(0)

#define SZDC_BUS_SELECT		0xB	/* b */
#define SZDC_BUS_SELECT_DRAM	0
#define SZDC_BUS_SELECT_VGA	1
#define SZDC_BUS_SELECT_CORE	2
#define SZDC_BUS_SELECT_MCON	3

#define SZDC_BUS_ADDR		0xC	/* bw */
#define SZDC_BUS_DATA		0xE	/* bw */

#define SZDC_READMODE_BETTER	0x02 /* rather than faster */
#define SZDC_READMODE_XFLIP	0x04
#define SZDC_READMODE_YFLIP	0x08

// inl is usual
/*
#undef outb
static inline void iowrite8(u8 data, void __iomem *io)
{
	*(volatile u8*)io = data;
}
*/
#define inbw(io)  (ioread8(io) | (ioread8((io) + 1) << 8))
#define outbw(data, io) \
	ioread8(io);		  \
	iowrite8(data, io);   \
	ioread8(io+1);		\
	iowrite8(data >> 8, io+1);
#define setw(bit, io)   \
	do {				\
		unsigned short __d;\
		__d = inbw(io);  \
		__d |= (bit);	   \
		outbw(__d, io);  \
	} while (0)

#define clearw(bit, io)   \
	do {				\
		unsigned short __d;\
		__d = inbw(io);  \
		__d &= ~(bit);	   \
		outbw(__d, io);  \
	} while (0)

static const unsigned short __devinitdata sharpzdc_params[] = {
	0xFA0,	0,
	0xF0E,	0x50,
	0xF0F,	0x60,
	0xF0B,	1,
	0xF0C,	3,
	0xF0D,	2,
	0xF0A,	0x60,
};
static const unsigned short __devinitdata sharpzdc_camcore[] = {
	0x50,	0x25,
	0x52,	0xcd,
	0x54,	0x55,
	0x56,	0x9d,
	0x50,	0x25,
	0x52,	0xcd,
	0x60,	0x1285,
};

static const unsigned short __devinitdata sharpzdc_gamma[] = {
	0x00, 0x03, 0x05, 0x07, 0x09, 0x0a, 0x0c, 0x0d,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x25, 0x26,
	0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2c, 0x2d,
	0x2e, 0x2f, 0x30, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x34, 0x35, 0x36, 0x37, 0x37, 0x38, 0x39, 0x3a,
	0x3a, 0x3b, 0x3c, 0x3d, 0x3d, 0x3e, 0x3f, 0x3f,
};


static void __devinit set_camcore(void __iomem *io, unsigned short addr, unsigned short data)
{
	iowrite8(SZDC_BUS_SELECT_CORE, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);
}
static void set_dram_ctrl(void __iomem *io, unsigned short addr, unsigned short data)
{
	iowrite8(SZDC_BUS_SELECT_DRAM, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);
}
static void set_vga(void __iomem *io, unsigned short addr, unsigned short data)
{
	iowrite8(SZDC_BUS_SELECT_VGA, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);
}

static void __devinit eeprom_strobe(void __iomem *io, int data)
{
	char val = SZDC_EEPROM_ENABLE | SZDC_EEPROM_CS;
	if (data)
		val |= SZDC_EEPROM_DATA_OUT;

	iowrite8(val, io + SZDC_EEPROM);
	udelay(4);
	val |= SZDC_EEPROM_CLOCK;
	iowrite8(val, io + SZDC_EEPROM);
	udelay(4);
}

static unsigned short __devinit eeprom_read(void __iomem *io, unsigned char addr)
{
	unsigned short result = 0;
	int i;

	iowrite8(SZDC_EEPROM_ENABLE, io + SZDC_EEPROM);
	udelay(4);
	iowrite8(SZDC_EEPROM_ENABLE | SZDC_EEPROM_CS, io + SZDC_EEPROM);
	udelay(4);

	eeprom_strobe(io, 1);
	eeprom_strobe(io, 1);
	eeprom_strobe(io, 0);

	for (i = 7; i >= 0; i--)
		eeprom_strobe(io, addr & (1 << i));

	for (i = 0xF; i >= 0; i--) {
		eeprom_strobe(io, 0);
		result <<= 1;
		if (ioread8(io + SZDC_EEPROM) & SZDC_EEPROM_DATA_IN)
			result |= 1;
	}

	iowrite8(SZDC_EEPROM_ENABLE | SZDC_EEPROM_CS, io + SZDC_EEPROM);
	udelay(4);
	iowrite8(SZDC_EEPROM_ENABLE, io + SZDC_EEPROM);
	udelay(4);
	iowrite8(0, io + SZDC_EEPROM);
	udelay(4);

	return result;
}

static int wait_capture(void __iomem *io)
{
	int cnt;

	cnt = 0x100000;
	while (1) {
		if (!--cnt)
			return 0;
		if ((inbw(io + SZDC_FLAGS1) & SZDC_FLAGS1_CAPTURING) == 0)
			return 1;
	}
}
static int __devinit mcon_send_enable(void __iomem *io)
{
	int i;
	clearw(SZDC_MCON_DISABLED, io + SZDC_MCON);
	setw(SZDC_MCON_ENABLED2, io + SZDC_MCON);

	i = 0x500000;
	while ((inbw(io + SZDC_MCON) & SZDC_MCON_READY) == 0) {
		i--;
		if (i == 0) {
			clearw(SZDC_MCON_ENABLED2, io + SZDC_MCON);
			return 0;
		}
	}

	return 1;

}
static void __devinit mcon_send_disable(void __iomem *io, unsigned char start)
{

	clearw(SZDC_MCON_ENABLED2, io + SZDC_MCON);
	if (start) {
		clearw(SZDC_MCON_RESET, io + SZDC_MCON);
		setw(SZDC_MCON_RESET, io + SZDC_MCON);
		clearw(SZDC_MCON_RESET, io + SZDC_MCON);
	}
	setw(SZDC_MCON_DISABLED, io + SZDC_MCON);
}

static void __devinit mcon_send(void __iomem *io, unsigned short addr, unsigned short data)
{
	unsigned short d;
	iowrite8(SZDC_BUS_SELECT_MCON, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);

	clearw(SZDC_MCON_RO, io + SZDC_MCON);

	d = inbw(io + SZDC_MCON);
	outbw(d |  SZDC_MCON_STROBE, io + SZDC_MCON);
	outbw(d & ~SZDC_MCON_STROBE, io + SZDC_MCON);
	outbw(d |  SZDC_MCON_STROBE, io + SZDC_MCON);


	setw(SZDC_MCON_RO, io + SZDC_MCON);
}

static int __devinit sharpzdc_start(struct sharpzdc_info *zdcinfo)
{
	void __iomem *io = zdcinfo->io;
	const struct firmware *ag6exe;
	int ret;
	int i;

	ret = request_firmware(&ag6exe, "ag6exe.bin", &zdcinfo->p_dev->dev);
	if (ret) {
		dev_err(&zdcinfo->p_dev->dev, "firmware ag6exe.bin not available\n");
		return ret;
	}
	if (ag6exe->size == 0 || ag6exe->size > 0x2000 ||
			ag6exe->size % sizeof(unsigned short) != 0) {
		dev_err(&zdcinfo->p_dev->dev, "invalid firmware ag6exe.bin\n");
		release_firmware(ag6exe);
		return -EINVAL;
	}

	outbw(0, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_FLAGS2);
	setw(0x0100, io + SZDC_FLAGS1);
	clearw(0x4000, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_SET_DATA_BUS);

	udelay(1000);

	setw(0x8000, io + SZDC_FLAGS1);

	for (i = 0; i < 0x1F; i++) {
		set_camcore(io, 0x70, i);
		set_camcore(io, 0x72, eeprom_read(io, i * 2 + 0xC0));
		set_camcore(io, 0x74, eeprom_read(io, i * 2 + 0xC1));
	}

	for (i = 0; i < 0x16; i += 2) {
		unsigned short r = eeprom_read(io, i / 2 + 0x90);
		set_camcore(io, 0x78, i);
		set_camcore(io, 0x7A, r & 0xff);
		set_camcore(io, 0x78, i + 1);
		set_camcore(io, 0x7A, r >> 8);
	}

	for (i = 0; i < 0x10; i += 2) {
		unsigned short r = eeprom_read(io, i / 2 + 0xA0);
		set_camcore(io, 0x78, i + 0x100);
		set_camcore(io, 0x7A, r & 0xff);
		set_camcore(io, 0x78, i + 0x101);
		set_camcore(io, 0x7A, r >> 8);
	}

	set_camcore(io, 0x78, 0x110);
	set_camcore(io, 0x7A, eeprom_read(io, 0xA8) & 0xff);
	set_camcore(io, 0x7C, 0);

	setw(0x0200, io + SZDC_FLAGS1);
	setw(0x0c00, io + SZDC_FLAGS1);

	setw(0x8000, io + SZDC_FLAGS2);
	setw(0x0700, io + SZDC_FLAGS2);
	setw(0x0800, io + SZDC_FLAGS2);
	setw(0x1000, io + SZDC_FLAGS2);
	setw(0x00c0, io + SZDC_FLAGS2);
	clearw(0x0007, io + SZDC_FLAGS2);
	setw(0x0001, io + SZDC_FLAGS2);

	set_camcore(io, 0x44, 1);

	set_dram_ctrl(io, 0, 0x3C28); /* 640 x 480 */
	set_dram_ctrl(io, 1, 0);
	set_dram_ctrl(io, 2, 0x28);

	set_vga(io, 0, 4);
	set_vga(io, 1, 0x20);
	set_vga(io, 2, 0x280); /* 640 */
	set_vga(io, 4, 0x100);
	set_vga(io, 5, 0x100);

	clearw(SZDC_FLAGS1_SHUTTER, io + SZDC_FLAGS1);

	setw(0x0800, io + SZDC_FLAGS2);
	clearw(0x2000, io + SZDC_FLAGS2);
	setw(0x1000, io + SZDC_FLAGS2);

	clearw(0x4000, io + SZDC_FLAGS1);
	setw(0x4000, io + SZDC_FLAGS2);

	ret = mcon_send_enable(io);
	if (ret != 0) {
		for (i = 0; i < sizeof(sharpzdc_params) / sizeof(*sharpzdc_params); i += 2)
			mcon_send(io, sharpzdc_params[i], sharpzdc_params[i+1]);

		mcon_send_disable(io, 0);
	}

	set_camcore(io, 0x44, 1);
	for (i = 0; i <= 0x3f; i++) {
		set_camcore(io, 0x40, i);
		set_camcore(io, 0x42, sharpzdc_gamma[i]);
	}
	set_camcore(io, 0x44, 0);

	for (i = 0; i < sizeof(sharpzdc_camcore) / sizeof(*sharpzdc_camcore); i += 2)
		set_camcore(io, sharpzdc_camcore[i], sharpzdc_camcore[i+1]);

	ret = mcon_send_enable(io);
	if (ret == 0) {
		release_firmware(ag6exe);
		return -ENOTTY;
	}

	for (i = 0; i < ag6exe->size/2 && *((unsigned short *)ag6exe->data) != 0xffff; i++)
		mcon_send(io, i, ((unsigned short *)ag6exe->data)[i]);

	mcon_send_disable(io, 1);

	/*
	 * XXX: This is setiris
	 */
	mcon_send_enable(io);
	mcon_send(io, 0xF0A, 0x60);
	mcon_send_disable(io, 0);

	release_firmware(ag6exe);

	return 0;
}

static void sharpzdc_stop(struct sharpzdc_info *zdcinfo)
{
	void __iomem *io = zdcinfo->io;

	clearw(0x8000, io + SZDC_FLAGS2);
	clearw(0x0200, io + SZDC_FLAGS1);
	clearw(0x8000, io + SZDC_FLAGS1);
	clearw(0x0100, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_FLAGS2);

	outbw(0, io + SZDC_SET_DATA_BUS);
}

static void get_photo_straight(struct sharpzdc_info *zdcinfo, void *buf)
{
	int width = zdcinfo->width;
	unsigned line_stride = zdcinfo->line_stride;
	void __iomem *io = zdcinfo->io;
	void *cur_buf = buf;
	void *end_buf = buf + zdcinfo->image_size;

	BUG_ON(width & 1);
	BUG_ON(line_stride & 3);
	BUG_ON(((long)buf) & 3);

	while (cur_buf < end_buf) {
		unsigned *pos = cur_buf;
		unsigned *end = cur_buf + (width << 1);
		while (pos < end) {
			unsigned data = ioread32(io + SZDC_DATA);
			*(pos++) = data;
		}
		cur_buf += line_stride;
	}
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
int sharpzdc_get(struct sharpzdc_info *zdcinfo, char *buf)
{
	void __iomem *io = zdcinfo->io;
	unsigned short dram1, dram2;
	unsigned short reald1, reald2;
	unsigned short zoomd1, zoomd2;
	unsigned short temp1, temp2;
	unsigned short raw_zoom;
	unsigned short z = 256;

	if (wait_capture(io) == 0)
		return 0;

	reald1 = zdcinfo->width;
	reald2 = zdcinfo->height;
	zoomd1 = reald1 * z/256;
	zoomd2 = reald2 * z/256;

	if ((zoomd1 > 640) || (zoomd2 == 0) ||
		(zoomd2 > 480)) {
		return 0;
	}
	raw_zoom = MIN(640*256 / zoomd1, 480*256 / zoomd2);
	zoomd1 = 640*256 / raw_zoom;
	zoomd2 = 480*256 / raw_zoom;

	set_dram_ctrl(io, 0, ((zoomd2 >> 3) << 8) | ((zoomd1 >> 4) << 0));
	set_vga(io, 2, zoomd1);
	set_vga(io, 4, raw_zoom);
	set_vga(io, 5, raw_zoom); /* field_34 */

	temp1 = (zoomd1 - reald1) >> 1;
	temp2 = (zoomd2 - reald2) >> 1;

	setw(SZDC_FLAGS1_CAPTURING, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_SET_DATA_BUS);

	if (wait_capture(io) == 0)
		return 0;
	if (zdcinfo->readmode & SZDC_READMODE_BETTER) {
		clearw(0x4000, io + SZDC_FLAGS1);
		setw(0x4000, io + SZDC_FLAGS2);
	}

	dram1 = 0;
	dram2 = 0;
	if (zdcinfo->readmode & SZDC_READMODE_XFLIP) {
		dram1 |= (zoomd1 - temp1) >> 4;
		dram2 |= temp1 >> 4;
		dram2 |= 0x4000;
	} else {
		dram1 |= temp1 >> 4;
		dram2 |= (zoomd1 - temp1) >> 4;
	}
	if (zdcinfo->readmode & SZDC_READMODE_YFLIP) {
		dram1 |= ((zoomd2 - temp2) >> 3) << 8;
		dram2 |= 0x8000;
	} else {
		dram1 |= (temp2 >> 3) << 8;
	}

	set_dram_ctrl(io, 1, dram1);
	set_dram_ctrl(io, 2, dram2);

	if (zdcinfo->readmode & SZDC_READMODE_XFLIP)
		setw(SZDC_FLAGS2_XFLIP, io + SZDC_FLAGS2);
	else
		clearw(SZDC_FLAGS2_XFLIP, io + SZDC_FLAGS2);

	setw(SZDC_FLAGS1_RESET_PTR, io + SZDC_FLAGS1);
	udelay(100);
	clearw(SZDC_FLAGS1_RESET_PTR, io + SZDC_FLAGS1);

	ioread32(io + SZDC_DATA); /* XXX: was inw */
	get_photo_straight(zdcinfo, buf);
	if (zdcinfo->readmode & SZDC_READMODE_BETTER) {
		setw(0x4000, io + SZDC_FLAGS1);
		clearw(0x4000, io + SZDC_FLAGS2);
	}
	outbw(0, io + SZDC_SET_DATA_BUS);
	return zdcinfo->image_size;
}

#if 0

static int sharpzdc_status(struct sharpzdc_info *zdcinfo, char *buf, size_t size, loff_t *off)
{
	void __iomem *io = zdcinfo->io;
	unsigned short data;
	if (size)
		memset(buf, 0, size);
	data = inbw(io + SZDC_FLAGS1);
	if (size != 0)
		buf[0] = (data & SZDC_FLAGS1_SHUTTER) ? 'S' : 's';
	if (size >= 2)
		buf[1] = (data & SZDC_FLAGS1_REVERSE_DETECTED) ? 'M' : 'm';
	if (size >= 3)
		buf[2] = (data & SZDC_FLAGS1_CAPTURING) ? 'C' : 'c';
	if (size >= 4)
		buf[3] = 'A';
	outbw(0, io + SZDC_SET_DATA_BUS);
	*off += size;
	return size;
}
static int sharpzdc_shutterclear(struct sharpzdc_info *zdcinfo)
{
	void __iomem *io = zdcinfo->io;
	clearw(SZDC_FLAGS1_SHUTTER, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_SET_DATA_BUS);
	return 1;
}
static int sharpzdc_setiris(struct sharpzdc_info *zdcinfo)
{
	void __iomem *io = zdcinfo->io;
	mcon_send_enable(io);
	mcon_send(io, 0xF0A, zdcinfo->iris);
	mcon_send_disable(io, 0);
	outbw(0, io + SZDC_SET_DATA_BUS);
	return 1;
}

static int param_modeset(struct sharpzdc_info *zdcinfo, const char *data)
{
	void __iomem *io = zdcinfo->io;
	int val;
	unsigned orig = zdcinfo->readmode;
	int ret = get_param_value(data, '=', &val);
	unsigned new, diff;
	if (ret == 0)
		return 0;
	zdcinfo->readmode = (val & 0xf) | (zdcinfo->readmode & SZDC_READMODE_ROTATE);
	diff = zdcinfo->readmode ^ orig;
	if (diff & SZDC_READMODE_BETTER) {
		wait_capture(zdcinfo->io);
		if (zdcinfo->readmode & SZDC_READMODE_BETTER) {
			setw(0x4000, io + SZDC_FLAGS1);
			clearw(0x4000, io + SZDC_FLAGS2);
		} else {
			clearw(0x4000, io + SZDC_FLAGS1);
			setw(0x4000, io + SZDC_FLAGS2);
		}
	}
	return 1;
}
#endif

void sharpzdc_info_release(struct kref *ref)
{
	struct sharpzdc_info *info = to_zdcinfo(ref);

	pr_debug("%s\n", __func__);

	kfree(info);
}

static int __devinit sharpzdc_config_check(struct pcmcia_device *link,
		cistpl_cftable_entry_t *cfg,
		cistpl_cftable_entry_t *dflt,
		unsigned int vcc,
		void *priv_data)
{
	if (cfg->index == 0)
		return -ENODEV;

	/* Use power settings for Vcc and Vpp if present */
	/*  Note that the CIS values need to be rescaled */
	if (cfg->vcc.present & (1<<CISTPL_POWER_VNOM)) {
		if (vcc != cfg->vcc.param[CISTPL_POWER_VNOM]/10000)
			return -ENODEV;
	} else if (dflt->vcc.present & (1<<CISTPL_POWER_VNOM)) {
		if (vcc != dflt->vcc.param[CISTPL_POWER_VNOM]/10000)
			return -ENODEV;
	}

	if (cfg->vpp1.present & (1<<CISTPL_POWER_VNOM))
		link->conf.Vpp = cfg->vpp1.param[CISTPL_POWER_VNOM]/10000;
	else if (dflt->vpp1.present & (1<<CISTPL_POWER_VNOM))
		link->conf.Vpp = dflt->vpp1.param[CISTPL_POWER_VNOM]/10000;

	/* This card unfortunately doesn't have IRQ
	 * link->conf.Attributes |= CONF_ENABLE_IRQ; */

	/* IO window settings */
	link->io.NumPorts1 = 0;
	link->io.NumPorts2 = 0;
	if ((cfg->io.nwin > 0) || (dflt->io.nwin > 0)) {
		cistpl_io_t *io = (cfg->io.nwin) ? &cfg->io : &dflt->io;
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
	}

	/* This reserves IO space but doesn't actually enable it */
	if (pcmcia_request_io(link, &link->io) != 0)
		return -ENODEV;

	return 0;
}

static int __devinit sharpzdc_config(struct pcmcia_device *link)
{
	tuple_t tuple;
	u_short buf[64];
	int ret;

	pr_debug("%s\n", __func__);

	tuple.TupleData = (cisdata_t *)buf;
	tuple.TupleDataMax = sizeof(buf);
	tuple.TupleOffset = 0;

	tuple.Attributes = 0;
	tuple.DesiredTuple = CISTPL_CFTABLE_ENTRY;

	ret = pcmcia_loop_config(link, sharpzdc_config_check, NULL);
	if (ret) {
		goto failed;
	}

	if (link->conf.Attributes & CONF_ENABLE_IRQ) {
		ret = pcmcia_request_irq(link, &link->irq);
		if (ret)
			goto failed;
	}

	ret = pcmcia_request_configuration(link, &link->conf);
	if (ret)
		goto failed;

	/* Finally, report what we've done */
	printk(KERN_INFO "%s: index 0x%02x: ",
		   dev_name(&link->dev), link->conf.ConfigIndex);
	if (link->conf.Vpp)
		printk(", Vpp %d.%d", link->conf.Vpp/10, link->conf.Vpp%10);
	if (link->conf.Attributes & CONF_ENABLE_IRQ)
		printk(", irq %d", link->irq.AssignedIRQ);
	if (link->io.NumPorts1)
		printk(", io 0x%04x-0x%04x", link->io.BasePort1,
			   link->io.BasePort1+link->io.NumPorts1-1);
	if (link->io.NumPorts2)
		printk(" & 0x%04x-0x%04x", link->io.BasePort2,
			   link->io.BasePort2+link->io.NumPorts2-1);
	printk("\n");

	return 0;

failed:
	pcmcia_disable_device(link);
	return -ENODEV;
}

static int __devinit sharpzdc_probe(struct pcmcia_device *link)
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
	init_completion(&info->finish);

	info->p_dev = link;
	link->priv = info;

	link->irq.Attributes = IRQ_TYPE_DYNAMIC_SHARING;
	link->conf.Attributes = 0;
	link->conf.IntType = INT_MEMORY_AND_IO;

	ret = sharpzdc_config(link);
	if (ret)
		goto err_config;

	info->io = ioport_map(link->io.BasePort1, link->io.NumPorts1);
	if (!info->io)
		goto err_map;

	info->width = 320;
	info->height = 240;
	info->line_stride = info->width * 2;
	info->image_size = info->line_stride * info->height;

	ret = sharpzdc_start(info);
	if (ret)
		goto err_start;

	info->thread = kthread_run(sharpzdc_kthread, info,
		      "sharpzdc: %s", dev_name(&link->dev));
	if (IS_ERR(info->thread)) {
		ret = PTR_ERR(info->thread);
		goto err_thread;
	}

	ret = sharpzdc_vdev_init(&link->dev, info);
	if (ret)
		goto err_vdev;

	return 0;
err_vdev:
	kthread_stop(info->thread);
	wait_for_completion(&info->finish);
err_thread:
	sharpzdc_stop(info);
err_start:
	ioport_unmap(info->io);
err_map:
	pcmcia_disable_device(link);
err_config:
	kref_put(&info->ref, sharpzdc_info_release); /* put initial reference */
	return ret;
}

static void sharpzdc_remove(struct pcmcia_device *link)
{
	struct sharpzdc_info *info = link->priv;
	pr_debug("%s\n", __func__);

	sharpzdc_vdev_exit(info);

	kthread_stop(info->thread);
	wait_for_completion(&info->finish);

	sharpzdc_stop(info);

	ioport_unmap(info->io);
	pcmcia_disable_device(link);
	kref_put(&info->ref, sharpzdc_info_release); /* put initial reference */
}

static struct pcmcia_device_id sharpzdc_ids[] = {
	PCMCIA_DEVICE_CIS_PROD_ID12("SHARP", "CEAG06  ", 0xb3ad4c1c, 0xe1d1a7a9, "cis/CE-AG06.cis"),
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
MODULE_FIRMWARE("ag6exe.bin");

