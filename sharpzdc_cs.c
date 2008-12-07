//#define DEBUG
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
#include <linux/firmware.h>

#include <media/v4l2-dev.h>
#include <media/v4l2-ioctl.h>
#include <media/videobuf-vmalloc.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>

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

#define SZDC_READMODE_STATUS	0x01 /* rather than image */
#define SZDC_READMODE_BETTER	0x02 /* rather than faster */
#define SZDC_READMODE_XFLIP	0x04
#define SZDC_READMODE_YFLIP	0x08
#define SZDC_READMODE_ROTATE	0x10

static unsigned int vid_limit = 16;	/* Video memory limit, in Mb */
module_param(vid_limit, int, 0644);
MODULE_PARM_DESC(vid_limit, "capture memory limit in megabytes");

#define to_zdcinfo(r)	container_of(r, struct sharpzdc_info, ref)

struct sharpzdc_info {
	struct kref		ref;
	struct pcmcia_device	*p_dev;
	struct video_device	*vdev;

	struct videobuf_queue	vb_vidq;
	struct list_head	queued;
	spinlock_t		lock;

	struct task_struct	*thread;
	wait_queue_head_t	wq;

	ioaddr_t io;
	int	readmode;
	int	image_size;
	unsigned short	width;
	unsigned short	height;
	unsigned short	line_stride;

};

// inl is usual
/*
#undef outb
static inline void outb(u8 data, ioaddr_t io)
{
	*(volatile u8*)io = data;
}
*/
#define inbw(io)  (inb(io) | (inb((io) + 1) << 8))
#define outbw(data, io) \
	inb(io);		  \
	outb(data, io);   \
	inb(io+1);		\
	outb(data >> 8, io+1);
#define setw(bit, io)   \
	{				\
		unsigned short d;\
		d = inbw(io);  \
		d |= (bit);	   \
		outbw(d, io);  \
	}

#define clearw(bit, io)   \
	{				\
		unsigned short d;\
		d = inbw(io);  \
		d &= ~(bit);	   \
		outbw(d, io);  \
	}

static const unsigned short sharpzdc_params[] = {
	0xFA0,	0,
	0xF0E,	0x50,
	0xF0F,	0x60,
	0xF0B,	1,
	0xF0C,	3,
	0xF0D,	2,
	0xF0A,	0x60,
};
static const unsigned short sharpzdc_camcore[] = {
	0x50,	0x25,
	0x52,	0xcd,
	0x54,	0x55,
	0x56,	0x9d,
	0x50,	0x25,
	0x52,	0xcd,
	0x60,	0x1285,
};

static const unsigned short sharpzdc_gamma[] = {
	0x00, 0x03, 0x05, 0x07, 0x09, 0x0a, 0x0c, 0x0d,
	0x0f, 0x10, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x25, 0x26,
	0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2c, 0x2d,
	0x2e, 0x2f, 0x30, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x34, 0x35, 0x36, 0x37, 0x37, 0x38, 0x39, 0x3a,
	0x3a, 0x3b, 0x3c, 0x3d, 0x3d, 0x3e, 0x3f, 0x3f,
};


static void SetCamCoreData(ioaddr_t io, unsigned short addr, unsigned short data) {
	outb(SZDC_BUS_SELECT_CORE, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);
}
static void SetDRAMCtrl(ioaddr_t io, unsigned short addr, unsigned short data) {
	outb(SZDC_BUS_SELECT_DRAM, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);
}
static void SetRealVGA(ioaddr_t io, unsigned short addr, unsigned short data) {
	outb(SZDC_BUS_SELECT_VGA, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);
}

static void eep_data_out(ioaddr_t io, int data) {
	char val = SZDC_EEPROM_ENABLE | SZDC_EEPROM_CS;
	if (data)
		val |= SZDC_EEPROM_DATA_OUT;

	outb(val, io + SZDC_EEPROM);
	udelay(4);
	val |= SZDC_EEPROM_CLOCK;
	outb(val, io + SZDC_EEPROM);
	udelay(4);
}

static unsigned short eep_data_read(ioaddr_t io, unsigned char addr)
{
	unsigned short result = 0;
	int i;

	outb(SZDC_EEPROM_ENABLE, io + SZDC_EEPROM);
	udelay(4);
	outb(SZDC_EEPROM_ENABLE | SZDC_EEPROM_CS, io + SZDC_EEPROM);
	udelay(4);

	eep_data_out(io, 1);
	eep_data_out(io, 1);
	eep_data_out(io, 0);

	for (i = 7; i >= 0; i --)
		eep_data_out(io, addr & (1 << i));

	for (i = 0xF; i >= 0; i--) {
		eep_data_out(io, 0);
		result <<= 1;
		if (inb(io + SZDC_EEPROM) & SZDC_EEPROM_DATA_IN) {
			result |= 1;
		}
	}

	outb(SZDC_EEPROM_ENABLE | SZDC_EEPROM_CS, io + SZDC_EEPROM);
	udelay(4);
	outb(SZDC_EEPROM_ENABLE, io + SZDC_EEPROM);
	udelay(4);
	outb(0, io + SZDC_EEPROM);
	udelay(4);

	return result;
}

static int WaitCapture(ioaddr_t io) {
	int cnt;

	cnt = 0x100000;
	while (1) {
		if (!--cnt)
			return 0;
		if ((inbw(io + SZDC_FLAGS1) & SZDC_FLAGS1_CAPTURING) == 0)
			return 1;
	}
}
static int EnableSendDataToMCon(ioaddr_t io) {
	int i;
	clearw(SZDC_MCON_DISABLED, io + SZDC_MCON);
	setw(SZDC_MCON_ENABLED2, io + SZDC_MCON);

	i = 0x500000;
	while ((inbw(io + SZDC_MCON) & SZDC_MCON_READY) == 0) {
		i --;
		if (i == 0) {
			clearw(SZDC_MCON_ENABLED2, io + SZDC_MCON);
			return 0;
		}
	}

	return 1;

}
static void DisableSendDataToMCon(ioaddr_t io, unsigned char start) {

	clearw(SZDC_MCON_ENABLED2, io + SZDC_MCON);
	if (start) {
		clearw(SZDC_MCON_RESET, io + SZDC_MCON);
		setw(SZDC_MCON_RESET, io + SZDC_MCON);
		clearw(SZDC_MCON_RESET, io + SZDC_MCON);
	}
	setw(SZDC_MCON_DISABLED, io + SZDC_MCON);
}

static void SendDataToMCon(ioaddr_t io, unsigned short addr, unsigned short data) {
	unsigned short d;
	outb(SZDC_BUS_SELECT_MCON, io + SZDC_BUS_SELECT);
	outbw(addr, io + SZDC_BUS_ADDR);
	outbw(data, io + SZDC_BUS_DATA);

	clearw(SZDC_MCON_RO, io + SZDC_MCON);

	d = inbw(io + SZDC_MCON);
	outbw(d |  SZDC_MCON_STROBE, io + SZDC_MCON);
	outbw(d & ~SZDC_MCON_STROBE, io + SZDC_MCON);
	outbw(d |  SZDC_MCON_STROBE, io + SZDC_MCON);


	setw(SZDC_MCON_RO, io + SZDC_MCON);
}

static int sharpzdc_start(struct sharpzdc_info *zdcinfo) {
	ioaddr_t io = zdcinfo->io;
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
		SetCamCoreData(io, 0x70, i);
		SetCamCoreData(io, 0x72, eep_data_read(io, i * 2 + 0xC0));
		SetCamCoreData(io, 0x74, eep_data_read(io, i * 2 + 0xC1));
	}

	for (i = 0; i < 0x16; i+= 2) {
		unsigned short r = eep_data_read(io, i / 2 + 0x90);
		SetCamCoreData(io, 0x78, i);
		SetCamCoreData(io, 0x7A, r & 0xff);
		SetCamCoreData(io, 0x78, i + 1);
		SetCamCoreData(io, 0x7A, r >> 8);
	}

	for (i = 0; i < 0x10; i += 2) {
		unsigned short r = eep_data_read(io, i / 2 + 0xA0);
		SetCamCoreData(io, 0x78, i + 0x100);
		SetCamCoreData(io, 0x7A, r & 0xff);
		SetCamCoreData(io, 0x78, i + 0x101);
		SetCamCoreData(io, 0x7A, r >> 8);
	}

	SetCamCoreData(io, 0x78, 0x110);
	SetCamCoreData(io, 0x7A, eep_data_read(io, 0xA8) & 0xff);
	SetCamCoreData(io, 0x7C, 0);

	setw(0x0200, io + SZDC_FLAGS1);
	setw(0x0c00, io + SZDC_FLAGS1);

	setw(0x8000, io + SZDC_FLAGS2);
	setw(0x0700, io + SZDC_FLAGS2);
	setw(0x0800, io + SZDC_FLAGS2);
	setw(0x1000, io + SZDC_FLAGS2);
	setw(0x00c0, io + SZDC_FLAGS2);
	clearw(0x0007, io + SZDC_FLAGS2);
	setw(0x0001, io + SZDC_FLAGS2);

	SetCamCoreData(io, 0x44, 1);

	SetDRAMCtrl(io, 0, 0x3C28); /* 640 x 480 */
	SetDRAMCtrl(io, 1, 0);
	SetDRAMCtrl(io, 2, 0x28);

	SetRealVGA(io, 0, 4);
	SetRealVGA(io, 1, 0x20);
	SetRealVGA(io, 2, 0x280); /* 640 */
	SetRealVGA(io, 4, 0x100);
	SetRealVGA(io, 5, 0x100);

	clearw(SZDC_FLAGS1_SHUTTER, io + SZDC_FLAGS1);

	setw(0x0800, io + SZDC_FLAGS2);
	clearw(0x2000, io + SZDC_FLAGS2);
	setw(0x1000, io + SZDC_FLAGS2);

	clearw(0x4000, io + SZDC_FLAGS1);
	setw(0x4000, io + SZDC_FLAGS2);

	ret = EnableSendDataToMCon(io);
	if (ret != 0) {
		for (i = 0; i < sizeof(sharpzdc_params) / sizeof(*sharpzdc_params); i += 2) {
			SendDataToMCon(io, sharpzdc_params[i], sharpzdc_params[i+1]);
		}

		DisableSendDataToMCon(io, 0);
	}

	SetCamCoreData(io, 0x44, 1);
	for (i = 0; i <= 0x3f; i++) {
		SetCamCoreData(io, 0x40, i);
		SetCamCoreData(io, 0x42, sharpzdc_gamma[i]);
	}
	SetCamCoreData(io, 0x44, 0);

	for (i = 0; i < sizeof(sharpzdc_camcore) / sizeof(*sharpzdc_camcore); i += 2) {
		SetCamCoreData(io, sharpzdc_camcore[i], sharpzdc_camcore[i+1]);
	}

	ret = EnableSendDataToMCon(io);
	if (ret == 0) {
		release_firmware(ag6exe);
		return -ENOTTY;
	}

	for (i = 0; i < ag6exe->size/2 && *((unsigned short *)ag6exe->data) != 0xffff; i++) {
		SendDataToMCon(io, i, ((unsigned short *)ag6exe->data)[i] );
	}

	DisableSendDataToMCon(io, 1);

	/*
	 * XXX: This is setiris
	 */
	EnableSendDataToMCon(io);
	SendDataToMCon(io, 0xF0A, 0x60);
	DisableSendDataToMCon(io, 0);

	release_firmware(ag6exe);

	return 0;
}

static void sharpzdc_stop(struct sharpzdc_info *zdcinfo) {
	ioaddr_t io = zdcinfo->io;

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
	ioaddr_t io = zdcinfo->io;
	void *cur_buf = buf;
	void *end_buf = buf + zdcinfo->image_size;

	BUG_ON(width & 1);
	BUG_ON(line_stride & 3);
	BUG_ON(((long)buf) & 3);

	while (cur_buf < end_buf) {
		unsigned *pos = cur_buf;
		unsigned *end = cur_buf + (width << 1);
		while (pos < end) {
			unsigned data = inl(io + SZDC_DATA);
			*(pos++) = data;
		}
		cur_buf += line_stride;
	}
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))
static int sharpzdc_get(struct sharpzdc_info *zdcinfo, char *buf) {
	ioaddr_t io = zdcinfo->io;
	unsigned short dram1, dram2;
	unsigned short reald1, reald2;
	unsigned short zoomd1, zoomd2;
	unsigned short temp1, temp2;
	unsigned short raw_zoom;
	unsigned short z = 256;

	if (WaitCapture(io) == 0)
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

	SetDRAMCtrl(io, 0, ((zoomd2 >> 3) << 8) | ((zoomd1 >> 4) << 0));
	SetRealVGA(io, 2, zoomd1);
	SetRealVGA(io, 4, raw_zoom);
	SetRealVGA(io, 5, raw_zoom); /* field_34 */

	temp1 = (zoomd1 - reald1) >> 1;
	temp2 = (zoomd2 - reald2) >> 1;

	setw(SZDC_FLAGS1_CAPTURING, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_SET_DATA_BUS);

	if (WaitCapture(io) == 0)
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
		dram1 |= (temp2 >> 3)<< 8;
	}

	SetDRAMCtrl(io, 1, dram1);
	SetDRAMCtrl(io, 2, dram2);

	if (zdcinfo->readmode & SZDC_READMODE_XFLIP) {
		setw(SZDC_FLAGS2_XFLIP, io + SZDC_FLAGS2);
	} else {
		clearw(SZDC_FLAGS2_XFLIP, io + SZDC_FLAGS2);
	}

	setw(SZDC_FLAGS1_RESET_PTR, io + SZDC_FLAGS1);
	udelay(100);
	clearw(SZDC_FLAGS1_RESET_PTR, io + SZDC_FLAGS1);

	inl(io + SZDC_DATA); /* XXX: was inw */
	get_photo_straight(zdcinfo, buf);
	if (zdcinfo->readmode & SZDC_READMODE_BETTER) {
		setw(0x4000, io + SZDC_FLAGS1);
		clearw(0x4000, io + SZDC_FLAGS2);
	}
	outbw(0, io + SZDC_SET_DATA_BUS);
	return zdcinfo->image_size;
}

#if 0

static int sharpzdc_status(struct sharpzdc_info *zdcinfo, char *buf, size_t size, loff_t *off) {
	ioaddr_t io = zdcinfo->io;
	unsigned short data;
	if (size)
		memset(buf, 0, size);
	data = inbw(io + SZDC_FLAGS1);
	if (size != 0) {
		buf[0] = (data & SZDC_FLAGS1_SHUTTER) ? 'S' : 's';
	}
	if (size >= 2) {
		buf[1] = (data & SZDC_FLAGS1_REVERSE_DETECTED) ? 'M' : 'm';
	}
	if (size >= 3) {
		buf[2] = (data & SZDC_FLAGS1_CAPTURING) ? 'C' : 'c';
	}
	if (size >= 4) {
		buf[3] = 'A';
	}
	outbw(0, io + SZDC_SET_DATA_BUS);
	*off += size;
	return size;
}
static int sharpzdc_shutterclear(struct sharpzdc_info *zdcinfo)
{
	ioaddr_t io = zdcinfo->io;
	clearw(SZDC_FLAGS1_SHUTTER, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_SET_DATA_BUS);
	return 1;
}
static int sharpzdc_setiris(struct sharpzdc_info *zdcinfo)
{
	ioaddr_t io = zdcinfo->io;
	EnableSendDataToMCon(io);
	SendDataToMCon(io, 0xF0A, zdcinfo->iris);
	DisableSendDataToMCon(io, 0);
	outbw(0, io + SZDC_SET_DATA_BUS);
	return 1;
}

static int param_modeset(struct sharpzdc_info *zdcinfo, const char *data)
{
	ioaddr_t io = zdcinfo->io;
	int val;
	unsigned orig = zdcinfo->readmode;
	int ret = get_param_value(data, '=', &val);
	unsigned new, diff;
	if (ret == 0)
		return 0;
	zdcinfo->readmode = new = (val & 0xf) | (zdcinfo->readmode & SZDC_READMODE_ROTATE);
	diff = new ^ orig;
	if (diff & SZDC_READMODE_BETTER) {
		WaitCapture(zdcinfo->io);
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


static void sharpzdc_fillbuff(struct sharpzdc_info* info, struct videobuf_buffer *vb)
{
	void *vbuf = videobuf_to_vmalloc(vb);

	pr_debug("%s\n", __func__);

	if (!vbuf)
		return;

	sharpzdc_get(info, vbuf);

	/* Advice that buffer was filled */
	vb->field_count += 1; /* two fields */
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

		try_to_freeze();
		schedule_timeout_interruptible(1000 * 30 / 1001);
//		wait_event_freezable(info->wq, !list_empty(&info->queued) || kthread_should_stop());

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
	// FIXME: width, height, bytesperline, sizeimage limitation wrt rotating and zoom.
	if (f->fmt.pix.width < 32)
		f->fmt.pix.width = 32;
	if (f->fmt.pix.width > 640)
		f->fmt.pix.width = 640;
	f->fmt.pix.width = (f->fmt.pix.width + 1) &~1;

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

	// FIXME: width, height, bytesperline, sizeimage limitation wrt rotating and zoom.
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

	info->io = link->io.BasePort1;

	info->vdev = video_device_alloc();
	if (info->vdev == NULL) {
		ret = -ENOMEM;
		goto err_vdev;
	}
	kref_get(&info->ref);
	video_set_drvdata(info->vdev, info);

	info->width = 320;
	info->height = 240;
	info->line_stride = info->width * 2;
	info->image_size = info->line_stride * info->height;

	info->vdev->parent = &link->dev;
	info->vdev->fops = &sharpzdc_fops;
	info->vdev->release = sharpzdc_vdev_release;
	info->vdev->ioctl_ops = &sharpzdc_ioctl_ops;
	info->vdev->tvnorms = V4L2_STD_UNKNOWN;
	info->vdev->current_norm = V4L2_STD_UNKNOWN;
	strncpy(info->vdev->name, "sharpzdc", sizeof(info->vdev->name));

	ret = sharpzdc_start(info);
	if (ret)
		goto err_start;

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
	sharpzdc_stop(info);
err_start:
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

	sharpzdc_stop(info);

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
MODULE_FIRMWARE("ag6exe.bin");

