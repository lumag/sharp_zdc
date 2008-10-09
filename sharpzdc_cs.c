#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>

#include <pcmcia/cs_types.h>
#include <pcmcia/cs.h>
#include <pcmcia/cistpl.h>
#include <pcmcia/cisreg.h>
#include <pcmcia/ds.h>

#define SZDC_FLAGS1		0x0	/* bw */
#define SZDC_FLAGS1_CAPTURING	0x0001
#define SZDC_FLAGS1_RESET_PTR	0x0002
#define SZDC_FLAGS1_REVERSE_DETECTED 0x0004
#define SZDC_FLAGS1_SHUTTER	0x0008

#define SZDC_FLAGS2		0x2	/* bw */
#define SZDC_FLAGS2_XFLIP	0x0008

#define SZDC_DATA		0x4	/* l */

#define SZDC_DATA_BUS		0x6	/* bw */

#define SZDC_MCON		0x8	/* bw */
#define SZDC_MCON_RO		0x0001 /* at least it seems so */
#define SZDC_MCON_STROBE	0x0002
#define SZDC_MCON_DISABLED	0x0008
#define SZDC_MCON_ENABLED2	0x0010 /* seems to depend on MCON_DISABLED */
#define SZDC_MCON_READY		0x0020
#define SZDC_MCON_RESET		0x0040 /* toggled to start program */

#define SZDC_EEPROM		0xA	/* b */
#define SZDC_EEPROM_ENABLE	1 << 7
#define SZDC_EEPROM_CLOCK	1 << 3
#define SZDC_EEPROM_CS		1 << 2
#define SZDC_EEPROM_DATA_IN	1 << 1
#define SZDC_EEPROM_DATA_OUT	1 << 0

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

static int dev_maj;

typedef struct {
	struct pcmcia_device	*p_dev;
	struct miscdevice	mdev;
} sharpzdc_info_t;

struct drvWork_s {
//	int	field_00;
//	int	field_04;
//	int	field_08;
	ioaddr_t io;
//	int	field_10;
//	int	field_14;
	int	readmode;
	int	image_size;
	unsigned short	width;
	unsigned short	height;
	unsigned short	line_stride;
	short	field_26;
	unsigned short	field_28;
	unsigned short	field_2A;
//	short	field_2C;
//	short	field_2E;
	short	field_30;
	short	field_32;
//	short	field_34;
	unsigned short	iris;
	char	available;
//	int	hw_status; /* -1 => N/A, 0 => Stopped, >0 => working */
};
static struct drvWork_s* drvWork = &(struct drvWork_s){};
static struct pcmcia_device *zdcdev;

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

static void InitTable_CEAG06(ioaddr_t io) {
	int i;
	unsigned short r;

	for (i = 0; i < 0x1F; i++) {
		SetCamCoreData(io, 0x70, i);
		SetCamCoreData(io, 0x72, eep_data_read(io, i * 2 + 0xC0));
		SetCamCoreData(io, 0x74, eep_data_read(io, i * 2 + 0xC1));
	}

	for (i = 0; i < 0x16; i+= 2) {
		r = eep_data_read(io, i / 2 + 0x90);
		SetCamCoreData(io, 0x78, i);
		SetCamCoreData(io, 0x7A, r & 0xff);
		SetCamCoreData(io, 0x78, i + 1);
		SetCamCoreData(io, 0x7A, r >> 8);
	}

	for (i = 0; i < 0x10; i += 2) {
		r = eep_data_read(io, i / 2 + 0xA0);
		SetCamCoreData(io, 0x78, i + 0x100);
		SetCamCoreData(io, 0x7A, r & 0xff);
		SetCamCoreData(io, 0x78, i + 0x101);
		SetCamCoreData(io, 0x7A, r >> 8);
	}

	SetCamCoreData(io, 0x78, 0x110);
	SetCamCoreData(io, 0x7A, eep_data_read(io, 0xA8) & 0xff);
	SetCamCoreData(io, 0x7C, 0);
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
static int SendProgToMCon(ioaddr_t io, const unsigned short* prog, unsigned short size) {
	int ret;
	int i;
	if (size > 0x1000)
		return 0;
	if (size == 0)
		return 1;
	ret = EnableSendDataToMCon(io);
	if (ret == 0)
		return 0;

	for (i = 0; i < size && prog[i] != 0xffff; i++)
		SendDataToMCon(io, i, prog[i]);

	DisableSendDataToMCon(io, 1);
	return 1;
}
static int SetGammaData(ioaddr_t io, const void*gamma, unsigned char elemsize)
{
	if (elemsize > 2) {
		return 0;
	}
	SetCamCoreData(io, 0x44, 1);
	if (elemsize == 1) {
		int i;
		for (i = 0; i <= 0x3f; i++) {
			SetCamCoreData(io, 0x40, i);
			SetCamCoreData(io, 0x42, ((unsigned char*)gamma)[i]);
		}
	} else {
		int i;
		for (i = 0; i <= 0x3f; i++) {
			SetCamCoreData(io, 0x40, i);
			SetCamCoreData(io, 0x42, ((unsigned short*)gamma)[i]);
		}
	}
	SetCamCoreData(io, 0x44, 0);
	return 1;
}
#include "sharpzdc_ag6exe.h"
static void set_camera_param(ioaddr_t io) {
	int ret;
	int i;
	const unsigned short *d;
	int lim;
	ret = EnableSendDataToMCon(io);
	if (ret != 0) {
		lim = sizeof(sharpzdc_params) / sizeof(*sharpzdc_params);
		d = sharpzdc_params;
		for (i = 0; i < lim; i += 2) {
			SendDataToMCon(io, d[i], d[i+1]);
		}

		DisableSendDataToMCon(io, 0);
	}
	SetGammaData(io, sharpzdc_gamma, sizeof(*sharpzdc_gamma));
	lim = sizeof(sharpzdc_camcore) / sizeof(*sharpzdc_camcore);
	d = sharpzdc_camcore;
	for (i = 0; i < lim; i += 2) {
		SetCamCoreData(io, d[i], d[i+1]);
	}
}

static void sharpzdc_start(struct drvWork_s *drvWork) {
	ioaddr_t io = drvWork->io;

	outbw(0, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_FLAGS2);
	setw(0x0100, io + SZDC_FLAGS1);
	clearw(0x4000, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_DATA_BUS);

	udelay(1000);

	setw(0x8000, io + SZDC_FLAGS1);

	InitTable_CEAG06(io);

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

	SetDRAMCtrl(io, 0, 0x3C28);
	SetDRAMCtrl(io, 1, 0);
	SetDRAMCtrl(io, 2, 0x28);

	SetRealVGA(io, 0, 4);
	SetRealVGA(io, 1, 0x20);
	SetRealVGA(io, 2, 0x280);
	SetRealVGA(io, 4, 0x100);
	SetRealVGA(io, 5, 0x100);

	clearw(SZDC_FLAGS1_SHUTTER, io + SZDC_FLAGS1);

	setw(0x0800, io + SZDC_FLAGS2);
	clearw(0x2000, io + SZDC_FLAGS2);
	setw(0x1000, io + SZDC_FLAGS2);

	clearw(0x4000, io + SZDC_FLAGS1);
	setw(0x4000, io + SZDC_FLAGS2);


	drvWork->field_2A = 0xA;
//	drvWork->field_2C = 4;
	drvWork->field_26 = 0xF0A;
//	drvWork->field_2E = 0x20;
	drvWork->field_28 = 0;
	drvWork->field_32 = 0x400;
	drvWork->field_30 = 0xA0;
//	drvWork->field_34 = 0x400;
	set_camera_param(io);
	SendProgToMCon(io, ag6exe, sizeof(ag6exe)/sizeof(*ag6exe));
	EnableSendDataToMCon(io);
	SendDataToMCon(io, 0xF0A, 0x60);
	DisableSendDataToMCon(io, 0);
}

static void sharpzdc_stop(struct drvWork_s *drvWork) {
	ioaddr_t io = drvWork->io;

	clearw(0x8000, io + SZDC_FLAGS2);
	clearw(0x0200, io + SZDC_FLAGS1);
	clearw(0x8000, io + SZDC_FLAGS1);
	clearw(0x0100, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_FLAGS2);

	outbw(0, io + SZDC_DATA_BUS);
}

static int sharpzdc_capture(struct drvWork_s *drvWork) {
	ioaddr_t io = drvWork->io;
	int ret;

	ret = WaitCapture(io);
	if (ret == 0)
		return 0;

	SetDRAMCtrl(io, 0, drvWork->field_26);
	SetRealVGA(io, 2, drvWork->field_30);
	SetRealVGA(io, 4, drvWork->field_32);
	SetRealVGA(io, 5, drvWork->field_32); /* field_34 */

	setw(SZDC_FLAGS1_CAPTURING, io + SZDC_FLAGS1);

	outbw(0, io + SZDC_DATA_BUS);

	drvWork->available = 1;
	return 1;
}

static void get_photo_straight(struct drvWork_s *drvWork, void *buf)
{
	int width = drvWork->width;
	unsigned line_stride = drvWork->line_stride;
	ioaddr_t io = drvWork->io;
	void *cur_buf = buf;
	void *end_buf = buf + line_stride * drvWork->height;
	if ((width & 1) != 0 ||
			((line_stride & 3) != 0) ||
			 (((long)buf & 3) != 0)) {
		while (cur_buf < end_buf) {
			unsigned short *pos = cur_buf;
			unsigned short *end = cur_buf + (width << 1);
			while (pos < end) {
				unsigned data = inl(io + SZDC_DATA);
				*(pos++) = data;
				data >>= 16;
				*(pos++) = data;
			}
			cur_buf += line_stride;
		}
	} else {
		width >>= 1;
		while (cur_buf < end_buf) {
			unsigned *pos = cur_buf;
			unsigned *end = cur_buf + (width << 2);
			while (pos < end) {
				unsigned data = inl(io + SZDC_DATA);
				*(pos++) = data;
			}
			cur_buf += line_stride;
		}
	}
}
static void get_photo_rotate(struct drvWork_s *drvWork, void *buf)
{
	unsigned short line_stride = drvWork->line_stride;
	void *last_offset = buf + (drvWork->width * (sizeof(short)));
	ioaddr_t io = drvWork->io;
	unsigned end_offset = line_stride * (drvWork->height - 1);
	void *pos;



	while (buf < last_offset) {
		pos = buf + end_offset;
		if (pos >= buf) {
			do {
				unsigned data = inl(io + SZDC_DATA);
				*(unsigned short *)pos = (unsigned short)data;
				pos = pos - line_stride;
				*(unsigned short *)pos = (unsigned short)(data >> 16);
				pos = pos - line_stride;
			} while (pos >= buf);
		}
		buf += (sizeof(short));
	}
}

static int sharpzdc_get(struct drvWork_s *drvWork, char *buf, size_t size, loff_t *off) {
	unsigned short dram1, dram2;
	ioaddr_t io = drvWork->io;
	if (size < drvWork->image_size
		|| drvWork->image_size == 0) {
			return 0;
		}
	if (drvWork->available == 0)
		if (sharpzdc_capture(drvWork) == 0)
			return 0;
	if (WaitCapture(io) == 0)
		return 0;
	if (drvWork->readmode & SZDC_READMODE_BETTER) {
		clearw(0x4000, io + SZDC_FLAGS1);
		setw(0x4000, io + SZDC_FLAGS2);
	}

	dram1 = 0;
	dram2 = 0;
	if (drvWork->readmode & SZDC_READMODE_XFLIP) {
		dram1 |= drvWork->field_2A & 0x3f;
		dram2 |= drvWork->field_28 & 0x3f;
		dram2 |= 0x4000;
	} else {
		dram1 |= drvWork->field_28 & 0x3f;
		dram2 |= drvWork->field_2A & 0x3f;
	}
	if (drvWork->readmode & SZDC_READMODE_YFLIP) {
		dram1 |= drvWork->field_2A & 0x3f00;
		dram2 |= 0x8000;
	} else {
		dram1 |= drvWork->field_28 & 0x3f00;
	}
	SetDRAMCtrl(io, 1, dram1);
	SetDRAMCtrl(io, 2, dram2);

	if (drvWork->readmode & SZDC_READMODE_XFLIP) {
		setw(SZDC_FLAGS2_XFLIP, io + SZDC_FLAGS2);
	} else {
		clearw(SZDC_FLAGS2_XFLIP, io + SZDC_FLAGS2);
	}

	setw(SZDC_FLAGS1_RESET_PTR, io + SZDC_FLAGS1);
	udelay(100);
	clearw(SZDC_FLAGS1_RESET_PTR, io + SZDC_FLAGS1);

	inl(io + SZDC_DATA); /* XXX: was inw */
	if (drvWork->readmode & SZDC_READMODE_ROTATE)
		get_photo_rotate(drvWork, buf);
	else
		get_photo_straight(drvWork, buf);
	if (drvWork->readmode & SZDC_READMODE_BETTER) {
		setw(0x4000, io + SZDC_FLAGS1);
		clearw(0x4000, io + SZDC_FLAGS2);
	}
	outbw(0, io + SZDC_DATA_BUS);
	drvWork->available = 0;
	*off += (unsigned)drvWork->image_size;
	return drvWork->image_size;
}
static int sharpzdc_status(struct drvWork_s *drvWork, char *buf, size_t size, loff_t *off) {
	ioaddr_t io = drvWork->io;
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
	outbw(0, io + SZDC_DATA_BUS);
	*off += size;
	return size;
}
static int sharpzdc_shutterclear(struct drvWork_s *drvWork)
{
	ioaddr_t io = drvWork->io;
	clearw(SZDC_FLAGS1_SHUTTER, io + SZDC_FLAGS1);
	outbw(0, io + SZDC_DATA_BUS);
	return 1;
}
static int sharpzdc_setiris(struct drvWork_s *drvWork)
{
	ioaddr_t io = drvWork->io;
	EnableSendDataToMCon(io);
	SendDataToMCon(io, 0xF0A, drvWork->iris);
	DisableSendDataToMCon(io, 0);
	outbw(0, io + SZDC_DATA_BUS);
	return 1;
}
static int skip_spaces(const char *s) {
	const char *t = s;
	while (((*t)-1) < (unsigned)'\x20')
		t++;
	return t - s;
}

static int str_to_value(const char *str, int *resptr)
{
	int res;
	const char *ptr = str;
	int is_hex = 0;
	int valid = 0;
	char c;
	res = 0;
	if (*ptr == '0') {
		if (ptr[1] == 'x' || ptr[1] == 'X') {
			ptr += 2;
			is_hex = 1;
		}
	}

	while (*ptr) {
		c = *ptr;
		if (c >= '0' && c <= '9') {
			c = (c - '0') & 0xff;
		} else if (is_hex) {
			if (c >= 'a' && c <= 'f')
				c = c + 10 - 'a';
			else if (c >= 'A' && c <= 'F')
				c = c + 10 - 'A';
			else
				break;
		} else
			break;
		if (is_hex)
			res = res * 16 + c;
		else
			res = res * 10 + c;

		valid = 1;
		ptr ++;
	}

	if (!valid)
		return 0;

	if (resptr != NULL)
		*resptr = res;

	return ptr - str;
}
static int get_param_value(const char *str, char c, unsigned *resptr)
{
	int ret;
	const char *s = str + skip_spaces(str);
	if (c != '\0') {
		if (c != *s)
			return 0;

		s ++;

		s += skip_spaces(s);
	}

	ret = str_to_value(s, resptr);
	if (ret == 0)
		return 0;
	s += ret;
	return s - str;
}
static int param_viewsize(struct drvWork_s *drvWork, const char *data, int rotate)
{
	int val;
	int ret;
	unsigned short w, h, z, l; /* r10, r9, r7, r8 */
	unsigned short reald1, reald2;
	unsigned short zoomd1, zoomd2;
	unsigned short temp1, temp2;
	ret = get_param_value(data, '=', &val);
	if (ret == 0)
		return 0;
	data += ret;

	w = val;
	ret = get_param_value(data, ',', &val);
	if (ret == 0)
		return 0;
	data += ret;

	h = val;
	val = 1;
	ret = get_param_value(data, ',', &val);
	z = val;
	val = 0;
	if (ret) {
		data += ret;
		ret = get_param_value(data, ',', &val);
	}
	l = val;

	if (rotate) {
		reald1 = h;
		reald2 = w;
	} else {
		reald1 = w;
		reald2 = h;
	}

	zoomd1 = reald1 * z/256;
	zoomd2 = reald2 * z/256;
	if ((zoomd1 > 640) || (zoomd2 == 0) ||
		(zoomd2 > 480)) {
		return 0;
	}
	temp1 = 640*256 / zoomd1;
	temp2 = 480*256 / zoomd2;
	if (temp1 < temp2)
		zoomd2 = 480*256 / temp1;
	else if (temp1 > temp2) {
		temp1 = temp2;
		zoomd1 = 640*256 / temp1;
	}

	drvWork->available = 0;
	if (rotate)
		drvWork->readmode |= SZDC_READMODE_ROTATE;
	else
		drvWork->readmode &= ~SZDC_READMODE_ROTATE;

	if ((unsigned)l < (unsigned)(w*2)) {
		l = w * 2;
	}
	drvWork->image_size = l * h;
	drvWork->width = w;
	drvWork->height = h;
	drvWork->line_stride = l;
//	drvWork->field_2C = 4;
//	drvWork->field_2E = 0x20;
	drvWork->field_30 = zoomd1;
	drvWork->field_32 = temp1;
//	drvWork->field_34 = temp1;

	drvWork->field_26 = ((zoomd2 >> 3) << 8) | ((zoomd1 >> 4) << 0);

	temp1 = (zoomd1 - reald1) >> 1;
	temp2 = (zoomd2 - reald2) >> 1;
	drvWork->field_28 = ((temp2 >> 3) << 8) | (temp1 >> 4);

	temp1 = (zoomd1 - temp1);
	temp2 = (zoomd2 - temp2);
	drvWork->field_2A =  ((temp2 >> 3 )<< 8) | (temp1 >> 4);
	return 1;
}
static int param_modeset(struct drvWork_s *drvWork, const char *data)
{
	ioaddr_t io = drvWork->io;
	int val;
	unsigned orig = drvWork->readmode;
	int ret = get_param_value(data, '=', &val);
	unsigned new, diff;
	if (ret == 0)
		return 0;
	drvWork->readmode = new = (val & 0xf) | (drvWork->readmode & SZDC_READMODE_ROTATE);
	diff = new ^ orig;
//	val = new & SZDC_READMODE_BETTER;
	if (diff & SZDC_READMODE_BETTER) {
		WaitCapture(drvWork->io);
		if (drvWork->readmode & SZDC_READMODE_BETTER) {
			setw(0x4000, io + SZDC_FLAGS1);
			clearw(0x4000, io + SZDC_FLAGS2);
		} else {
			clearw(0x4000, io + SZDC_FLAGS1);
			setw(0x4000, io + SZDC_FLAGS2);
		}
	}
	return 1;
}
static int param_irisset(struct drvWork_s *drvWork, const char *data)
{
	int val;
	int ret = get_param_value(data, '=', &val);
	if (ret == 0)
		return 0;
	if (val < 0) {
		val = 0;
	} else if (val > 0xff) {
		val = 0xff;
	}

	drvWork->iris = (unsigned short) val;

	return sharpzdc_setiris(drvWork);
}
static int sharpzdc_param_part(struct drvWork_s *drvWork, const char *param) {
	char c;
	param += skip_spaces(param);
	c = *param;
	switch (c) {
		case 'B':
			return sharpzdc_shutterclear(drvWork);
		case 'C':
			return sharpzdc_capture(drvWork);
		case 'I':
			return param_irisset(drvWork, param + 1);
		case 'M':
			return param_modeset(drvWork, param + 1);
		case 'R':
			return param_viewsize(drvWork, param + 1, 1);
		case 'S':
			return param_viewsize(drvWork, param + 1, 0);
		default:
			return 0;
		case '#':
		case '\0':
			return 1;
	}
}
static int get_param_line(char *buf, int size, const char *param, int len)
{
	char c;
	int i;
	size --;
	for (i = 0; ; i++, param ++) {
		if (i >= len)
			break;

		c = *param;
		if (!c)
			break;

		if (i < size)
			*(buf++) = c;

		if (*param == '\n') {
			if (i < size) {
				buf --;
			}
			i++;
			break;
		}
	}
	*buf = '\0';
	return i;
}
static ssize_t sharpzdc_param(struct drvWork_s *drvWork, const char *buf, size_t size, loff_t *off)
{
	const char *ptr = buf;
	int left = size;
	int tlen = 0;
	char temp[160];
	while (left > 0) {
		if (!*ptr)
			break;
		tlen = get_param_line(temp, sizeof(temp), ptr, left);
		if (tlen == 0)
			continue;

		if (sharpzdc_param_part(drvWork, temp) == 0)
			break;
		ptr += tlen;
		left -= tlen;
	}
	*off += size;
	return size;
}
static int sharpzdc_open(struct inode *inode, struct file *file)
{
//	if (drvWork->hw_status < 0) {
//		printk(KERN_WARNING "sharpzdc_cs: Device Dead!\n");
//		return -EBUSY;
//	}

//	if (!(dev->state & DEV_SUSPEND)) {
//		printk(KERN_WARNING "sharpzdc_cs: Device not ready!\n");
//		return -EBUSY;
//	}

//	drvWork->hw_status = 1;

//	CardServices(ResumeCard, dev->handle);

	drvWork->io = zdcdev->io.BasePort1;
	sharpzdc_start(drvWork);

//	MOD_INC_USE_COUNT;

	return 0;
}

static int sharpzdc_close(struct inode *inode, struct file *file)
{
//	if (drvWork->hw_status > 0) {
		sharpzdc_stop(drvWork);
//		drvWork->hw_status = 0;
////		CardServices(SuspendCard, dev->handle);
//	}

//	MOD_DEC_USE_COUNT;

	return 0;
}

static int sharpzdc_ioctl(struct inode *inode, struct file *file,
		unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

static ssize_t sharpzdc_read(struct file *file, char *buf, size_t size, loff_t *off) {
	if ((drvWork->readmode & SZDC_READMODE_STATUS))
		return sharpzdc_status(drvWork, buf, size, off);

//	if (drvWork->hw_status < 0)
//		return drvWork->readmode & 1;

	return sharpzdc_get(drvWork, buf, size, off);
}
static ssize_t sharpzdc_write(struct file *file, const char *buf, size_t size, loff_t *off) {
	return sharpzdc_param(drvWork, buf, size, off);
}

static struct file_operations zdc_ops = {
	.owner		= THIS_MODULE,
	.read = sharpzdc_read,
	.write = sharpzdc_write,
	.ioctl = sharpzdc_ioctl,
	.open = sharpzdc_open,
	.release = sharpzdc_close,
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

	info->mdev.minor = MISC_DYNAMIC_MINOR;
	info->mdev.name = "sharp_zdc";
	info->mdev.fops = &zdc_ops;
	info->mdev.parent = &link->dev;
	ret = misc_register(&info->mdev);
	if (ret)
		goto err2;

	zdcdev = link;

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
	zdcdev = NULL;
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

