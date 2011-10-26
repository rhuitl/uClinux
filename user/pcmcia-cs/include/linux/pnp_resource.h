#ifndef LINUX_PNP_RESOURCE
#define LINUX_PNP_RESOURCE

/* ISA Plug and Play Resource Definitions */

#define PNP_RES_LARGE_ITEM		0x80

/* Small resource items */
#define PNP_RES_SMTAG_VERSION		0x01
#define PNP_RES_SMTAG_LDID		0x02
#define PNP_RES_SMTAG_CDID		0x03
#define PNP_RES_SMTAG_IRQ		0x04
#define PNP_RES_SMTAG_DMA		0x05
#define PNP_RES_SMTAG_DEP_START		0x06
#define PNP_RES_SMTAG_DEP_END		0x07
#define PNP_RES_SMTAG_IO		0x08
#define PNP_RES_SMTAG_IO_FIXED		0x09
#define PNP_RES_SMTAG_VENDOR		0x0e
#define PNP_RES_SMTAG_END		0x0f

/* Large resource items */
#define PNP_RES_LGTAG_MEM		0x01
#define PNP_RES_LGTAG_ID_ANSI		0x02
#define PNP_RES_LGTAG_ID_UNICODE	0x03
#define PNP_RES_LGTAG_VENDOR		0x04
#define PNP_RES_LGTAG_MEM32		0x05
#define PNP_RES_LGTAG_MEM32_FIXED	0x06

/* Logical device ID flags */
#define PNP_RES_LDID_BOOT		0x01

/* IRQ information */
#define PNP_RES_IRQ_HIGH_EDGE		0x01
#define PNP_RES_IRQ_LOW_EDGE		0x02
#define PNP_RES_IRQ_HIGH_LEVEL		0x04
#define PNP_RES_IRQ_LOW_LEVEL		0x08

/* DMA information */
#define PNP_RES_DMA_WIDTH_MASK		0x03
#define PNP_RES_DMA_WIDTH_8		0x00
#define PNP_RES_DMA_WIDTH_8_16		0x01
#define PNP_RES_DMA_WIDTH_16		0x02
#define PNP_RES_DMA_BUSMASTER		0x04
#define PNP_RES_DMA_COUNT_BYTE		0x08
#define PNP_RES_DMA_COUNT_WORD		0x10
#define PNP_RES_DMA_SPEED_MASK		0x60
#define PNP_RES_DMA_SPEED_COMPAT	0x00
#define PNP_RES_DMA_SPEED_TYPEA		0x20
#define PNP_RES_DMA_SPEED_TYPEB		0x40
#define PNP_RES_DMA_SPEED_TYPEF		0x60

/* Resource group priority */
#define PNP_RES_CONFIG_GOOD		0x00
#define PNP_RES_CONFIG_ACCEPTABLE	0x01
#define PNP_RES_CONFIG_SUBOPTIMAL	0x02

/* IO information */
#define PNP_RES_IO_DECODE_16		0x01

/* Memory information */
#define PNP_RES_MEM_WRITEABLE		0x01
#define PNP_RES_MEM_CACHEABLE		0x02
#define PNP_RES_MEM_HIGH_ADDRESS	0x04
#define PNP_RES_MEM_WIDTH_MASK		0x18
#define PNP_RES_MEM_WIDTH_8		0x00
#define PNP_RES_MEM_WIDTH_16		0x08
#define PNP_RES_MEM_WIDTH_8_16		0x10
#define PNP_RES_MEM_WIDTH_32		0x18
#define PNP_RES_MEM_SHADOWABLE		0x20
#define PNP_RES_MEM_EXPANSION_ROM	0x40

/*
  note: multi-byte data types in these structures are little endian,
  and have to be byte swapped before use on big endian platforms.
*/

#pragma pack(1)
union pnp_small_resource {
	struct {
		__u8	pnp, vendor;
	} version;
	struct {
		__u32	id;
		__u8	flag0, flag1;
	} ldid;
	struct {
		__u32	id;
	} gdid;
	struct {
		__u16	mask;
		__u8	info;
	} irq;
	struct {
		__u8	mask, info;
	} dma;
	struct {
		__u8	priority;
	} dep_start;
	struct {
		__u8	info;
		__u16	min, max;
		__u8	align, len;
	} io;
	struct {
		__u16	base;
		__u8	len;
	} io_fixed;
	struct {
		__u8	checksum;
	} end;
};

union pnp_large_resource {
	struct {
		__u8	info;
		__u16	min, max, align, len;
	} mem;
	struct {
		__u8	str[0];
	} ansi;
	struct {
		__u16	country;
		__u8	str[0];
	} unicode;
	struct {
		__u8	info;
		__u32	min, max, align, len;
	} mem32;
	struct {
		__u8	info;
		__u32	base, len;
	} mem32_fixed;
};

union pnp_resource {
	struct {
		__u8	tag;
		union pnp_small_resource d;
	} sm;
	struct {
		__u8	tag;
		__u16	sz;
		union pnp_large_resource d;
	} lg;
};
#pragma pack()

#endif /* LINUX_PNP_RESOURCE */
