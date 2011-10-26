/****************************************************************************/

/*
 *    sgutool.c -- tools that read and manipulate SGU images
 *                       binary image (SGU)
 *
 */

/****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <endian.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#ifndef CONFIG_USER_NETFLASH_CRYPTO_V2
#define	CONFIG_USER_NETFLASH_CRYPTO_V2	1
#endif
#include "../../user/netflash/crypto.h"

/****************************************************************************/

#define	PROGNAME	"sgutool"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define	BSWAP(x)	(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define BSWAP(x)	(((x) << 24) | (((x) & 0xff00) << 8) | \
			 (((x) >> 8) & 0xff00) | ((x) >> 24))
#else
#error "Endian not defined?"
#endif

/****************************************************************************/

int verbose;
int trace;

char *sgu;
unsigned int sgusize;
unsigned int imgsize;
unsigned int fssize;
unsigned int fstype;

#define	FS_UNKNOWN	0
#define	FS_ROMFS	1
#define	FS_CRAMFS	2
#define	FS_SQUASHFS	3

char *fs_names[] = {
	[FS_UNKNOWN] = "UNKNOWN",
	[FS_ROMFS] = "ROMfs",
	[FS_CRAMFS] = "CRAMfs",
	[FS_SQUASHFS] = "SQUASHfs",
};

/*
 * These taken from the netflash version.h (though the Makefile script
 * generation of these doesn't actually impose any limits on their size.
 * Modern image contain this info twice, once on the compatability
 * trailer, and also before the signed crypt header.
 */
#define MAX_VENDOR_SIZE		256
#define MAX_PRODUCT_SIZE	256
#define MAX_VERSION_SIZE	12

struct info {
	char vendor[MAX_VENDOR_SIZE];
	unsigned int vendorofs;
	unsigned int vendorsize;

	char product[MAX_PRODUCT_SIZE];
	unsigned int productofs;
	unsigned int productsize;

	char version[MAX_VERSION_SIZE];
	unsigned int versionofs;
	unsigned int versionsize;
};

struct info trailer;
struct info internal;

unsigned int checksum, checksummed;
unsigned int checksumofs, checksumsize;

int imgsigned;
int imgsummed;
int hashtype;

#define	HASH_NONE	0
#define HASH_UNKNOWN	1
#define	HASH_MD5	2
#define	HASH_SHA256	3

char *hash_names[] = {
	[HASH_NONE] = "NONE",
	[HASH_UNKNOWN] = "UNKNOWN",
	[HASH_MD5] = "MD5",
	[HASH_SHA256] = "SHA256",
};

unsigned char crypthash[SHA256_DIGEST_LENGTH];

struct little_header postcrypthdr;
unsigned int postcrypthdrofs, postcrypthdrsize;

struct header crypthdr;
unsigned int crypthdrofs, crypthdrsize;
void *crypthdrbuf, *decrypthdrbuf;
int cryptsigngood;

int publickeygot;
RSA *publickey;

/****************************************************************************/

/*
 * Determine the size of the image filesystem.
 * Can be either ROMfs or CRAmfs.
 */

unsigned int getfssize(int ifd, void *imap)
{
	unsigned int magic, size;
	char *ibuf = imap;

	fstype = FS_UNKNOWN;

	if (trace > 1) {
		printf("magic: 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			ibuf[0], ibuf[1], ibuf[2], ibuf[3],
			ibuf[4], ibuf[5], ibuf[6], ibuf[7]);
	}

	if (memcmp(&ibuf[0], "-rom1fs-", 8) == 0) {
		fstype = FS_ROMFS;
                size = (ibuf[8] << 24) | (ibuf[9] << 16) | (ibuf[10] << 8) |
			ibuf[11];
                size = ((size + 1023) & ~1023);
		if (trace)
			printf("ROMfs size=%d\n", size);
		return size;
	}

	memcpy(&magic, &ibuf[0], sizeof(magic));
        if (magic == BSWAP(0x28cd3d45)) {
		fstype = FS_CRAMFS;
                memcpy(&size, &ibuf[4], sizeof(size));
                size = BSWAP(size);
		if ((ibuf[8] == 's') && (ibuf[9] == 'q') &&
		    (ibuf[10] == 's') && (ibuf[11] == 'h'))
			fstype = FS_SQUASHFS;
		if (trace)
			printf("%s size=%d\n", fs_names[fstype], size);
		return size;
        }

	printf("ERROR: unknown filesystem type?\n", sgu);
	return 0;
}


/****************************************************************************/

int extractkernel(int ifd, void *imap, char *zImage)
{
	int ofd, zImagesize;

	if ((ofd = open(zImage, O_WRONLY | O_CREAT | O_TRUNC, 0660)) < 0) {
		printf("ERROR: cannot open(%s), %s\n", zImage, strerror(errno));
		return -1;
	}

	zImagesize = imgsize - fssize;
	write(ofd, imap + fssize, zImagesize);

	if (trace)
		printf("zImage size=%d\n", zImagesize);

	close(ofd);
	return 0;
}

/****************************************************************************/

int extractfs(int ifd, void *imap, char *fsimg)
{
	int ofd;

	if ((ofd = open(fsimg, O_WRONLY | O_CREAT | O_TRUNC, 0660)) < 0) {
		printf("ERROR: cannot open(%s), %s\n", fsimg, strerror(errno));
		return -1;
	}

	write(ofd, imap, fssize);

	if (trace)
		printf("filesystem size=%d\n", fssize);

	close(ofd);
	return 0;
}

/****************************************************************************/

int extractchecksum(void *imap)
{
	if (imgsize < 4)
		return 0;

	checksumsize = 4;
	checksumofs = imgsize - checksumsize;
	memcpy(&checksum, imap + checksumofs, 4);
	checksum = ntohl(checksum);
	if (checksum > 0xffff) {
		if (trace)
			printf("image has no final checksum");
		return 0;
	}

	imgsize = checksumofs;

	if (trace)
		printf("image checksum=0x%x\n", checksum);
	return 1;
}

/****************************************************************************/

unsigned int findbackwardstring(void *imap, unsigned int end, unsigned int max)
{
	unsigned int start, base;
	char *ibuf = imap;

	/* Normally this would never be true, but lets be careful */
	base = (max > end) ? 0 : (end - max);

	for (start = end; (start > base); start--) {
		if (ibuf[start] == 0)
			return start;
	}
	return 0;
}

int extractinfo(void *imap, struct info *ip)
{
	unsigned int end;

	end = imgsize - 1;

	/* Extract product name string */
	ip->productofs = findbackwardstring(imap, end, MAX_PRODUCT_SIZE);
	if (ip->productofs == 0) {
		printf("WARNING: sgu doesn't appear to be versioned?\n");
		return -1;
	}
	ip->productsize = end - ip->productofs;
	if (ip->productsize > 0) {
		ip->productofs++;
		memcpy(&ip->product, imap + ip->productofs, end - ip->productofs + 1);
		if (trace)
			printf("image product name=`%s`\n", ip->product);
		end = ip->productofs - 2;
	}

	/* Extract vendor name string */
	ip->vendorofs = findbackwardstring(imap, end, MAX_VENDOR_SIZE);
	ip->vendorsize = end - ip->vendorofs;
	if (ip->vendorsize > 0) {
		ip->vendorofs++;
		memcpy(&ip->vendor, imap + ip->vendorofs, end - ip->vendorofs + 1);
		if (trace)
			printf("image vendor name=`%s`\n", ip->vendor);
		end = ip->vendorofs - 2;
	}

	/* Extract version string */
	ip->versionofs = findbackwardstring(imap, end, MAX_VERSION_SIZE);
	ip->versionsize = end - ip->versionofs;
	if (ip->versionsize > 0) {
		ip->versionofs++;
		memcpy(&ip->version, imap + ip->versionofs, end - ip->versionofs + 1);
		if (trace)
			printf("image version=`%s`\n", ip->version);
		end = ip->versionofs - 2;
	}

	imgsize = end + 1;
	return 0;
}

/****************************************************************************/

int sha256image(void *imap)
{
	SHA256_CTX ctx;

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, imap, imgsize);
	SHA256_Final(&crypthash[0], &ctx);
	return 0;
}

/****************************************************************************/

int extractcrypto(void *imap)
{
	int len;

	hashtype = HASH_NONE;

	/* Extract the small pre-header to verify we have a signature */
	memcpy(&postcrypthdr, imap + imgsize - sizeof(postcrypthdr), sizeof(postcrypthdr));
	postcrypthdr.magic = ntohs(postcrypthdr.magic);
	postcrypthdr.hlen = ntohs(postcrypthdr.hlen);

	if (postcrypthdr.magic != LITTLE_CRYPTO_MAGIC)
		return -1;
	if (imgsize < sizeof(postcrypthdr))
		return -1;
	if (imgsize < postcrypthdr.hlen)
		return -1;

	postcrypthdrsize = sizeof(postcrypthdr);
	postcrypthdrofs = imgsize - sizeof(postcrypthdr);
	imgsize = postcrypthdrofs;
	imgsigned = 1;

	/* All this code currently supports... */
	hashtype = HASH_SHA256;

	if (trace)
		printf("signed image, hash type=%s\n", hash_names[hashtype]);

	crypthdrofs = imgsize - postcrypthdr.hlen;
	crypthdrsize = postcrypthdr.hlen;
	crypthdrbuf = malloc(crypthdrsize);
	imgsize = crypthdrofs;

	/* If we didn't get the public key then we are done. */
	if (! publickeygot)
		return 0;

	memcpy(crypthdrbuf, imap + crypthdrofs, crypthdrsize);

	decrypthdrbuf = malloc(crypthdrsize);
	len = RSA_public_decrypt(crypthdrsize, crypthdrbuf, decrypthdrbuf,
		publickey, RSA_PKCS1_PADDING);
	if (len < 0)
		return -1;
	if (len != sizeof(crypthdr)) {
		printf("WARNING: crypt header different size?\n");
		return -1;
	}
	memcpy(&crypthdr, decrypthdrbuf, sizeof(crypthdr));

	crypthdr.magic = ntohl(crypthdr.magic);
	if (crypthdr.magic != CRYPTO_MAGIC) {
		printf("WARNING: crypt header wrong magic 0x%8x "
			"(expected 0x%08x)?\n", crypthdr.magic, CRYPTO_MAGIC);
		return -1;
	}

	/* Check the hash matches */
	sha256image(imap);
	if (memcmp(crypthash, crypthdr.hash, SHA256_DIGEST_LENGTH) != 0) {
		printf("WARNING: crypt hash does not match?\n");
		return -1;
	}

	cryptsigngood = 1;
	return 0;
}

/****************************************************************************/

unsigned int genchecksum(void *imap)
{
	unsigned char *p, *end;

	end = imap + checksumofs;
	for (p = imap; (p < end); p++)
		checksummed += *p;
	checksummed = (checksummed & 0xffff) + (checksummed >> 16);
	checksummed = (checksummed & 0xffff) + (checksummed >> 16);

	if (trace) {
		printf("calculated checksum=0x%x (%s)\n", checksummed,
			(checksum == checksummed) ? "good" : "BAD");
	}
	return checksummed;
}

/****************************************************************************/

int loadpublickey(char *pubkeyfile)
{
	BIO *bin;
	if ((bin = BIO_new(BIO_s_file()))  == NULL) {
		if (trace)
			printf("WARNING: failed to allocate crypt BIO?\n");
		return 0;
	}
	if (BIO_read_filename(bin, pubkeyfile) <= 0) {
		if (trace)
			printf("WARNING: cannot read public key file, %s\n",
				pubkeyfile);
		return 0;
	}
	publickey = PEM_read_bio_RSA_PUBKEY(bin, NULL, NULL, NULL);
	if (publickey == NULL) {
		if (trace)
			printf("WARNING: cannot read public key, %s\n",
                                pubkeyfile);
                return 0;
        }

	return 1;
}

/****************************************************************************/

void printinfo(void)
{
	printf("SGU %s:\n", sgu);
	printf("    total size =\t%d bytes\n", sgusize);
	printf("    filesystem size =\t%d bytes\n", fssize);
	printf("    kernel size =\t%d bytes\n", imgsize - fssize);
	printf("    filesystem type =\t%s\n", fs_names[fstype]);

	if (imgsummed) {
		printf("    old checksum =\t0x%04x (%s)\n", checksum,
			(checksum == checksummed) ? "good" : "bad");
		if (checksum != checksummed) {
			printf("    calculat checksum =\t0x%04x\n",
				checksummed);
		}
		printf("    vendor string =\t%s\n", trailer.vendor);
		printf("    product string =\t%s\n", trailer.product);
		printf("    version string =\t%s\n", trailer.version);
	}

	printf("    signed image =\t%s (%s)\n", (imgsigned) ? "yes" : "no",
		(publickeygot ? (cryptsigngood ? "good" : "bad") : "unverified"));

	if (imgsigned) {
		printf("    signature type =\t%s\n", hash_names[hashtype]);
		printf("    signed vendor =\t%s\n", internal.vendor);
		printf("    signed product =\t%s\n", internal.product);
		printf("    signed version =\t%s\n", internal.version);
	}
}

/****************************************************************************/

void usage(int rc)
{
	printf("Usage: %s [-h?tvVPRCcs] [-p <public.key>] [-k <zImage>] "
		"[-f <fs.bin>] <file.sgu>\n", PROGNAME);
	printf("\n\t-h?\t\tthis help\n"
		"\t-v\t\tverbose output\n"
		"\t-t\t\ttrace output\n"
		"\t-V\t\treport VENDOR type of image\n"
		"\t-P\t\treport PRODUCT type of image\n"
		"\t-R\t\treport VERSION stamped in image\n"
		"\t-C\t\treport CHECKSUM stamped in image\n"
		"\t-c\t\treport generated image checksum\n"
		"\t-s\t\treport checksum status (good/bad)\n"
		"\t-p <public.key>\tkey file to use (default /etc/publickey.pem)\n"
		"\t-k <zImage>\twrite out kernel to file <zImage>\n"
		"\t-f <fs.bin>\twrite out filesystem to file <fs.bin>\n"
	);
	exit(rc);
}

/****************************************************************************/

int main(int argc, char *argv[])
{
	struct stat st;
	void *imap;
	char *zImage, *fsimg, *pubkeyfile;
	int ifd, c;
	int dokernel, dofilesystem;
	int dovendor, doproduct, doversion;
	int dochecksum, dochecksummed, dochecksumstatus;

	dokernel = 0;
	dofilesystem = 0;
	dovendor = 0;
	doproduct = 0;
	doversion = 0;
	dochecksum = 0;
	dochecksummed = 0;
	dochecksumstatus = 0;
	pubkeyfile = "/etc/publickey.pem";

	while ((c = getopt(argc, argv, "?hvtVPRCcsk:f:p:")) >= 0) {
		switch (c) {
		case 'V':
			dovendor = 1;
			break;
		case 'P':
			doproduct = 1;
			break;
		case 'R':
			doversion = 1;
			break;
		case 'C':
			dochecksum = 1;
			break;
		case 'c':
			dochecksummed = 1;
			break;
		case 's':
			dochecksumstatus = 1;
			break;
		case 'p':
			pubkeyfile = optarg;
			break;
		case 'k':
			dokernel = 1;
			zImage = optarg;
			break;
		case 'f':
			dofilesystem = 1;
			fsimg = optarg;
			break;
		case 't':
			trace++;
			break;
		case 'v':
			verbose++;
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (argc != (optind + 1))
		usage(1);
	sgu = argv[optind++];

	if (trace)
		printf("file=%s\n", sgu);

	if (stat(sgu, &st) < 0) {
		printf("ERROR: image %s, %s\n", sgu, strerror(errno));
		return 1;
	}
	sgusize = st.st_size;
	imgsize = sgusize;

	if (trace)
		printf("size=%d bytes\n", sgusize);

	if ((ifd = open(sgu, O_RDONLY)) < 0) {
		printf("ERROR: cannot open(%s), %s\n", sgu, strerror(errno));
		return 1;
	}
	imap = mmap(NULL, sgusize, PROT_READ, MAP_PRIVATE, ifd, 0);
	if (imap == MAP_FAILED) {
		printf("ERROR: cannot mmap(%s), %s\n", sgu, strerror(errno));
		return 1;
	}

	publickeygot = loadpublickey(pubkeyfile);

	fssize = getfssize(ifd, imap);
	if (fssize == 0)
		return 1;
	if (fssize > imgsize) {
		printf("WARNING: filesystem (%d) larger than image %d)?\n",
			fssize, imgsize);
		return 1;
	}

	/* Allow for crypto only signed images */
	imgsummed = extractchecksum(imap);
	if (imgsummed) {
		extractinfo(imap, &trailer);
		genchecksum(imap);
		if (checksum != checksummed) {
			printf("WARNING: bad checksum, file=0x%04x, "
				"calculated=0x%04x\n", checksum, checksummed);
		}
	}

	extractcrypto(imap);
	if (imgsigned && (hashtype == HASH_UNKNOWN))
		printf("WARNING: signed image using unknown hash type?\n");

	extractinfo(imap, &internal);

	if (verbose)
		printinfo();
	if (dokernel)
		extractkernel(ifd, imap, zImage);
	if (dofilesystem)
		extractfs(ifd, imap, fsimg);
	if (dovendor)
		printf("%s\n", trailer.vendor);
	if (doproduct)
		printf("%s\n", trailer.product);
	if (doversion)
		printf("%s\n", trailer.version);
	if (dochecksum)
		printf("0x%04x\n", checksum);
	if (dochecksummed)
		printf("0x%04x\n", checksummed);
	if (dochecksumstatus) {
		printf("%s\n", (checksum == checksummed) ? "good" : "bad");
		exit((checksum == checksummed) ? 0 : 1);
	}

	munmap(imap, sgusize);
	close(ifd);
	return 0;
}

/****************************************************************************/
