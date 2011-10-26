/*
 * pnp_proc.c: /proc/bus/pnp interface for Plug and Play devices
 *
 * Written by David Hinds, dahinds@users.sourceforge.net
 */

#include <pcmcia/config.h>
#define __NO_VERSION__
#include <pcmcia/k_compat.h>

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/malloc.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/pnp_bios.h>

static struct proc_dir_entry *proc_pnp = NULL;
static struct proc_dir_entry *proc_pnp_boot = NULL;
static struct pnp_dev_node_info node_info;

static int proc_read_devices(char *buf, char **start, off_t pos,
			     int count, int *eof, void *data)
{
	struct pnp_bios_node *node;
	u8 num;
	char *p = buf;

	node = kmalloc(node_info.max_node_size, GFP_KERNEL);
	if (!node) return -ENOMEM;
	for (num = 0; num != 0xff; ) {
		pnp_bios_get_dev_node(&num, 0, node);
		p += sprintf(p, "%02x\t%08x\t%02x:%02x:%02x\t%04x\n",
			     node->handle, node->eisa_id,
			     node->type_code[0], node->type_code[1],
			     node->type_code[2], node->flags);
	}
	kfree(node);
	return (p-buf);
}

static int proc_read_node(char *buf, char **start, off_t pos,
			  int count, int *eof, void *data)
{
	struct pnp_bios_node *node;
	int boot = (long)data >> 8;
	u8 num = (long)data;
	int len;

	if (pos != 0) {
	    *eof = 1;
	    return 0;
	}
	node = kmalloc(node_info.max_node_size, GFP_KERNEL);
	if (!node) return -ENOMEM;
	pnp_bios_get_dev_node(&num, boot, node);
	len = node->size - sizeof(struct pnp_bios_node);
	memcpy(buf, node->data, len);
	kfree(node);
	return len;
}

static int proc_write_node(struct file *file, const char *buf,
			   unsigned long count, void *data)
{
	struct pnp_bios_node *node;
	int boot = (long)data >> 8;
	u8 num = (long)data;

	node = kmalloc(node_info.max_node_size, GFP_KERNEL);
	if (!node) return -ENOMEM;
	pnp_bios_get_dev_node(&num, boot, node);
	if (count != node->size - sizeof(struct pnp_bios_node))
		return -EINVAL;
	memcpy(node->data, buf, count);
	if (pnp_bios_set_dev_node(node->handle, boot, node) != 0)
	    return -EINVAL;
	kfree(node);
	return count;
}

void pnp_proc_init(void)
{
	struct pnp_bios_node *node;
	struct proc_dir_entry *ent;
	char name[3];
	u8 num;

	if (!pnp_bios_present()) return;
	if (pnp_bios_dev_node_info(&node_info) != 0)
		return;
	
	proc_pnp = proc_mkdir("pnp", proc_bus);
	if (!proc_pnp) return;
	proc_pnp_boot = proc_mkdir("boot", proc_pnp);
	if (!proc_pnp_boot) return;
	create_proc_read_entry("devices", 0, proc_pnp,
			       proc_read_devices, NULL);
	
	node = kmalloc(node_info.max_node_size, GFP_KERNEL);
	if (!node) return;
	for (num = 0; num != 0xff; ) {
		if (pnp_bios_get_dev_node(&num, 0, node) != 0)
			break;
		sprintf(name, "%02x", node->handle);
		ent = create_proc_entry(name, 0, proc_pnp);
		if (ent) {
			ent->read_proc = proc_read_node;
			ent->write_proc = proc_write_node;
			ent->data = (void *)(long)(node->handle);
		}
		ent = create_proc_entry(name, 0, proc_pnp_boot);
		if (ent) {
			ent->read_proc = proc_read_node;
			ent->write_proc = proc_write_node;
			ent->data = (void *)(long)(node->handle+0x100);
		}
	}
	kfree(node);
}

void pnp_proc_done(void)
{
	u8 num;
	char name[3];
	
	if (!proc_pnp) return;
	for (num = 0; num != 0xff; num++) {
		sprintf(name, "%02x", num);
		remove_proc_entry(name, proc_pnp);
		remove_proc_entry(name, proc_pnp_boot);
	}
	remove_proc_entry("boot", proc_pnp);
	remove_proc_entry("devices", proc_pnp);
	remove_proc_entry("pnp", proc_bus);
}
