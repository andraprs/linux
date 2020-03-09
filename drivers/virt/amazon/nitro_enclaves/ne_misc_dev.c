// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Enclave lifetime management driver for Nitro Enclaves (NE).
 * Nitro is a hypervisor that has been developed by Amazon.
 */

#include <linux/anon_inodes.h>
#include <linux/bug.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/hugetlb.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nitro_enclaves.h>
#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "ne_misc_dev.h"
#include "ne_pci_dev.h"

#define NE_DEV_NAME "nitro_enclaves"

#define MIN_MEM_REGION_SIZE (2 * 1024UL * 1024UL)

static char *ne_cpus;
module_param(ne_cpus, charp, 0644);
MODULE_PARM_DESC(ne_cpus, "<cpu-list> - CPU pool used for Nitro Enclaves");

/* CPU pool used for Nitro Enclaves. */
struct ne_cpu_pool {
	/* Available CPUs in the pool. */
	cpumask_var_t avail;
};

static struct ne_cpu_pool ne_cpu_pool;

static struct mutex ne_cpu_pool_mutex;

static int ne_enclave_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_enclave_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	switch (cmd) {
	default:
		return -ENOTTY;
	}

	return 0;
}

static int ne_enclave_release(struct inode *inode, struct file *file)
{
	return 0;
}

static __poll_t ne_enclave_poll(struct file *file, poll_table *wait)
{
	__poll_t mask = 0;
	struct ne_enclave *ne_enclave = file->private_data;

	poll_wait(file, &ne_enclave->eventq, wait);

	if (!ne_enclave->has_event)
		return mask;

	mask = POLLHUP;

	return mask;
}

static const struct file_operations ne_enclave_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.poll		= ne_enclave_poll,
	.unlocked_ioctl	= ne_enclave_ioctl,
	.open		= ne_enclave_open,
	.release	= ne_enclave_release,
};

/**
 * ne_create_vm_ioctl - Alloc slot to be associated with an enclave. Create
 * enclave file descriptor to be further used for enclave resources handling
 * e.g. memory regions and CPUs.
 *
 * This function gets called with the ne_pci_dev enclave mutex held.
 *
 * @pdev: PCI device used for enclave lifetime management.
 * @ne_pci_dev: private data associated with the PCI device.
 * @type: type of the virtual machine to be created.
 *
 * @returns: enclave fd on success, negative return value on failure.
 */
static int ne_create_vm_ioctl(struct pci_dev *pdev,
			      struct ne_pci_dev *ne_pci_dev, unsigned long type)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int fd = 0;
	struct file *file = NULL;
	struct ne_enclave *ne_enclave = NULL;
	int rc = -EINVAL;
	struct slot_alloc_req slot_alloc_req = {};

	BUG_ON(!pdev);
	BUG_ON(!ne_pci_dev);

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (!ne_enclave)
		return -ENOMEM;

	if (!zalloc_cpumask_var(&ne_enclave->cpu_siblings, GFP_KERNEL)) {
		kzfree(ne_enclave);

		return -ENOMEM;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;

		pr_err_ratelimited("Failure in getting unused fd [rc=%d]\n",
				   rc);

		goto err_get_unused_fd;
	}

	file = anon_inode_getfile("ne-vm", &ne_enclave_fops, ne_enclave,
				  O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);

		pr_err_ratelimited("Failure in anon inode get file [rc=%d]\n",
				   rc);

		goto err_anon_inode_getfile;
	}

	ne_enclave->pdev = pdev;

	rc = ne_do_request(ne_enclave->pdev, SLOT_ALLOC, &slot_alloc_req,
			   sizeof(slot_alloc_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		pr_err_ratelimited("Failure in slot alloc [rc=%d]\n", rc);

		goto err_slot_alloc;
	}

	init_waitqueue_head(&ne_enclave->eventq);
	ne_enclave->has_event = false;
	mutex_init(&ne_enclave->enclave_info_mutex);
	ne_enclave->max_mem_regions = cmd_reply.mem_regions;
	INIT_LIST_HEAD(&ne_enclave->mem_regions_list);
	ne_enclave->mm = current->mm;
	ne_enclave->slot_uid = cmd_reply.slot_uid;
	ne_enclave->state = NE_STATE_INIT;
	INIT_LIST_HEAD(&ne_enclave->vcpu_ids_list);

	list_add(&ne_enclave->enclave_list_entry, &ne_pci_dev->enclaves_list);

	fd_install(fd, file);

	return fd;

err_slot_alloc:
	fput(file);
err_anon_inode_getfile:
	put_unused_fd(fd);
err_get_unused_fd:
	free_cpumask_var(ne_enclave->cpu_siblings);
	kzfree(ne_enclave);
	return rc;
}

static int ne_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
					      PCI_DEVICE_ID_NE, NULL);

	BUG_ON(!pdev);

	ne_pci_dev = pci_get_drvdata(pdev);
	BUG_ON(!ne_pci_dev);

	switch (cmd) {
	case KVM_CREATE_VM: {
		int rc = -EINVAL;
		unsigned long type = 0;

		if (copy_from_user(&type, (void *)arg, sizeof(type))) {
			pr_err_ratelimited("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);

		rc = ne_create_vm_ioctl(pdev, ne_pci_dev, type);

		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		return rc;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

static int ne_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations ne_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_ioctl,
	.open		= ne_open,
	.release	= ne_release,
};

struct miscdevice ne_miscdevice = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= NE_DEV_NAME,
	.fops	= &ne_fops,
	.mode	= 0664,
};

static int __init ne_init(void)
{
	unsigned int cpu = 0;
	int rc = -EINVAL;

	memset(&ne_cpu_pool, 0, sizeof(ne_cpu_pool));

	if (!zalloc_cpumask_var(&ne_cpu_pool.avail, GFP_KERNEL))
		return -ENOMEM;

	mutex_init(&ne_cpu_pool_mutex);

	rc = cpulist_parse(ne_cpus, ne_cpu_pool.avail);
	if (rc < 0) {
		pr_err_ratelimited("Failure in cpulist parse [rc=%d]\n", rc);

		goto err_cpulist_parse;
	}

	for_each_cpu(cpu, ne_cpu_pool.avail) {
		rc = remove_cpu(cpu);
		if (rc != 0) {
			pr_err_ratelimited("Failure in cpu=%d remove [rc=%d]\n",
					   cpu, rc);

			goto err_remove_cpu;
		}
	}

	rc = pci_register_driver(&ne_pci_driver);
	if (rc < 0) {
		pr_err_ratelimited("Failure in pci register driver [rc=%d]\n",
				   rc);

		goto err_pci_register_driver;
	}

	return 0;

err_pci_register_driver:
err_remove_cpu:
	for_each_cpu(cpu, ne_cpu_pool.avail)
		add_cpu(cpu);
err_cpulist_parse:
	free_cpumask_var(ne_cpu_pool.avail);
	return rc;
}

static void __exit ne_exit(void)
{
	unsigned int cpu = 0;
	int rc = -EINVAL;

	pci_unregister_driver(&ne_pci_driver);

	if (!ne_cpu_pool.avail)
		return;

	for_each_cpu(cpu, ne_cpu_pool.avail) {
		rc = add_cpu(cpu);
		if (WARN_ON(rc != 0))
			pr_err_ratelimited("Failure in cpu=%d add [rc=%d]\n",
					   cpu, rc);
	}

	free_cpumask_var(ne_cpu_pool.avail);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
