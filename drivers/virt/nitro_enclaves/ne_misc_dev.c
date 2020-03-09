// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

/**
 * Enclave lifetime management driver for Nitro Enclaves (NE).
 * Nitro is a hypervisor that has been developed by Amazon.
 */

#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cpu.h>
#include <linux/device.h>
#include <linux/file.h>
#include <linux/hugetlb.h>
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

#define NE_EIF_LOAD_OFFSET (8 * 1024UL * 1024UL)

#define NE_MIN_ENCLAVE_MEM_SIZE (64 * 1024UL * 1024UL)

#define NE_MIN_MEM_REGION_SIZE (2 * 1024UL * 1024UL)

/*
 * TODO: Update logic to create new sysfs entries instead of using
 * a kernel parameter e.g. if multiple sysfs files needed.
 */
static const struct kernel_param_ops ne_cpu_pool_ops = {
};

static char ne_cpus[PAGE_SIZE];
static struct kparam_string ne_cpus_arg = {
	.maxlen = sizeof(ne_cpus),
	.string = ne_cpus,
};

module_param_cb(ne_cpus, &ne_cpu_pool_ops, &ne_cpus_arg, 0644);
MODULE_PARM_DESC(ne_cpus, "<cpu-list> - CPU pool used for Nitro Enclaves");

/* CPU pool used for Nitro Enclaves. */
struct ne_cpu_pool {
	/* Available CPUs in the pool. */
	cpumask_var_t avail;
	struct mutex mutex;
};

static struct ne_cpu_pool ne_cpu_pool;

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
 * @slot_uid: generated unique slot id associated with an enclave.
 *
 * @returns: enclave fd on success, negative return value on failure.
 */
static int ne_create_vm_ioctl(struct pci_dev *pdev,
			      struct ne_pci_dev *ne_pci_dev, u64 *slot_uid)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	unsigned int cpu = 0;
	int fd = 0;
	struct file *file = NULL;
	struct ne_enclave *ne_enclave = NULL;
	int numa_node = -1;
	int rc = -EINVAL;
	struct slot_alloc_req slot_alloc_req = {};

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (!ne_enclave)
		return -ENOMEM;

	if (!zalloc_cpumask_var(&ne_enclave->cpu_siblings, GFP_KERNEL)) {
		kfree(ne_enclave);

		return -ENOMEM;
	}

	cpu = cpumask_any(ne_cpu_pool.avail);
	if (cpu >= nr_cpu_ids) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in CPU pool\n");

		goto free_cpumask;
	}

	numa_node = cpu_to_node(cpu);
	if (numa_node < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid NUMA node %d\n", numa_node);

		goto free_cpumask;
	}

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in getting unused fd [rc=%d]\n",
				    rc);

		goto free_cpumask;
	}

	file = anon_inode_getfile("ne-vm", &ne_enclave_fops, ne_enclave,
				  O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in anon inode get file [rc=%d]\n",
				    rc);

		goto put_fd;
	}

	ne_enclave->pdev = pdev;

	rc = ne_do_request(ne_enclave->pdev, SLOT_ALLOC, &slot_alloc_req,
			   sizeof(slot_alloc_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot alloc [rc=%d]\n", rc);

		goto put_file;
	}

	init_waitqueue_head(&ne_enclave->eventq);
	ne_enclave->has_event = false;
	mutex_init(&ne_enclave->enclave_info_mutex);
	ne_enclave->max_mem_regions = cmd_reply.mem_regions;
	INIT_LIST_HEAD(&ne_enclave->mem_regions_list);
	ne_enclave->mm = current->mm;
	ne_enclave->numa_node = numa_node;
	ne_enclave->slot_uid = cmd_reply.slot_uid;
	ne_enclave->state = NE_STATE_INIT;
	INIT_LIST_HEAD(&ne_enclave->vcpu_ids_list);

	list_add(&ne_enclave->enclave_list_entry, &ne_pci_dev->enclaves_list);

	*slot_uid = ne_enclave->slot_uid;

	fd_install(fd, file);

	return fd;

put_file:
	fput(file);
put_fd:
	put_unused_fd(fd);
free_cpumask:
	free_cpumask_var(ne_enclave->cpu_siblings);
	kfree(ne_enclave);

	return rc;
}

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
					      PCI_DEVICE_ID_NE, NULL);

	if (!pdev)
		return -ENODEV;

	ne_pci_dev = pci_get_drvdata(pdev);
	if (!ne_pci_dev)
		return -EINVAL;

	switch (cmd) {
	case NE_GET_API_VERSION:
		return NE_API_VERSION;

	case NE_CREATE_VM: {
		u64 slot_uid = 0;
		int rc = -EINVAL;

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);

		rc = ne_create_vm_ioctl(pdev, ne_pci_dev, &slot_uid);

		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		if (copy_to_user((void *)arg, &slot_uid, sizeof(slot_uid))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			return -EFAULT;
		}

		return rc;
	}

	default:
		return -ENOTTY;
	}

	return 0;
}

static const struct file_operations ne_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_ioctl,
};

struct miscdevice ne_misc_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "nitro_enclaves",
	.fops	= &ne_fops,
	.mode	= 0660,
};

static int __init ne_init(void)
{
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
					      PCI_DEVICE_ID_NE, NULL);
	int rc = -EINVAL;

	if (!pdev)
		return -ENODEV;

	if (!zalloc_cpumask_var(&ne_cpu_pool.avail, GFP_KERNEL))
		return -ENOMEM;

	mutex_init(&ne_cpu_pool.mutex);

	rc = pci_register_driver(&ne_pci_driver);
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Error in pci register driver [rc=%d]\n", rc);

		goto free_cpumask;
	}

	return 0;

free_cpumask:
	free_cpumask_var(ne_cpu_pool.avail);

	return rc;
}

static void __exit ne_exit(void)
{
	pci_unregister_driver(&ne_pci_driver);

	free_cpumask_var(ne_cpu_pool.avail);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
