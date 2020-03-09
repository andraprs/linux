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

/**
 * Size for max 128 CPUs, for now, in a cpu-list string, comma separated.
 * The NE CPU pool includes CPUs from a single NUMA node.
 */
#define NE_CPUS_SIZE (512)

#define NE_EIF_LOAD_OFFSET (8 * 1024UL * 1024UL)

#define NE_MIN_ENCLAVE_MEM_SIZE (64 * 1024UL * 1024UL)

#define NE_MIN_MEM_REGION_SIZE (2 * 1024UL * 1024UL)

/*
 * TODO: Update logic to create new sysfs entries instead of using
 * a kernel parameter e.g. if multiple sysfs files needed.
 */
static const struct kernel_param_ops ne_cpu_pool_ops = {
	.get = param_get_string,
};

static char ne_cpus[NE_CPUS_SIZE];
static struct kparam_string ne_cpus_arg = {
	.maxlen = sizeof(ne_cpus),
	.string = ne_cpus,
};

module_param_cb(ne_cpus, &ne_cpu_pool_ops, &ne_cpus_arg, 0644);
/* https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html#cpu-lists */
MODULE_PARM_DESC(ne_cpus, "<cpu-list> - CPU pool used for Nitro Enclaves");

/* CPU pool used for Nitro Enclaves. */
struct ne_cpu_pool {
	/* Available CPU cores in the pool. */
	cpumask_var_t *avail_cores;

	/* The size of the available cores array. */
	unsigned int avail_cores_size;

	struct mutex mutex;

	/* NUMA node of the CPUs in the pool. */
	int numa_node;
};

static struct ne_cpu_pool ne_cpu_pool;

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NE_GET_API_VERSION:
		return NE_API_VERSION;

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
	mutex_init(&ne_cpu_pool.mutex);

	return pci_register_driver(&ne_pci_driver);
}

static void __exit ne_exit(void)
{
	pci_unregister_driver(&ne_pci_driver);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
