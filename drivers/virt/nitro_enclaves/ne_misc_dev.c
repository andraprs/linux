// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 */

/**
 * Enclave lifetime management driver for Nitro Enclaves (NE).
 * Nitro is a hypervisor that has been developed by Amazon.
 */

#include <linux/anon_inodes.h>
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

#define MIN_MEM_REGION_SIZE (2 * 1024UL * 1024UL)

#define NE "nitro_enclaves: "

#define NE_DEV_NAME "nitro_enclaves"

#define NE_IMAGE_LOAD_OFFSET (8 * 1024UL * 1024UL)

static char *ne_cpus;
module_param(ne_cpus, charp, 0644);
MODULE_PARM_DESC(ne_cpus, "<cpu-list> - CPU pool used for Nitro Enclaves");

/* CPU pool used for Nitro Enclaves. */
struct ne_cpu_pool {
	/* Available CPUs in the pool. */
	cpumask_var_t avail;
	struct mutex mutex;
};

static struct ne_cpu_pool ne_cpu_pool;

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {

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

struct miscdevice ne_miscdevice = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= NE_DEV_NAME,
	.fops	= &ne_fops,
	.mode	= 0660,
};

static int __init ne_init(void)
{
	unsigned int cpu = 0;
	unsigned int cpu_sibling = 0;
	int rc = -EINVAL;

	if (!zalloc_cpumask_var(&ne_cpu_pool.avail, GFP_KERNEL))
		return -ENOMEM;

	mutex_init(&ne_cpu_pool.mutex);

	rc = cpulist_parse(ne_cpus, ne_cpu_pool.avail);
	if (rc < 0) {
		pr_err(NE "Error in cpulist parse [rc=%d]\n", rc);

		goto free_cpumask;
	}

	/*
	 * Check if CPU siblings are included in the provided CPU pool. The
	 * expectation is that CPU cores are made available in the CPU pool for
	 * enclaves.
	 */
	for_each_cpu(cpu, ne_cpu_pool.avail) {
		for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
			if (!cpumask_test_cpu(cpu_sibling, ne_cpu_pool.avail)) {
				pr_err(NE "CPU %d is not in the CPU pool\n",
				       cpu_sibling);

				rc = -EINVAL;

				goto free_cpumask;
			}
		}
	}

	for_each_cpu(cpu, ne_cpu_pool.avail) {
		rc = remove_cpu(cpu);
		if (rc != 0) {
			pr_err(NE "CPU %d not offlined [rc=%d]\n", cpu, rc);

			goto online_cpus;
		}
	}

	rc = pci_register_driver(&ne_pci_driver);
	if (rc < 0) {
		pr_err(NE "Error in pci register driver [rc=%d]\n", rc);

		goto online_cpus;
	}

	return 0;

online_cpus:
	for_each_cpu(cpu, ne_cpu_pool.avail)
		add_cpu(cpu);
free_cpumask:
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
		if (rc != 0)
			pr_err(NE "CPU %d not onlined [rc=%d]\n", cpu, rc);
	}

	free_cpumask_var(ne_cpu_pool.avail);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
