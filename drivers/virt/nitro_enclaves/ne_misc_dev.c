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
static int ne_set_kernel_param(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops ne_cpu_pool_ops = {
	.get = param_get_string,
	.set = ne_set_kernel_param,
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

/**
 * ne_check_enclaves_created - Verify if at least one enclave has been created.
 *
 * @returns: true if at least one enclave is created, false otherwise.
 */
static bool ne_check_enclaves_created(void)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	/* TODO: Find another way to get the NE PCI device reference. */
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON, PCI_DEVICE_ID_NE, NULL);
	bool ret = false;

	if (!pdev)
		return ret;

	ne_pci_dev = pci_get_drvdata(pdev);
	if (!ne_pci_dev) {
		pci_dev_put(pdev);

		return ret;
	}

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);

	if (!list_empty(&ne_pci_dev->enclaves_list))
		ret = true;

	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	pci_dev_put(pdev);

	return ret;
}

/**
 * ne_setup_cpu_pool - Set the NE CPU pool after handling sanity checks such as
 * not sharing CPU cores with the primary / parent VM or not using CPU 0, which
 * should remain available for the primary / parent VM. Offline the CPUs from
 * the pool after the checks passed.
 *
 * @ne_cpu_list: the CPU list used for setting NE CPU pool.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_setup_cpu_pool(const char *ne_cpu_list)
{
	int core_id = -1;
	unsigned int cpu = 0;
	cpumask_var_t cpu_pool = NULL;
	unsigned int cpu_sibling = 0;
	unsigned int i = 0;
	int numa_node = -1;
	int rc = -EINVAL;

	if (!ne_cpu_list)
		return 0;

	if (!zalloc_cpumask_var(&cpu_pool, GFP_KERNEL))
		return -ENOMEM;

	mutex_lock(&ne_cpu_pool.mutex);

	rc = cpulist_parse(ne_cpu_list, cpu_pool);
	if (rc < 0) {
		pr_err("%s: Error in cpulist parse [rc=%d]\n", ne_misc_dev.name, rc);

		goto free_pool_cpumask;
	}

	cpu = cpumask_any(cpu_pool);
	if (cpu >= nr_cpu_ids) {
		pr_err("%s: No CPUs available in CPU pool\n", ne_misc_dev.name);

		rc = -EINVAL;

		goto free_pool_cpumask;
	}

	/*
	 * Check if CPU 0 and its siblings are included in the provided CPU pool
	 * They should remain available for the primary / parent VM.
	 */
	if (cpumask_test_cpu(0, cpu_pool)) {
		pr_err("%s: CPU 0 has to remain available\n", ne_misc_dev.name);

		rc = -EINVAL;

		goto free_pool_cpumask;
	}

	for_each_cpu(cpu_sibling, topology_sibling_cpumask(0)) {
		if (cpumask_test_cpu(cpu_sibling, cpu_pool)) {
			pr_err("%s: CPU sibling %d for CPU 0 is in CPU pool\n",
			       ne_misc_dev.name, cpu_sibling);

			rc = -EINVAL;

			goto free_pool_cpumask;
		}
	}

	/*
	 * Check if CPU siblings are included in the provided CPU pool. The
	 * expectation is that CPU cores are made available in the CPU pool for
	 * enclaves.
	 */
	for_each_cpu(cpu, cpu_pool) {
		for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
			if (!cpumask_test_cpu(cpu_sibling, cpu_pool)) {
				pr_err("%s: CPU %d is not in CPU pool\n",
				       ne_misc_dev.name, cpu_sibling);

				rc = -EINVAL;

				goto free_pool_cpumask;
			}
		}
	}

	/*
	 * Check if the CPUs from the NE CPU pool are from the same NUMA node.
	 */
	for_each_cpu(cpu, cpu_pool) {
		if (numa_node < 0) {
			numa_node = cpu_to_node(cpu);
			if (numa_node < 0) {
				pr_err("%s: Invalid NUMA node %d\n",
				       ne_misc_dev.name, numa_node);

				rc = -EINVAL;

				goto free_pool_cpumask;
			}
		} else {
			if (numa_node != cpu_to_node(cpu)) {
				pr_err("%s: CPUs with different NUMA nodes\n",
				       ne_misc_dev.name);

				rc = -EINVAL;

				goto free_pool_cpumask;
			}
		}
	}

	ne_cpu_pool.avail_cores_size = nr_cpu_ids / smp_num_siblings;

	ne_cpu_pool.avail_cores = kcalloc(ne_cpu_pool.avail_cores_size,
					  sizeof(*ne_cpu_pool.avail_cores),
					  GFP_KERNEL);
	if (!ne_cpu_pool.avail_cores) {
		rc = -ENOMEM;

		goto free_pool_cpumask;
	}

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (!zalloc_cpumask_var(&ne_cpu_pool.avail_cores[i], GFP_KERNEL)) {
			rc = -ENOMEM;

			goto free_cores_cpumask;
		}

	ne_cpu_pool.numa_node = numa_node;

	/* Split the NE CPU pool in CPU cores. */
	for_each_cpu(cpu, cpu_pool) {
		core_id = topology_core_id(cpu);
		if (core_id < 0 || core_id >= ne_cpu_pool.avail_cores_size) {
			pr_err("%s: Invalid core id  %d\n",
			       ne_misc_dev.name, core_id);

			rc = -EINVAL;

			goto clear_cpumask;
		}

		cpumask_set_cpu(cpu, ne_cpu_pool.avail_cores[core_id]);
	}

	/*
	 * CPUs that are donated to enclave(s) should not be considered online
	 * by Linux anymore, as the hypervisor will degrade them to floating.
	 * The physical CPUs (full cores) are carved out of the primary / parent
	 * VM and given to the enclave VM. The same number of vCPUs would run
	 * on less pCPUs for the primary / parent VM.
	 *
	 * We offline them here, to not degrade performance and expose correct
	 * topology to Linux and user space.
	 */
	for_each_cpu(cpu, cpu_pool) {
		rc = remove_cpu(cpu);
		if (rc != 0) {
			pr_err("%s: CPU %d is not offlined [rc=%d]\n",
			       ne_misc_dev.name, cpu, rc);

			goto online_cpus;
		}
	}

	free_cpumask_var(cpu_pool);

	mutex_unlock(&ne_cpu_pool.mutex);

	return 0;

online_cpus:
	for_each_cpu(cpu, cpu_pool)
		add_cpu(cpu);
clear_cpumask:
	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		cpumask_clear(ne_cpu_pool.avail_cores[i]);
free_cores_cpumask:
	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		free_cpumask_var(ne_cpu_pool.avail_cores[i]);
	kfree(ne_cpu_pool.avail_cores);
	ne_cpu_pool.avail_cores_size = 0;
free_pool_cpumask:
	free_cpumask_var(cpu_pool);
	mutex_unlock(&ne_cpu_pool.mutex);

	return rc;
}

/**
 * ne_teardown_cpu_pool - Online the CPUs from the NE CPU pool and cleanup the
 * CPU pool.
 */
static void ne_teardown_cpu_pool(void)
{
	unsigned int cpu = 0;
	unsigned int i = 0;
	int rc = -EINVAL;

	mutex_lock(&ne_cpu_pool.mutex);

	if (!ne_cpu_pool.avail_cores_size) {
		mutex_unlock(&ne_cpu_pool.mutex);

		return;
	}

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++) {
		for_each_cpu(cpu, ne_cpu_pool.avail_cores[i]) {
			rc = add_cpu(cpu);
			if (rc != 0)
				pr_err("%s: CPU %d is not onlined [rc=%d]\n",
				       ne_misc_dev.name, cpu, rc);
		}

		cpumask_clear(ne_cpu_pool.avail_cores[i]);

		free_cpumask_var(ne_cpu_pool.avail_cores[i]);
	}

	kfree(ne_cpu_pool.avail_cores);
	ne_cpu_pool.avail_cores_size = 0;

	mutex_unlock(&ne_cpu_pool.mutex);
}

static int ne_set_kernel_param(const char *val, const struct kernel_param *kp)
{
	char error_val[] = "";
	int rc = -EINVAL;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (ne_check_enclaves_created()) {
		pr_err("%s: The CPU pool is used by enclave(s)\n", ne_misc_dev.name);

		return -EPERM;
	}

	ne_teardown_cpu_pool();

	rc = ne_setup_cpu_pool(val);
	if (rc < 0) {
		pr_err("%s: Error in setup CPU pool [rc=%d]\n", ne_misc_dev.name, rc);

		param_set_copystring(error_val, kp);

		return rc;
	}

	return param_set_copystring(val, kp);
}

/**
 * ne_get_cpu_from_cpu_pool - Get a CPU from the NE CPU pool, either from the
 * remaining sibling(s) of a CPU core or the first sibling of a new CPU core.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the chosen CPU from the NE CPU pool.
 *
 * @returns: vCPU id or 0, if no CPU available in the pool.
 */
static unsigned int ne_get_cpu_from_cpu_pool(struct ne_enclave *ne_enclave)
{
	int core_id = -1;
	unsigned int cpu = 0;
	unsigned int i = 0;
	unsigned int vcpu_id = 0;

	/* There are CPU siblings available to choose from. */
	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		for_each_cpu(cpu, ne_enclave->avail_cpu_cores[i])
			if (!cpumask_test_cpu(cpu, ne_enclave->vcpu_ids)) {
				vcpu_id = cpu;

				goto out;
			}

	mutex_lock(&ne_cpu_pool.mutex);

	/* Choose a CPU from the available NE CPU pool. */
	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (!cpumask_empty(ne_cpu_pool.avail_cores[i])) {
			core_id = i;

			break;
		}

	if (core_id < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in NE CPU pool\n");

		goto unlock_mutex;
	}

	if (core_id >= ne_enclave->avail_cpu_cores_size) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid core id %d - ne_enclave\n", core_id);

		goto unlock_mutex;
	}

	vcpu_id = cpumask_any(ne_cpu_pool.avail_cores[core_id]);

	for_each_cpu(cpu, ne_cpu_pool.avail_cores[core_id])
		cpumask_set_cpu(cpu, ne_enclave->avail_cpu_cores[core_id]);

	cpumask_clear(ne_cpu_pool.avail_cores[core_id]);

unlock_mutex:
	mutex_unlock(&ne_cpu_pool.mutex);
out:
	return vcpu_id;
}

/**
 * ne_check_cpu_in_cpu_pool - Check if the given vCPU is in the available CPUs
 * from the pool.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the vCPU to check if available in the NE CPU pool.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_check_cpu_in_cpu_pool(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	int core_id = -1;
	unsigned int cpu = 0;
	unsigned int i = 0;

	if (cpumask_test_cpu(vcpu_id, ne_enclave->vcpu_ids)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "CPU %d already used\n", vcpu_id);

		return -NE_ERR_VCPU_ALREADY_USED;
	}

	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		if (cpumask_test_cpu(vcpu_id, ne_enclave->avail_cpu_cores[i]))
			return 0;

	mutex_lock(&ne_cpu_pool.mutex);

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (cpumask_test_cpu(vcpu_id, ne_cpu_pool.avail_cores[i])) {
			core_id = i;

			break;
	}

	if (core_id < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "CPU %d is not in NE CPU pool\n", vcpu_id);

		mutex_unlock(&ne_cpu_pool.mutex);

		return -NE_ERR_VCPU_NOT_IN_POOL;
	}

	if (core_id >= ne_enclave->avail_cpu_cores_size) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid core id %d - ne_enclave\n", core_id);

		mutex_unlock(&ne_cpu_pool.mutex);

		return -NE_ERR_INVALID_CPU_CORE;
	}

	for_each_cpu(cpu, ne_cpu_pool.avail_cores[core_id])
		cpumask_set_cpu(cpu, ne_enclave->avail_cpu_cores[core_id]);

	cpumask_clear(ne_cpu_pool.avail_cores[core_id]);

	mutex_unlock(&ne_cpu_pool.mutex);

	return 0;
}

/**
 * ne_add_vcpu_ioctl - Add a vCPU to the slot associated with the current
 * enclave.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the CPU to be associated with the given slot, apic id on x86.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_add_vcpu_ioctl(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int rc = -EINVAL;
	struct slot_add_vcpu_req slot_add_vcpu_req = {};

	if (ne_enclave->mm != current->mm)
		return -EIO;

	slot_add_vcpu_req.slot_uid = ne_enclave->slot_uid;
	slot_add_vcpu_req.vcpu_id = vcpu_id;

	rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_VCPU, &slot_add_vcpu_req,
			   sizeof(slot_add_vcpu_req), &cmd_reply, sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot add vCPU [rc=%d]\n", rc);

		return rc;
	}

	cpumask_set_cpu(vcpu_id, ne_enclave->vcpu_ids);

	ne_enclave->nr_vcpus++;

	return 0;
}

/**
 * ne_sanity_check_user_mem_region - Sanity check the userspace memory
 * region received during the set user memory region ioctl call.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @mem_region: user space memory region to be sanity checked.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_sanity_check_user_mem_region(struct ne_enclave *ne_enclave,
	struct ne_user_memory_region *mem_region)
{
	if (ne_enclave->mm != current->mm)
		return -EIO;

	if (mem_region->memory_size & (NE_MIN_MEM_REGION_SIZE - 1)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Memory size is not multiple of 2 MiB\n");

		return -NE_ERR_INVALID_MEM_REGION_SIZE;
	}

	if ((mem_region->userspace_addr & (NE_MIN_MEM_REGION_SIZE - 1)) ||
	    !access_ok((void __user *)(unsigned long)mem_region->userspace_addr,
		       mem_region->memory_size)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid user space addr range\n");

		return -NE_ERR_INVALID_MEM_REGION_ADDR;
	}

	if (!IS_ALIGNED(mem_region->userspace_addr, NE_MIN_MEM_REGION_SIZE)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "User space addr is not 2 MiB aligned\n");

		return -NE_ERR_UNALIGNED_MEM_REGION_ADDR;
	}

	return 0;
}

/**
 * ne_set_user_memory_region_ioctl - Add user space memory region to the slot
 * associated with the current enclave.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @mem_region: user space memory region to be associated with the given slot.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_set_user_memory_region_ioctl(struct ne_enclave *ne_enclave,
	struct ne_user_memory_region *mem_region)
{
	long gup_rc = 0;
	unsigned long i = 0;
	unsigned long max_nr_pages = 0;
	unsigned long memory_size = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	unsigned long nr_phys_contig_mem_regions = 0;
	struct page **phys_contig_mem_regions = NULL;
	int rc = -EINVAL;

	rc = ne_sanity_check_user_mem_region(ne_enclave, mem_region);
	if (rc < 0)
		return rc;

	ne_mem_region = kzalloc(sizeof(*ne_mem_region), GFP_KERNEL);
	if (!ne_mem_region)
		return -ENOMEM;

	max_nr_pages = mem_region->memory_size / NE_MIN_MEM_REGION_SIZE;

	ne_mem_region->pages = kcalloc(max_nr_pages, sizeof(*ne_mem_region->pages),
				       GFP_KERNEL);
	if (!ne_mem_region->pages) {
		rc = -ENOMEM;

		goto free_mem_region;
	}

	phys_contig_mem_regions = kcalloc(max_nr_pages, sizeof(*phys_contig_mem_regions),
					  GFP_KERNEL);
	if (!phys_contig_mem_regions) {
		rc = -ENOMEM;

		goto free_mem_region;
	}

	do {
		i = ne_mem_region->nr_pages;

		gup_rc = get_user_pages(mem_region->userspace_addr + memory_size, 1, FOLL_GET,
					ne_mem_region->pages + i, NULL);
		if (gup_rc < 0) {
			rc = gup_rc;

			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in get user pages [rc=%d]\n", rc);

			goto unpin_pages;
		}

		if (!PageHuge(ne_mem_region->pages[i])) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Not a hugetlbfs page\n");

			rc = -NE_ERR_MEM_NOT_HUGE_PAGE;

			goto unpin_pages;
		}

		if (ne_enclave->numa_node != page_to_nid(ne_mem_region->pages[i])) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Page is not from NUMA node %d\n",
					    ne_enclave->numa_node);

			rc = -NE_ERR_MEM_DIFF_NUMA_NODE;

			goto unpin_pages;
		}

		/*
		 * TODO: Update once handled non-contiguous memory regions
		 * received from user space or contiguous physical memory regions
		 * larger than 2 MiB e.g. 8 MiB.
		 */
		phys_contig_mem_regions[i] = ne_mem_region->pages[i];

		memory_size += page_size(ne_mem_region->pages[i]);

		ne_mem_region->nr_pages++;
	} while (memory_size < mem_region->memory_size);

	/*
	 * TODO: Update once handled non-contiguous memory regions received
	 * from user space or contiguous physical memory regions larger than
	 * 2 MiB e.g. 8 MiB.
	 */
	nr_phys_contig_mem_regions = ne_mem_region->nr_pages;

	if ((ne_enclave->nr_mem_regions + nr_phys_contig_mem_regions) >
	    ne_enclave->max_mem_regions) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Reached max memory regions %lld\n",
				    ne_enclave->max_mem_regions);

		rc = -NE_ERR_MEM_MAX_REGIONS;

		goto unpin_pages;
	}

	for (i = 0; i < nr_phys_contig_mem_regions; i++) {
		struct ne_pci_dev_cmd_reply cmd_reply = {};
		struct slot_add_mem_req slot_add_mem_req = {};

		u64 phys_addr = page_to_phys(phys_contig_mem_regions[i]);

		slot_add_mem_req.slot_uid = ne_enclave->slot_uid;
		slot_add_mem_req.paddr = phys_addr;
		slot_add_mem_req.size = page_size(phys_contig_mem_regions[i]);

		rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_MEM,
				   &slot_add_mem_req, sizeof(slot_add_mem_req),
				   &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in slot add mem [rc=%d]\n", rc);

			kfree(phys_contig_mem_regions);

			/*
			 * Exit here without unpinning the pages as memory
			 * regions may have already been added.
			 */
			return rc;
		}

		ne_enclave->mem_size += slot_add_mem_req.size;
		ne_enclave->nr_mem_regions++;
	}

	list_add(&ne_mem_region->mem_region_list_entry, &ne_enclave->mem_regions_list);

	kfree(phys_contig_mem_regions);

	return 0;

unpin_pages:
	unpin_user_pages(ne_mem_region->pages, ne_mem_region->nr_pages);
free_mem_region:
	kfree(phys_contig_mem_regions);
	kfree(ne_mem_region->pages);
	kfree(ne_mem_region);

	return rc;
}

static long ne_enclave_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	switch (cmd) {
	case NE_ADD_VCPU: {
		int rc = -EINVAL;
		u32 vcpu_id = 0;

		if (copy_from_user(&vcpu_id, (void __user *)arg, sizeof(vcpu_id)))
			return -EFAULT;

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		if (vcpu_id >= (ne_enclave->avail_cpu_cores_size * smp_num_siblings)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "vCPU id higher than max CPU id\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_INVALID_VCPU;
		}

		if (!vcpu_id) {
			/* Use the CPU pool for choosing a CPU for the enclave. */
			vcpu_id = ne_get_cpu_from_cpu_pool(ne_enclave);
			if (!vcpu_id) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Error in getting CPU from pool\n");

				mutex_unlock(&ne_enclave->enclave_info_mutex);

				return -NE_ERR_NO_CPUS_AVAIL_IN_POOL;
			}
		} else {
			/* Check if the vCPU is available in the NE CPU pool. */
			rc = ne_check_cpu_in_cpu_pool(ne_enclave, vcpu_id);
			if (rc < 0) {
				dev_err_ratelimited(ne_misc_dev.this_device,
						    "Error in checking if CPU is in pool\n");

				mutex_unlock(&ne_enclave->enclave_info_mutex);

				return rc;
			}
		}

		rc = ne_add_vcpu_ioctl(ne_enclave, vcpu_id);
		if (rc < 0) {
			cpumask_clear_cpu(vcpu_id, ne_enclave->vcpu_ids);

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void __user *)arg, &vcpu_id, sizeof(vcpu_id)))
			return -EFAULT;

		return 0;
	}

	case NE_GET_IMAGE_LOAD_INFO: {
		struct ne_image_load_info image_load_info = {};

		if (copy_from_user(&image_load_info, (void __user *)arg, sizeof(image_load_info)))
			return -EFAULT;

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (image_load_info.flags == NE_EIF_IMAGE)
			image_load_info.memory_offset = NE_EIF_LOAD_OFFSET;

		if (copy_to_user((void __user *)arg, &image_load_info, sizeof(image_load_info)))
			return -EFAULT;

		return 0;
	}

	case NE_SET_USER_MEMORY_REGION: {
		struct ne_user_memory_region mem_region = {};
		int rc = -EINVAL;

		if (copy_from_user(&mem_region, (void __user *)arg, sizeof(mem_region)))
			return -EFAULT;

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave is not in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -NE_ERR_NOT_IN_INIT_STATE;
		}

		rc = ne_set_user_memory_region_ioctl(ne_enclave, &mem_region);
		if (rc < 0) {
			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return rc;
		}

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return 0;
	}

	default:
		return -ENOTTY;
	}

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
static int ne_create_vm_ioctl(struct pci_dev *pdev, struct ne_pci_dev *ne_pci_dev,
			      u64 *slot_uid)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int enclave_fd = -1;
	struct file *enclave_file = NULL;
	unsigned int i = 0;
	struct ne_enclave *ne_enclave = NULL;
	int rc = -EINVAL;
	struct slot_alloc_req slot_alloc_req = {};

	mutex_lock(&ne_cpu_pool.mutex);

	for (i = 0; i < ne_cpu_pool.avail_cores_size; i++)
		if (!cpumask_empty(ne_cpu_pool.avail_cores[i]))
			break;

	if (i == ne_cpu_pool.avail_cores_size) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in CPU pool\n");

		mutex_unlock(&ne_cpu_pool.mutex);

		return -NE_ERR_NO_CPUS_AVAIL_IN_POOL;
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	ne_enclave = kzalloc(sizeof(*ne_enclave), GFP_KERNEL);
	if (!ne_enclave)
		return -ENOMEM;

	mutex_lock(&ne_cpu_pool.mutex);

	ne_enclave->avail_cpu_cores_size = ne_cpu_pool.avail_cores_size;
	ne_enclave->numa_node = ne_cpu_pool.numa_node;

	mutex_unlock(&ne_cpu_pool.mutex);

	ne_enclave->avail_cpu_cores = kcalloc(ne_enclave->avail_cpu_cores_size,
		sizeof(*ne_enclave->avail_cpu_cores), GFP_KERNEL);
	if (!ne_enclave->avail_cpu_cores) {
		rc = -ENOMEM;

		goto free_ne_enclave;
	}

	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		if (!zalloc_cpumask_var(&ne_enclave->avail_cpu_cores[i], GFP_KERNEL)) {
			rc = -ENOMEM;

			goto free_cpumask;
		}

	if (!zalloc_cpumask_var(&ne_enclave->vcpu_ids, GFP_KERNEL)) {
		rc = -ENOMEM;

		goto free_cpumask;
	}

	ne_enclave->pdev = pdev;

	enclave_fd = get_unused_fd_flags(O_CLOEXEC);
	if (enclave_fd < 0) {
		rc = enclave_fd;

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in getting unused fd [rc=%d]\n", rc);

		goto free_cpumask;
	}

	enclave_file = anon_inode_getfile("ne-vm", &ne_enclave_fops, ne_enclave, O_RDWR);
	if (IS_ERR(enclave_file)) {
		rc = PTR_ERR(enclave_file);

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in anon inode get file [rc=%d]\n", rc);

		goto put_fd;
	}

	rc = ne_do_request(ne_enclave->pdev, SLOT_ALLOC, &slot_alloc_req, sizeof(slot_alloc_req),
			   &cmd_reply, sizeof(cmd_reply));
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
	ne_enclave->slot_uid = cmd_reply.slot_uid;
	ne_enclave->state = NE_STATE_INIT;

	list_add(&ne_enclave->enclave_list_entry, &ne_pci_dev->enclaves_list);

	*slot_uid = ne_enclave->slot_uid;

	fd_install(enclave_fd, enclave_file);

	return enclave_fd;

put_file:
	fput(enclave_file);
put_fd:
	put_unused_fd(enclave_fd);
free_cpumask:
	free_cpumask_var(ne_enclave->vcpu_ids);
	for (i = 0; i < ne_enclave->avail_cpu_cores_size; i++)
		free_cpumask_var(ne_enclave->avail_cpu_cores[i]);
	kfree(ne_enclave->avail_cpu_cores);
free_ne_enclave:
	kfree(ne_enclave);

	return rc;
}

static long ne_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case NE_GET_API_VERSION:
		return NE_API_VERSION;

	case NE_CREATE_VM: {
		int enclave_fd = -1;
		struct file *enclave_file = NULL;
		struct ne_pci_dev *ne_pci_dev = NULL;
		/* TODO: Find another way to get the NE PCI device reference. */
		struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
						      PCI_DEVICE_ID_NE, NULL);
		int rc = -EINVAL;
		u64 slot_uid = 0;

		ne_pci_dev = pci_get_drvdata(pdev);

		mutex_lock(&ne_pci_dev->enclaves_list_mutex);

		enclave_fd = ne_create_vm_ioctl(pdev, ne_pci_dev, &slot_uid);
		if (enclave_fd < 0) {
			rc = enclave_fd;

			mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

			pci_dev_put(pdev);

			return rc;
		}

		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		if (copy_to_user((void __user *)arg, &slot_uid, sizeof(slot_uid))) {
			enclave_file = fget(enclave_fd);
			/* Decrement file refs to have release() called. */
			fput(enclave_file);
			fput(enclave_file);
			put_unused_fd(enclave_fd);

			return -EFAULT;
		}

		return enclave_fd;
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
	mutex_init(&ne_cpu_pool.mutex);

	return pci_register_driver(&ne_pci_driver);
}

static void __exit ne_exit(void)
{
	pci_unregister_driver(&ne_pci_driver);

	ne_teardown_cpu_pool();
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
