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
static int ne_set_kernel_param(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops ne_cpu_pool_ops = {
	.get = param_get_string,
	.set = ne_set_kernel_param,
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

static const struct file_operations ne_enclave_vcpu_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
};

/**
 * ne_check_enclaves_created - Verify if at least one enclave has been created.
 *
 * @pdev: PCI device used for enclave lifetime management.
 *
 * @returns: true if at least one enclave is created, false otherwise.
 */
static bool ne_check_enclaves_created(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	if (!ne_pci_dev)
		return false;

	mutex_lock(&ne_pci_dev->enclaves_list_mutex);

	if (list_empty(&ne_pci_dev->enclaves_list)) {
		mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

		return false;
	}

	mutex_unlock(&ne_pci_dev->enclaves_list_mutex);

	return true;
}

/**
 * ne_setup_cpu_pool - Set the NE CPU pool after handling sanity checks such as
 * not sharing CPU cores with the primary / parent VM or not using CPU 0, which
 * should remain available for the primary / parent VM. Offline the CPUs from
 * the pool after the checks passed.
 *
 * @pdev: PCI device used for enclave lifetime management.
 * @ne_cpu_list: the CPU list used for setting NE CPU pool.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_setup_cpu_pool(struct pci_dev *pdev, const char *ne_cpu_list)
{
	unsigned int cpu = 0;
	unsigned int cpu_sibling = 0;
	int numa_node = -1;
	int rc = -EINVAL;

	if (!capable(CAP_SYS_ADMIN)) {
		dev_err(&pdev->dev, "No admin capability for CPU pool setup\n");

		return -EPERM;
	}

	if (!ne_cpu_list)
		return 0;

	if (ne_check_enclaves_created(pdev)) {
		dev_err(&pdev->dev, "The CPU pool is used, enclaves created\n");

		return -EINVAL;
	}

	mutex_lock(&ne_cpu_pool.mutex);

	rc = cpulist_parse(ne_cpu_list, ne_cpu_pool.avail);
	if (rc < 0) {
		dev_err(&pdev->dev,
			"Error in cpulist parse [rc=%d]\n", rc);

		goto unlock_mutex;
	}

	/*
	 * Check if CPU 0 and its siblings are included in the provided CPU pool
	 * They should remain available for the primary / parent VM.
	 */
	if (cpumask_test_cpu(0, ne_cpu_pool.avail)) {

		dev_err(&pdev->dev,
			"CPU 0 has to remain available for the primary VM\n");

		rc = -EINVAL;

		goto unlock_mutex;
	}

	for_each_cpu(cpu_sibling, topology_sibling_cpumask(0)) {
		if (cpumask_test_cpu(cpu_sibling, ne_cpu_pool.avail)) {
			dev_err(&pdev->dev,
				"CPU sibling %d of CPU 0 is in the CPU pool\n",
				cpu_sibling);

			rc = -EINVAL;

			goto unlock_mutex;
		}
	}

	/*
	 * Check if CPU siblings are included in the provided CPU pool. The
	 * expectation is that CPU cores are made available in the CPU pool for
	 * enclaves.
	 */
	for_each_cpu(cpu, ne_cpu_pool.avail) {
		for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
			if (!cpumask_test_cpu(cpu_sibling, ne_cpu_pool.avail)) {
				dev_err(&pdev->dev,
					"CPU %d is not in the CPU pool\n",
					cpu_sibling);

				rc = -EINVAL;

				goto unlock_mutex;
			}
		}
	}

	/*
	 * Check if the CPUs from the NE CPU pool are from the same NUMA node.
	 */
	for_each_cpu(cpu, ne_cpu_pool.avail) {
		if (numa_node < 0) {
			numa_node = cpu_to_node(cpu);

			if (numa_node < 0) {
				dev_err(&pdev->dev,
					"Invalid NUMA node %d\n", numa_node);

				rc = -EINVAL;

				goto unlock_mutex;
			}
		} else {
			if (numa_node != cpu_to_node(cpu)) {
				dev_err(&pdev->dev,
					"CPUs are from different NUMA nodes\n");

				rc = -EINVAL;

				goto unlock_mutex;
			}
		}
	}

	for_each_cpu(cpu, ne_cpu_pool.avail) {
		rc = remove_cpu(cpu);
		if (rc != 0) {
			dev_err(&pdev->dev,
				"CPU %d is not offlined [rc=%d]\n", cpu, rc);

			goto online_cpus;
		}
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	return 0;

online_cpus:
	for_each_cpu(cpu, ne_cpu_pool.avail)
		add_cpu(cpu);
unlock_mutex:
	mutex_unlock(&ne_cpu_pool.mutex);

	return rc;
}

/**
 * ne_teardown_cpu_pool - Online the CPUs from the NE CPU pool and cleanup the
 * CPU pool.
 *
 * @pdev: PCI device used for enclave lifetime management.
 */
static void ne_teardown_cpu_pool(struct pci_dev *pdev)
{
	unsigned int cpu = 0;
	int rc = -EINVAL;

	if (!capable(CAP_SYS_ADMIN)) {
		dev_err(&pdev->dev, "No admin capability for CPU pool setup\n");

		return;
	}

	if (!ne_cpu_pool.avail)
		return;

	if (ne_check_enclaves_created(pdev)) {
		dev_err(&pdev->dev, "The CPU pool is used, enclaves created\n");

		return;
	}

	mutex_lock(&ne_cpu_pool.mutex);

	for_each_cpu(cpu, ne_cpu_pool.avail) {
		rc = add_cpu(cpu);
		if (rc != 0)
			dev_err(&pdev->dev,
				"CPU %d is not onlined [rc=%d]\n", cpu, rc);
	}

	cpumask_clear(ne_cpu_pool.avail);

	mutex_unlock(&ne_cpu_pool.mutex);
}

static int ne_set_kernel_param(const char *val, const struct kernel_param *kp)
{
	const char *ne_cpu_list = val;
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
					      PCI_DEVICE_ID_NE, NULL);
	int rc = -EINVAL;

	if (!pdev)
		return -ENODEV;

	ne_teardown_cpu_pool(pdev);

	rc = ne_setup_cpu_pool(pdev, ne_cpu_list);
	if (rc < 0) {
		dev_err(&pdev->dev, "Error in setup CPU pool [rc=%d]\n", rc);

		return rc;
	}

	return param_set_copystring(val, kp);
}

/**
 * ne_get_cpu_from_cpu_pool - Get a CPU from the CPU pool. If the vCPU id is 0,
 * the CPU is autogenerated and chosen from the NE CPU pool.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the CPU to be associated with the given slot, apic id on x86.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_get_cpu_from_cpu_pool(struct ne_enclave *ne_enclave, u32 *vcpu_id)
{
	unsigned int cpu = 0;
	unsigned int cpu_sibling = 0;

	if (*vcpu_id != 0) {
		if (cpumask_test_cpu(*vcpu_id, ne_enclave->cpu_siblings)) {
			cpumask_clear_cpu(*vcpu_id, ne_enclave->cpu_siblings);

			return 0;
		}

		mutex_lock(&ne_cpu_pool.mutex);

		if (!cpumask_test_cpu(*vcpu_id, ne_cpu_pool.avail)) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "CPU %d is not in NE CPU pool\n",
					    *vcpu_id);

			mutex_unlock(&ne_cpu_pool.mutex);

			return -EINVAL;
		}

		cpumask_clear_cpu(*vcpu_id, ne_cpu_pool.avail);

		/*
		 * Make sure the CPU siblings are not marked as available
		 * anymore.
		 */
		for_each_cpu(cpu_sibling, topology_sibling_cpumask(*vcpu_id)) {
			if (cpu_sibling != *vcpu_id) {
				cpumask_clear_cpu(cpu_sibling,
						  ne_cpu_pool.avail);

				cpumask_set_cpu(cpu_sibling,
						ne_enclave->cpu_siblings);
			}
		}

		mutex_unlock(&ne_cpu_pool.mutex);

		return 0;
	}

	/* There are CPU siblings available to choose from. */
	cpu = cpumask_any(ne_enclave->cpu_siblings);
	if (cpu < nr_cpu_ids) {
		cpumask_clear_cpu(cpu, ne_enclave->cpu_siblings);

		*vcpu_id = cpu;

		return 0;
	}

	mutex_lock(&ne_cpu_pool.mutex);

	/* Choose any CPU from the available CPU pool. */
	cpu = cpumask_any(ne_cpu_pool.avail);
	if (cpu >= nr_cpu_ids) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "No CPUs available in CPU pool\n");

		mutex_unlock(&ne_cpu_pool.mutex);

		return -EINVAL;
	}

	cpumask_clear_cpu(cpu, ne_cpu_pool.avail);

	/* Make sure the CPU siblings are not marked as available anymore. */
	for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
		if (cpu_sibling != cpu) {
			cpumask_clear_cpu(cpu_sibling, ne_cpu_pool.avail);

			cpumask_set_cpu(cpu_sibling, ne_enclave->cpu_siblings);
		}
	}

	mutex_unlock(&ne_cpu_pool.mutex);

	*vcpu_id = cpu;

	return 0;
}

/**
 * ne_create_vcpu_ioctl - Add vCPU to the slot associated with the current
 * enclave. Create vCPU file descriptor to be further used for CPU handling.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @vcpu_id: id of the CPU to be associated with the given slot, apic id on x86.
 *
 * @returns: vCPU fd on success, negative return value on failure.
 */
static int ne_create_vcpu_ioctl(struct ne_enclave *ne_enclave, u32 vcpu_id)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	int fd = 0;
	struct file *file = NULL;
	struct ne_vcpu_id *ne_vcpu_id = NULL;
	int rc = -EINVAL;
	struct slot_add_vcpu_req slot_add_vcpu_req = {};

	if (ne_enclave->mm != current->mm)
		return -EIO;

	ne_vcpu_id = kzalloc(sizeof(*ne_vcpu_id), GFP_KERNEL);
	if (!ne_vcpu_id)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in getting unused fd [rc=%d]\n", rc);

		goto free_ne_vcpu_id;
	}

	/* TODO: Include (vcpu) id in the ne-vm-vcpu naming. */
	file = anon_inode_getfile("ne-vm-vcpu", &ne_enclave_vcpu_fops,
				  ne_enclave, O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);

		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in anon inode get file [rc=%d]\n",
				    rc);

		goto put_fd;
	}

	slot_add_vcpu_req.slot_uid = ne_enclave->slot_uid;
	slot_add_vcpu_req.vcpu_id = vcpu_id;

	rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_VCPU, &slot_add_vcpu_req,
			   sizeof(slot_add_vcpu_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Error in slot add vcpu [rc=%d]\n", rc);

		goto put_file;
	}

	ne_vcpu_id->vcpu_id = vcpu_id;

	list_add(&ne_vcpu_id->vcpu_id_list_entry, &ne_enclave->vcpu_ids_list);

	ne_enclave->nr_vcpus++;

	fd_install(fd, file);

	return fd;

put_file:
	fput(file);
put_fd:
	put_unused_fd(fd);
free_ne_vcpu_id:
	kfree(ne_vcpu_id);

	return rc;
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

	if ((mem_region->memory_size % NE_MIN_MEM_REGION_SIZE) != 0) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Mem size not multiple of 2 MiB\n");

		return -EINVAL;
	}

	if ((mem_region->userspace_addr & (NE_MIN_MEM_REGION_SIZE - 1)) ||
	    !access_ok((void __user *)(unsigned long)mem_region->userspace_addr,
		       mem_region->memory_size)) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Invalid user space addr range\n");

		return -EINVAL;
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
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	long gup_rc = 0;
	unsigned long i = 0;
	struct ne_mem_region *ne_mem_region = NULL;
	unsigned long nr_phys_contig_mem_regions = 0;
	unsigned long nr_pinned_pages = 0;
	struct page **phys_contig_mem_regions = NULL;
	int rc = -EINVAL;
	struct slot_add_mem_req slot_add_mem_req = {};

	rc = ne_sanity_check_user_mem_region(ne_enclave, mem_region);
	if (rc < 0)
		return rc;

	ne_mem_region = kzalloc(sizeof(*ne_mem_region), GFP_KERNEL);
	if (!ne_mem_region)
		return -ENOMEM;

	/*
	 * TODO: Update nr_pages value to handle contiguous virtual address
	 * ranges mapped to non-contiguous physical regions. Hugetlbfs can give
	 * 2 MiB / 1 GiB contiguous physical regions.
	 */
	ne_mem_region->nr_pages = mem_region->memory_size /
		NE_MIN_MEM_REGION_SIZE;

	ne_mem_region->pages = kcalloc(ne_mem_region->nr_pages,
				       sizeof(*ne_mem_region->pages),
				       GFP_KERNEL);
	if (!ne_mem_region->pages) {
		kfree(ne_mem_region);

		return -ENOMEM;
	}

	phys_contig_mem_regions = kcalloc(ne_mem_region->nr_pages,
					  sizeof(*phys_contig_mem_regions),
					  GFP_KERNEL);
	if (!phys_contig_mem_regions) {
		kfree(ne_mem_region->pages);
		kfree(ne_mem_region);

		return -ENOMEM;
	}

	/*
	 * TODO: Handle non-contiguous memory regions received from user space.
	 * Hugetlbfs can give 2 MiB / 1 GiB contiguous physical regions. The
	 * virtual address space can be seen as contiguous, although it is
	 * mapped underneath to 2 MiB / 1 GiB physical regions e.g. 8 MiB
	 * virtual address space mapped to 4 physically contiguous regions of 2
	 * MiB.
	 */
	do {
		unsigned long tmp_nr_pages = ne_mem_region->nr_pages -
			nr_pinned_pages;
		struct page **tmp_pages = ne_mem_region->pages +
			nr_pinned_pages;
		u64 tmp_userspace_addr = mem_region->userspace_addr +
			nr_pinned_pages * NE_MIN_MEM_REGION_SIZE;

		gup_rc = get_user_pages(tmp_userspace_addr, tmp_nr_pages,
					FOLL_GET, tmp_pages, NULL);
		if (gup_rc < 0) {
			rc = gup_rc;

			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in gup [rc=%d]\n", rc);

			unpin_user_pages(ne_mem_region->pages, nr_pinned_pages);

			goto free_mem_region;
		}

		nr_pinned_pages += gup_rc;

	} while (nr_pinned_pages < ne_mem_region->nr_pages);

	/*
	 * TODO: Update checks once physically contiguous regions are collected
	 * based on the user space address and get_user_pages() results.
	 */
	for (i = 0; i < ne_mem_region->nr_pages; i++) {
		if (!PageHuge(ne_mem_region->pages[i])) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Not a hugetlbfs page\n");

			goto unpin_pages;
		}

		if (huge_page_size(page_hstate(ne_mem_region->pages[i])) !=
		    NE_MIN_MEM_REGION_SIZE) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Page size isn't 2 MiB\n");

			goto unpin_pages;
		}

		if (ne_enclave->numa_node !=
		    page_to_nid(ne_mem_region->pages[i])) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Page isn't from NUMA node %d\n",
					    ne_enclave->numa_node);

			goto unpin_pages;
		}

		/*
		 * TODO: Update once handled non-contiguous memory regions
		 * received from user space.
		 */
		phys_contig_mem_regions[i] = ne_mem_region->pages[i];
	}

	/*
	 * TODO: Update once handled non-contiguous memory regions received
	 * from user space.
	 */
	nr_phys_contig_mem_regions = ne_mem_region->nr_pages;

	if ((ne_enclave->nr_mem_regions + nr_phys_contig_mem_regions) >
	    ne_enclave->max_mem_regions) {
		dev_err_ratelimited(ne_misc_dev.this_device,
				    "Reached max memory regions %lld\n",
				    ne_enclave->max_mem_regions);

		goto unpin_pages;
	}

	for (i = 0; i < nr_phys_contig_mem_regions; i++) {
		u64 phys_addr = page_to_phys(phys_contig_mem_regions[i]);

		slot_add_mem_req.slot_uid = ne_enclave->slot_uid;
		slot_add_mem_req.paddr = phys_addr;
		/*
		 * TODO: Update memory size of physical contiguous memory
		 * region, in case of non-contiguous memory regions received
		 * from user space.
		 */
		slot_add_mem_req.size = NE_MIN_MEM_REGION_SIZE;

		rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_MEM,
				   &slot_add_mem_req, sizeof(slot_add_mem_req),
				   &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in slot add mem [rc=%d]\n",
					    rc);

			/* TODO: Only unpin memory regions not added. */
			goto unpin_pages;
		}

		ne_enclave->mem_size += slot_add_mem_req.size;
		ne_enclave->nr_mem_regions++;

		memset(&slot_add_mem_req, 0, sizeof(slot_add_mem_req));
		memset(&cmd_reply, 0, sizeof(cmd_reply));
	}

	list_add(&ne_mem_region->mem_region_list_entry,
		 &ne_enclave->mem_regions_list);

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

static long ne_enclave_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	if (!ne_enclave || !ne_enclave->pdev)
		return -EINVAL;

	switch (cmd) {
	case NE_CREATE_VCPU: {
		int rc = -EINVAL;
		u32 vcpu_id = 0;

		if (copy_from_user(&vcpu_id, (void *)arg, sizeof(vcpu_id))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave isn't in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		/* Use the CPU pool for choosing a CPU for the enclave. */
		rc = ne_get_cpu_from_cpu_pool(ne_enclave, &vcpu_id);
		if (rc < 0) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in get CPU from pool\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		rc = ne_create_vcpu_ioctl(ne_enclave, vcpu_id);

		/* Put back the CPU in enclave cpu pool, if add vcpu error. */
		if (rc < 0)
			cpumask_set_cpu(vcpu_id, ne_enclave->cpu_siblings);

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void *)arg, &vcpu_id, sizeof(vcpu_id))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			return -EFAULT;
		}

		return rc;
	}

	case NE_GET_IMAGE_LOAD_INFO: {
		struct ne_image_load_info image_load_info = {};

		if (copy_from_user(&image_load_info, (void *)arg,
				   sizeof(image_load_info))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		if (image_load_info.flags == NE_EIF_IMAGE)
			image_load_info.memory_offset = NE_EIF_LOAD_OFFSET;

		if (copy_to_user((void *)arg, &image_load_info,
				 sizeof(image_load_info))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy to user\n");

			return -EFAULT;
		}

		return 0;
	}

	case NE_SET_USER_MEMORY_REGION: {
		struct ne_user_memory_region mem_region = {};
		int rc = -EINVAL;

		if (copy_from_user(&mem_region, (void *)arg,
				   sizeof(mem_region))) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Error in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (ne_enclave->state != NE_STATE_INIT) {
			dev_err_ratelimited(ne_misc_dev.this_device,
					    "Enclave isn't in init state\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		rc = ne_set_user_memory_region_ioctl(ne_enclave, &mem_region);

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return rc;
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
	struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_AMAZON,
					      PCI_DEVICE_ID_NE, NULL);
	if (!pdev)
		return;

	pci_unregister_driver(&ne_pci_driver);

	ne_teardown_cpu_pool(pdev);

	free_cpumask_var(ne_cpu_pool.avail);
}

/* TODO: Handle actions such as reboot, kexec. */

module_init(ne_init);
module_exit(ne_exit);

MODULE_AUTHOR("Amazon.com, Inc. or its affiliates");
MODULE_DESCRIPTION("Nitro Enclaves Driver");
MODULE_LICENSE("GPL v2");
