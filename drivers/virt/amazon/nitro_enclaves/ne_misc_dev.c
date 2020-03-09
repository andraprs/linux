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

static int ne_enclave_vcpu_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_enclave_vcpu_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	switch (cmd) {
	default:
		return -ENOTTY;
	}

	return 0;
}

static int ne_enclave_vcpu_release(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations ne_enclave_vcpu_fops = {
	.owner		= THIS_MODULE,
	.llseek		= noop_llseek,
	.unlocked_ioctl	= ne_enclave_vcpu_ioctl,
	.open		= ne_enclave_vcpu_open,
	.release	= ne_enclave_vcpu_release,
};

/**
 * ne_get_cpu_from_cpu_pool - Get a CPU from the CPU pool, if it is set.
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

	BUG_ON(!ne_enclave);

	if (WARN_ON(!vcpu_id))
		return -EINVAL;

	/* There are CPU siblings available to choose from. */
	cpu = cpumask_any(ne_enclave->cpu_siblings);
	if (cpu < nr_cpu_ids) {
		cpumask_clear_cpu(cpu, ne_enclave->cpu_siblings);

		*vcpu_id = cpu;

		return 0;
	}

	mutex_lock(&ne_cpu_pool_mutex);

	/* Choose any CPU from the available CPU pool. */
	cpu = cpumask_any(ne_cpu_pool.avail);
	if (cpu >= nr_cpu_ids) {
		pr_err_ratelimited("No CPUs available in CPU pool\n");

		mutex_unlock(&ne_cpu_pool_mutex);

		return -EINVAL;
	}

	cpumask_clear_cpu(cpu, ne_cpu_pool.avail);

	/*
	 * Make sure the CPU siblings are not marked as
	 * available anymore.
	 */
	for_each_cpu(cpu_sibling, topology_sibling_cpumask(cpu)) {
		if (cpu_sibling != cpu) {
			cpumask_clear_cpu(cpu_sibling, ne_cpu_pool.avail);

			cpumask_set_cpu(cpu_sibling, ne_enclave->cpu_siblings);
		}
	}

	mutex_unlock(&ne_cpu_pool_mutex);

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

	BUG_ON(!ne_enclave);
	BUG_ON(!ne_enclave->pdev);

	if (ne_enclave->mm != current->mm)
		return -EIO;

	ne_vcpu_id = kzalloc(sizeof(*ne_vcpu_id), GFP_KERNEL);
	if (!ne_vcpu_id)
		return -ENOMEM;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		rc = fd;

		pr_err_ratelimited("Failure in getting unused fd [rc=%d]\n",
				   rc);

		goto err_get_unused_fd;
	}

	/* TODO: Include (vcpu) id in the ne-vm-vcpu naming. */
	file = anon_inode_getfile("ne-vm-vcpu", &ne_enclave_vcpu_fops,
				  ne_enclave, O_RDWR);
	if (IS_ERR(file)) {
		rc = PTR_ERR(file);

		pr_err_ratelimited("Failure in anon inode get file [rc=%d]\n",
				   rc);

		goto err_anon_inode_getfile;
	}

	slot_add_vcpu_req.slot_uid = ne_enclave->slot_uid;
	slot_add_vcpu_req.vcpu_id = vcpu_id;

	rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_VCPU, &slot_add_vcpu_req,
			   sizeof(slot_add_vcpu_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		pr_err_ratelimited("Failure in slot add vcpu [rc=%d]\n", rc);

		goto err_slot_add_vcpu;
	}

	ne_vcpu_id->vcpu_id = vcpu_id;

	list_add(&ne_vcpu_id->vcpu_id_list_entry, &ne_enclave->vcpu_ids_list);

	fd_install(fd, file);

	return fd;

err_slot_add_vcpu:
	fput(file);
err_anon_inode_getfile:
	put_unused_fd(fd);
err_get_unused_fd:
	kzfree(ne_vcpu_id);
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
	struct kvm_userspace_memory_region *mem_region)
{
	BUG_ON(!ne_enclave);

	if (WARN_ON(!mem_region))
		return -EINVAL;

	if (mem_region->slot > ne_enclave->max_mem_regions) {
		pr_err_ratelimited("Mem slot higher than max mem regions\n");

		return -EINVAL;
	}

	if ((mem_region->memory_size % MIN_MEM_REGION_SIZE) != 0) {
		pr_err_ratelimited("Mem region size not multiple of 2 MiB\n");

		return -EINVAL;
	}

	if ((mem_region->userspace_addr & (MIN_MEM_REGION_SIZE - 1)) ||
	    !access_ok((void __user *)(unsigned long)mem_region->userspace_addr,
		       mem_region->memory_size)) {
		pr_err_ratelimited("Invalid user space addr range\n");

		return -EINVAL;
	}

	if ((mem_region->guest_phys_addr + mem_region->memory_size) <
	    mem_region->guest_phys_addr) {
		pr_err_ratelimited("Invalid guest phys addr range\n");

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
	struct kvm_userspace_memory_region *mem_region)
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

	BUG_ON(!ne_enclave);
	BUG_ON(!ne_enclave->pdev);

	if (WARN_ON(!mem_region))
		return -EINVAL;

	if (ne_enclave->mm != current->mm)
		return -EIO;

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
	ne_mem_region->nr_pages = mem_region->memory_size / MIN_MEM_REGION_SIZE;

	ne_mem_region->pages = kcalloc(ne_mem_region->nr_pages,
				       sizeof(*ne_mem_region->pages),
				       GFP_KERNEL);
	if (!ne_mem_region->pages) {
		kzfree(ne_mem_region);

		return -ENOMEM;
	}

	phys_contig_mem_regions = kcalloc(ne_mem_region->nr_pages,
					  sizeof(*phys_contig_mem_regions),
					  GFP_KERNEL);
	if (!phys_contig_mem_regions) {
		kzfree(ne_mem_region->pages);
		kzfree(ne_mem_region);

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
			nr_pinned_pages * MIN_MEM_REGION_SIZE;

		gup_rc = get_user_pages(tmp_userspace_addr, tmp_nr_pages,
					FOLL_GET, tmp_pages, NULL);
		if (gup_rc < 0) {
			rc = gup_rc;

			pr_err_ratelimited("Failure in gup [rc=%d]\n", rc);

			unpin_user_pages(ne_mem_region->pages, nr_pinned_pages);

			goto err_get_user_pages;
		}

		nr_pinned_pages += gup_rc;

	} while (nr_pinned_pages < ne_mem_region->nr_pages);

	/*
	 * TODO: Update checks once physically contiguous regions are collected
	 * based on the user space address and get_user_pages() results.
	 */
	for (i = 0; i < ne_mem_region->nr_pages; i++) {
		if (!PageHuge(ne_mem_region->pages[i])) {
			pr_err_ratelimited("The page isn't a hugetlbfs page\n");

			goto err_phys_pages_check;
		}

		if (huge_page_size(page_hstate(ne_mem_region->pages[i])) !=
		    MIN_MEM_REGION_SIZE) {
			pr_err_ratelimited("The page size isn't 2 MiB\n");

			goto err_phys_pages_check;
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

	for (i = 0; i < nr_phys_contig_mem_regions; i++) {
		u64 phys_addr = page_to_phys(phys_contig_mem_regions[i]);

		slot_add_mem_req.slot_uid = ne_enclave->slot_uid;
		slot_add_mem_req.paddr = phys_addr;
		/*
		 * TODO: Update memory size of physical contiguous memory
		 * region, in case of non-contiguous memory regions received
		 * from user space.
		 */
		slot_add_mem_req.size = MIN_MEM_REGION_SIZE;

		rc = ne_do_request(ne_enclave->pdev, SLOT_ADD_MEM,
				   &slot_add_mem_req, sizeof(slot_add_mem_req),
				   &cmd_reply, sizeof(cmd_reply));
		if (rc < 0) {
			pr_err_ratelimited("Failure in slot add mem [rc=%d]\n",
					   rc);

			goto err_slot_add_mem;
		}

		memset(&slot_add_mem_req, 0, sizeof(slot_add_mem_req));
		memset(&cmd_reply, 0, sizeof(cmd_reply));
	}

	list_add(&ne_mem_region->mem_region_list_entry,
		 &ne_enclave->mem_regions_list);

	kzfree(phys_contig_mem_regions);

	return 0;

err_slot_add_mem:
err_phys_pages_check:
	unpin_user_pages(ne_mem_region->pages, ne_mem_region->nr_pages);
err_get_user_pages:
	kzfree(phys_contig_mem_regions);
	kzfree(ne_mem_region->pages);
	kzfree(ne_mem_region);
	return rc;
}

/**
 * ne_enclave_start_ioctl - Trigger enclave start after the enclave resources,
 * such as memory and CPU, have been set.
 *
 * This function gets called with the ne_enclave mutex held.
 *
 * @ne_enclave: private data associated with the current enclave.
 * @enclave_start_metadata: enclave metadata that includes enclave cid and
 *			    flags and the slot uid.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_enclave_start_ioctl(struct ne_enclave *ne_enclave,
	struct enclave_start_metadata *enclave_start_metadata)
{
	struct ne_pci_dev_cmd_reply cmd_reply = {};
	struct enclave_start_req enclave_start_req = {};
	int rc = -EINVAL;

	BUG_ON(!ne_enclave);
	BUG_ON(!ne_enclave->pdev);

	if (WARN_ON(!enclave_start_metadata))
		return -EINVAL;

	enclave_start_metadata->slot_uid = ne_enclave->slot_uid;

	enclave_start_req.enclave_cid = enclave_start_metadata->enclave_cid;
	enclave_start_req.flags = enclave_start_metadata->flags;
	enclave_start_req.slot_uid = enclave_start_metadata->slot_uid;

	rc = ne_do_request(ne_enclave->pdev, ENCLAVE_START, &enclave_start_req,
			   sizeof(enclave_start_req), &cmd_reply,
			   sizeof(cmd_reply));
	if (rc < 0) {
		pr_err_ratelimited("Failure in enclave start [rc=%d]\n", rc);

		return rc;
	}

	ne_enclave->state = NE_STATE_RUNNING;

	enclave_start_metadata->enclave_cid = cmd_reply.enclave_cid;

	return 0;
}

static int ne_enclave_open(struct inode *node, struct file *file)
{
	return 0;
}

static long ne_enclave_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	struct ne_enclave *ne_enclave = file->private_data;

	BUG_ON(!ne_enclave);

	switch (cmd) {
	case KVM_CREATE_VCPU: {
		int rc = -EINVAL;
		u32 vcpu_id = 0;

		if (copy_from_user(&vcpu_id, (void *)arg, sizeof(vcpu_id))) {
			pr_err_ratelimited("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		/* Use the CPU pool for choosing a CPU for the enclave. */
		rc = ne_get_cpu_from_cpu_pool(ne_enclave, &vcpu_id);
		if (rc < 0) {
			pr_err_ratelimited("Failure in get CPU from pool\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		rc = ne_create_vcpu_ioctl(ne_enclave, vcpu_id);

		/* Put back the CPU in enclave cpu pool, if add vcpu error. */
		if (rc < 0)
			cpumask_set_cpu(vcpu_id, ne_enclave->cpu_siblings);

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return rc;
	}

	case KVM_SET_USER_MEMORY_REGION: {
		struct kvm_userspace_memory_region mem_region = {};
		int rc = -EINVAL;

		if (copy_from_user(&mem_region, (void *)arg,
				   sizeof(mem_region))) {
			pr_err_ratelimited("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		rc = ne_set_user_memory_region_ioctl(ne_enclave, &mem_region);

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		return rc;
	}

	case NE_ENCLAVE_START: {
		struct enclave_start_metadata enclave_start_metadata = {};
		int rc = -EINVAL;

		if (copy_from_user(&enclave_start_metadata, (void *)arg,
				   sizeof(enclave_start_metadata))) {
			pr_err_ratelimited("Failure in copy from user\n");

			return -EFAULT;
		}

		mutex_lock(&ne_enclave->enclave_info_mutex);

		if (!cpumask_empty(ne_enclave->cpu_siblings)) {
			pr_err_ratelimited("Enclave has CPU siblings avail\n");

			mutex_unlock(&ne_enclave->enclave_info_mutex);

			return -EINVAL;
		}

		rc = ne_enclave_start_ioctl(ne_enclave,
					    &enclave_start_metadata);

		mutex_unlock(&ne_enclave->enclave_info_mutex);

		if (copy_to_user((void *)arg, &enclave_start_metadata,
				 sizeof(enclave_start_metadata))) {
			pr_err_ratelimited("Failure in copy to user\n");

			return -EFAULT;
		}

		return rc;
	}

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
