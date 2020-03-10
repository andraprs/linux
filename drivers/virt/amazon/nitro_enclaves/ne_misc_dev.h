/* SPDX-License-Identifier: GPL-2.0 */
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

#ifndef _NE_MISC_DEV_H_
#define _NE_MISC_DEV_H_

#include <linux/cpumask.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/wait.h>

/* Entry in vCPU IDs list. */
struct ne_vcpu_id {
	/* CPU id associated with a given slot, apic id on x86. */
	u32 vcpu_id;

	struct list_head vcpu_id_list_entry;
};

/* Entry in memory regions list. */
struct ne_mem_region {
	struct list_head mem_region_list_entry;

	/* Number of pages that make up the memory region. */
	unsigned long nr_pages;

	/* Pages that make up the user space memory region. */
	struct page **pages;
};

/* Per-enclave data used for enclave lifetime management. */
struct ne_enclave {
	/**
	 * CPU pool with siblings of already allocated CPUs to an enclave.
	 * This is used when a CPU pool is set, to be able to know the CPU
	 * siblings for the hyperthreading (HT) setup.
	 */
	cpumask_var_t cpu_siblings;

	struct list_head enclave_list_entry;

	/* Mutex for accessing this internal state. */
	struct mutex enclave_info_mutex;

	/**
	 * Wait queue used for out-of-band event notifications
	 * triggered from the PCI device event handler to the enclave
	 * process via the poll function.
	 */
	wait_queue_head_t eventq;

	/* Variable used to determine if the out-of-band event was triggered. */
	bool has_event;

	/**
	 * The maximum number of memory regions that can be handled by the
	 * lower levels.
	 */
	u64 max_mem_regions;

	/* Enclave memory regions list. */
	struct list_head mem_regions_list;

	/* Enclave process abstraction mm data struct. */
	struct mm_struct *mm;

	/* PCI device used for enclave lifetime management. */
	struct pci_dev *pdev;

	/* Slot unique id mapped to the enclave. */
	u64 slot_uid;

	/* Enclave state, updated during enclave lifetime. */
	u16 state;

	/* Enclave vCPUs list. */
	struct list_head vcpu_ids_list;
};

/**
 * States available for an enclave.
 *
 * TODO: Determine if the following states are exposing enough information
 * to the kernel driver.
 */
enum ne_state {
	/* NE_ENCLAVE_START ioctl was never issued for the enclave. */
	NE_STATE_INIT = 0,

	/**
	 * NE_ENCLAVE_START ioctl was issued and the enclave is running
	 * as expected.
	 */
	NE_STATE_RUNNING = 2,

	/* Enclave exited without userspace interaction. */
	NE_STATE_STOPPED = U16_MAX,
};

/* Nitro Enclaves (NE) misc device */
extern struct miscdevice ne_miscdevice;

#endif /* _NE_MISC_DEV_H_ */
