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
 * Sample flow of using the ioctl interface provided by the Nitro Enclaves (NE)
 * kernel driver.
 *
 * Usage
 * -----
 *
 * Load the nitro_enclaves module, setting also the enclave CPU pool.
 *
 * See the cpu list section from the kernel documentation.
 * https://www.kernel.org/doc/html/latest/admin-guide/kernel-parameters.html
 *
 *	insmod drivers/virt/nitro_enclaves/nitro_enclaves.ko ne_cpus=<cpu-list>
 *	lsmod
 *
 * Check dmesg for any warnings / errors through the NE driver lifetime / usage.
 * The NE logs contain the "nitro_enclaves" pattern.
 *
 *	dmesg
 *
 * Check the online / offline CPU list. The CPUs from the pool should be
 * offlined.
 *
 *	lscpu
 *
 * Setup hugetlbfs huge pages.
 *
 *	echo <nr_hugepages> > /proc/sys/vm/nr_hugepages
 *
 *	In this example 256 hugepages of 2 MiB are used.
 *
 * Build and run the NE sample.
 *
 *	make -C samples/nitro_enclaves clean
 *	make -C samples/nitro_enclaves
 *	./samples/nitro_enclaves/ne_ioctl_sample <path_to_enclave_image>
 *
 * Unload the nitro_enclaves module.
 *
 *	rmmod nitro_enclaves
 *	lsmod
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/nitro_enclaves.h>
#include <linux/vm_sockets.h>

/* Nitro Enclaves (NE) misc device that provides the ioctl interface. */
#define NE_DEV_NAME "/dev/nitro_enclaves"

/* Timeout in seconds / milliseconds for each poll event. */
#define POLL_WAIT_TIME (60)
#define POLL_WAIT_TIME_MS (POLL_WAIT_TIME * 1000)

/* Amount of time in seconds for the process to keep the enclave alive. */
#define SLEEP_TIME (300)

/* Enclave vCPUs metadata. */
#define DEFAULT_NR_VCPUS (2)

/* Enclave memory metadata */
/* Min memory size - 2 MiB */
#define MIN_MEM_REGION_SIZE (2 * 1024 * 1024)
/* 256 memory regions of 2 MiB */
#define DEFAULT_NR_MEM_REGIONS (256)

/* Vsock addressing for enclave image loading heartbeat. */
#define VSOCK_CID (3)
#define VSOCK_PORT (9000)
#define HEARTBEAT_VALUE (0xb7)

struct ne_mem_region {
	void *mem_addr;
	size_t mem_size;
};

struct ne_vcpu {
	int vcpu_fd;
	unsigned int vcpu_id;
};

/* Thread function for polling the enclave fd. */
void *ne_poll_enclave_fd(void *data)
{
	int enclave_fd = *(int *)data;
	struct pollfd fds[1] = {};
	int i = 0;
	int rc = 0;

	printf("Running from poll thread, enclave fd %d\n", enclave_fd);

	fds[0].fd = enclave_fd;
	fds[0].events = POLLIN | POLLERR | POLLHUP;

	/* Keep on polling until the current process is terminated. */
	while (1) {
		printf("[iter %d] Polling ...\n", i);

		rc = poll(fds, 1, POLL_WAIT_TIME_MS);
		if (rc < 0) {
			printf("Error in poll [%m]\n");

			return NULL;
		}

		i++;

		if (!rc) {
			printf("Poll: %d seconds elapsed\n",
			       i * POLL_WAIT_TIME);

			continue;
		}

		printf("Poll received value %d\n", fds[0].revents);
	}

	return NULL;
}

/* Allocate memory region that will be used for the enclave. */
int ne_alloc_mem_region(struct ne_mem_region *ne_mem_region)
{
	if (!ne_mem_region)
		return -EINVAL;

	if (!ne_mem_region->mem_size)
		return -EINVAL;

	ne_mem_region->mem_addr = mmap(NULL, ne_mem_region->mem_size,
				       PROT_READ | PROT_WRITE,
				       MAP_PRIVATE | MAP_ANONYMOUS |
				       MAP_HUGETLB, -1, 0);
	if (ne_mem_region->mem_addr == MAP_FAILED) {
		printf("Error in mmap memory [%m]\n");

		return -1;
	}

	return 0;
}

/* Place enclave image in enclave memory. */
int ne_load_enclave_image(int enclave_fd, struct ne_mem_region ne_mem_regions[],
			  char enclave_image_path[])
{
	struct image_load_metadata image_load_metadata = {};
	int rc = 0;

	if (enclave_fd < 0)
		return -EINVAL;

	/* TODO: Set flags based on enclave image type. */
	image_load_metadata.flags = 0;

	rc = ioctl(enclave_fd, NE_GET_IMAGE_LOAD_METADATA,
		   &image_load_metadata);
	if (rc < 0) {
		printf("Error in get image load metadata [rc=%d]\n", rc);

		return rc;
	}

	printf("Enclave image offset in enclave memory is %lld\n",
	       image_load_metadata.memory_offset);

	/*
	 * TODO: Copy enclave image in enclave memory starting from the given
	 * offset.
	 */

	return 0;
}

/* Wait for a hearbeat from the enclave to check it has booted. */
int ne_check_enclave_booted(void)
{
	struct sockaddr_vm client_vsock_addr = {};
	socklen_t client_vsock_len = sizeof(client_vsock_addr);
	struct pollfd fds[1] = {};
	int rc = 0;
	unsigned char recv_buf = 0;
	struct sockaddr_vm server_vsock_addr = {
		.svm_family = AF_VSOCK,
		.svm_cid = VSOCK_CID,
		.svm_port = VSOCK_PORT,
	};
	int server_vsock_fd = 0;

	server_vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
	if (server_vsock_fd < 0) {
		rc = server_vsock_fd;

		printf("Error in socket [rc=%d]\n", rc);

		return rc;
	}

	rc = bind(server_vsock_fd, (struct sockaddr *)&server_vsock_addr,
		  sizeof(server_vsock_addr));
	if (rc < 0) {
		printf("Error in bind [rc=%d]\n", rc);

		goto out;
	}

	rc = listen(server_vsock_fd, 1);
	if (rc < 0) {
		printf("Error in listen [rc=%d]\n", rc);

		goto out;
	}

	fds[0].fd = server_vsock_fd;
	fds[0].events = POLLIN;

	rc = poll(fds, 1, POLL_WAIT_TIME_MS);
	if (rc < 0) {
		printf("Error in poll [%m]\n");

		goto out;
	}

	if (!rc) {
		printf("Poll timeout, %d seconds elapsed\n", POLL_WAIT_TIME);

		rc = -ETIMEDOUT;

		goto out;
	}

	if ((fds[0].revents & POLLIN) == 0) {
		printf("Poll received value %d\n", fds[0].revents);

		rc = -EINVAL;

		goto out;
	}

	rc = accept(server_vsock_fd, (struct sockaddr *)&client_vsock_addr,
		    &client_vsock_len);
	if (rc < 0) {
		printf("Error in accept [rc=%d]\n", rc);

		goto out;
	}

	/*
	 * Read the heartbeat value that the init process in the enclave sends
	 * after vsock connect.
	 */
	rc = read(server_vsock_fd, &recv_buf, sizeof(recv_buf));
	if (rc < 0) {
		printf("Error in read [rc=%d]\n", rc);

		goto out;
	}

	if (rc != sizeof(recv_buf) || recv_buf != HEARTBEAT_VALUE) {
		printf("Read %d instead of %d\n", recv_buf, HEARTBEAT_VALUE);

		goto out;
	}

	close(server_vsock_fd);

	return 0;

out:
	close(server_vsock_fd);

	return rc;
}

/* Set memory region for the given enclave. */
int ne_set_mem_region(int enclave_fd, struct ne_mem_region ne_mem_region)
{
	struct kvm_userspace_memory_region mem_region = {};
	int rc = 0;

	if (enclave_fd < 0)
		return -EINVAL;

	mem_region.slot = 0;
	mem_region.memory_size = ne_mem_region.mem_size;
	mem_region.userspace_addr = (__u64)ne_mem_region.mem_addr;
	mem_region.guest_phys_addr = 0;

	rc = ioctl(enclave_fd, KVM_SET_USER_MEMORY_REGION, &mem_region);
	if (rc < 0) {
		printf("Error in set user memory region [rc=%d]\n", rc);

		return rc;
	}

	return 0;
}

/* Unmap all the memory regions that were set aside for the  enclave. */
void ne_free_mem_regions(struct ne_mem_region ne_mem_regions[])
{
	unsigned int i = 0;

	for (i = 0; i < DEFAULT_NR_MEM_REGIONS; i++)
		munmap(ne_mem_regions[i].mem_addr, ne_mem_regions[i].mem_size);
}

/* Create enclave vCPU. */
int ne_create_vcpu(int enclave_fd, struct ne_vcpu *ne_vcpu)
{
	if (enclave_fd < 0)
		return -EINVAL;

	if (!ne_vcpu)
		return -EINVAL;

	ne_vcpu->vcpu_fd = ioctl(enclave_fd, KVM_CREATE_VCPU,
				 &ne_vcpu->vcpu_id);
	if (ne_vcpu->vcpu_fd < 0) {
		printf("Error in create vcpu [rc=%d]\n", ne_vcpu->vcpu_fd);

		return ne_vcpu->vcpu_fd;
	}

	return 0;
}

/* Release enclave vCPU fd(s). */
void ne_release_vcpus(struct ne_vcpu ne_vcpus[])
{
	unsigned int i = 0;

	for (i = 0; i < DEFAULT_NR_VCPUS; i++)
		if (ne_vcpus[i].vcpu_fd > 0)
			close(ne_vcpus[i].vcpu_fd);
}

int main(int argc, char *argv[])
{
	int enclave_fd = 0;
	char enclave_image_path[PATH_MAX] = {};
	unsigned int i = 0;
	int ne_dev_fd = 0;
	struct ne_mem_region ne_mem_regions[DEFAULT_NR_MEM_REGIONS] = {};
	struct enclave_start_metadata ne_start_metadata = {};
	struct ne_vcpu ne_vcpus[DEFAULT_NR_VCPUS] = {};
	int rc = 0;
	pthread_t thread_id = 0;
	unsigned long type = 0;

	if (argc != 2) {
		printf("Usage: %s <path_to_enclave_image>\n", argv[0]);

		exit(EXIT_FAILURE);
	}

	strncpy(enclave_image_path, argv[1], sizeof(enclave_image_path) - 1);

	ne_dev_fd = open(NE_DEV_NAME, O_RDWR | O_CLOEXEC);
	if (ne_dev_fd < 0) {
		printf("Error in open NE device [rc=%d]\n", ne_dev_fd);

		exit(EXIT_FAILURE);
	}

	printf("Creating enclave slot ...\n");

	enclave_fd = ioctl(ne_dev_fd, KVM_CREATE_VM, &type);

	close(ne_dev_fd);

	if (enclave_fd < 0) {
		printf("Error in create enclave slot [rc=%d]\n", enclave_fd);

		exit(EXIT_FAILURE);
	}

	printf("Enclave fd %d\n", enclave_fd);

	rc = pthread_create(&thread_id, NULL, ne_poll_enclave_fd,
			    (void *)&enclave_fd);
	if (rc < 0) {
		printf("Error in thread create [rc=%d]\n", rc);

		close(enclave_fd);

		exit(EXIT_FAILURE);
	}

	for (i = 0; i < DEFAULT_NR_MEM_REGIONS; i++) {
		ne_mem_regions[i].mem_size = MIN_MEM_REGION_SIZE;
		rc = ne_alloc_mem_region(&ne_mem_regions[i]);
		if (rc < 0) {
			printf("Error in alloc mem region, iter %d [rc=%d]\n",
			       i, rc);

			goto release_enclave_fd;
		}
	}

	rc = ne_load_enclave_image(enclave_fd, ne_mem_regions,
				   enclave_image_path);
	if (rc < 0) {
		printf("Error in load enclave image [rc=%d]\n", rc);

		goto release_enclave_fd;
	}

	for (i = 0; i < DEFAULT_NR_MEM_REGIONS; i++) {
		rc = ne_set_mem_region(enclave_fd, ne_mem_regions[i]);
		if (rc < 0) {
			printf("Error in set mem region, iter %d [rc=%d]\n",
			       i, rc);

			goto release_enclave_fd;
		}
	}

	printf("Enclave memory regions were added\n");

	for (i = 0; i < DEFAULT_NR_VCPUS; i++) {
		/*
		 * The vCPU is chosen from the enclave vCPU pool, this value is
		 * not used for now.
		 */
		ne_vcpus[i].vcpu_id = i;
		rc = ne_create_vcpu(enclave_fd, &ne_vcpus[i]);
		if (rc < 0) {
			printf("Error in create vcpu, iter %d [rc=%d]\n",
			       i, rc);

			goto release_enclave_vcpu_fds;
		}
	}

	printf("Enclave vCPUs were created\n");

	rc = ioctl(enclave_fd, NE_START_ENCLAVE, &ne_start_metadata);
	if (rc < 0) {
		printf("Error in start enclave [rc=%d]\n", rc);

		goto release_enclave_vcpu_fds;
	}

	printf("Enclave started, CID %llu\n", ne_start_metadata.enclave_cid);

	/*
	 * TODO: Check for enclave hearbeat after it has started to see if it
	 * has booted.
	 */

	printf("Entering sleep for %d seconds ...\n", SLEEP_TIME);

	sleep(SLEEP_TIME);

	ne_release_vcpus(ne_vcpus);

	close(enclave_fd);

	ne_free_mem_regions(ne_mem_regions);

	exit(EXIT_SUCCESS);

release_enclave_vcpu_fds:
	ne_release_vcpus(ne_vcpus);
release_enclave_fd:
	close(enclave_fd);
	ne_free_mem_regions(ne_mem_regions);

	exit(EXIT_FAILURE);
}
