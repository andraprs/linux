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

/* Nitro Enclaves (NE) PCI device driver. */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/nitro_enclaves.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/wait.h>

#include "ne_misc_dev.h"
#include "ne_pci_dev.h"

#define DEFAULT_TIMEOUT_MSECS (120000) // 120 sec

static const struct pci_device_id ne_pci_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_AMAZON, PCI_DEVICE_ID_NE) },
	{ 0, }
};

MODULE_DEVICE_TABLE(pci, ne_pci_ids);

/**
 * ne_submit_request - Submit command request to the PCI device based on the
 * command type.
 *
 * This function gets called with the ne_pci_dev mutex held.
 *
 * @pdev: PCI device to send the command to.
 * @cmd_type: command type of the request sent to the PCI device.
 * @cmd_request: command request payload.
 * @cmd_request_size: size of the command request payload.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_submit_request(struct pci_dev *pdev,
			     enum ne_pci_dev_cmd_type cmd_type,
			     void *cmd_request, size_t cmd_request_size)
{
	struct ne_pci_dev *ne_pci_dev = NULL;

	BUG_ON(!pdev);

	ne_pci_dev = pci_get_drvdata(pdev);
	BUG_ON(!ne_pci_dev);
	BUG_ON(!ne_pci_dev->iomem_base);

	if (WARN_ON(cmd_type <= INVALID_CMD || cmd_type >= MAX_CMD)) {
		dev_err_ratelimited(&pdev->dev, "Invalid cmd type=%d\n",
				    cmd_type);

		return -EINVAL;
	}

	if (WARN_ON(!cmd_request))
		return -EINVAL;

	if (WARN_ON(cmd_request_size > NE_SEND_DATA_SIZE)) {
		dev_err_ratelimited(&pdev->dev,
				    "Invalid req size=%ld for cmd type=%d\n",
				    cmd_request_size, cmd_type);

		return -EINVAL;
	}

	memcpy_toio(ne_pci_dev->iomem_base + NE_SEND_DATA, cmd_request,
		    cmd_request_size);

	iowrite32(cmd_type, ne_pci_dev->iomem_base + NE_COMMAND);

	return 0;
}

/**
 * ne_retrieve_reply - Retrieve reply from the PCI device.
 *
 * This function gets called with the ne_pci_dev mutex held.
 *
 * @pdev: PCI device to receive the reply from.
 * @cmd_reply: command reply payload.
 * @cmd_reply_size: size of the command reply payload.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_retrieve_reply(struct pci_dev *pdev,
			     struct ne_pci_dev_cmd_reply *cmd_reply,
			     size_t cmd_reply_size)
{
	struct ne_pci_dev *ne_pci_dev = NULL;

	BUG_ON(!pdev);

	ne_pci_dev = pci_get_drvdata(pdev);
	BUG_ON(!ne_pci_dev);
	BUG_ON(!ne_pci_dev->iomem_base);

	if (WARN_ON(!cmd_reply))
		return -EINVAL;

	if (WARN_ON(cmd_reply_size > NE_RECV_DATA_SIZE)) {
		dev_err_ratelimited(&pdev->dev, "Invalid reply size=%ld\n",
				    cmd_reply_size);

		return -EINVAL;
	}

	memcpy_fromio(cmd_reply, ne_pci_dev->iomem_base + NE_RECV_DATA,
		      cmd_reply_size);

	return 0;
}

/**
 * ne_wait_for_reply - Wait for a reply of a PCI command.
 *
 * This function gets called with the ne_pci_dev mutex held.
 *
 * @pdev: PCI device for which a reply is waited.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_wait_for_reply(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;

	BUG_ON(!pdev);

	ne_pci_dev = pci_get_drvdata(pdev);
	BUG_ON(!ne_pci_dev);

	/*
	 * TODO: Update to _interruptible and handle interrupted wait event
	 * e.g. -ERESTARTSYS, incoming signals + add / update timeout.
	 */
	rc = wait_event_timeout(ne_pci_dev->cmd_reply_wait_q,
				atomic_read(&ne_pci_dev->cmd_reply_avail) != 0,
				msecs_to_jiffies(DEFAULT_TIMEOUT_MSECS));
	if (!rc) {
		pr_err("Wait event timed out when waiting for PCI cmd reply\n");

		return -ETIMEDOUT;
	}

	return 0;
}

int ne_do_request(struct pci_dev *pdev, enum ne_pci_dev_cmd_type cmd_type,
		  void *cmd_request, size_t cmd_request_size,
		  struct ne_pci_dev_cmd_reply *cmd_reply, size_t cmd_reply_size)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;

	BUG_ON(!pdev);

	ne_pci_dev = pci_get_drvdata(pdev);
	BUG_ON(!ne_pci_dev);
	BUG_ON(!ne_pci_dev->iomem_base);

	if (WARN_ON(cmd_type <= INVALID_CMD || cmd_type >= MAX_CMD)) {
		dev_err_ratelimited(&pdev->dev, "Invalid cmd type=%d\n",
				    cmd_type);

		return -EINVAL;
	}

	if (WARN_ON(!cmd_request))
		return -EINVAL;

	if (WARN_ON(cmd_request_size > NE_SEND_DATA_SIZE)) {
		dev_err_ratelimited(&pdev->dev,
				    "Invalid req size=%ld for cmd type=%d\n",
				    cmd_request_size, cmd_type);

		return -EINVAL;
	}

	if (WARN_ON(!cmd_reply))
		return -EINVAL;

	if (WARN_ON(cmd_reply_size > NE_RECV_DATA_SIZE)) {
		dev_err_ratelimited(&pdev->dev, "Invalid reply size=%ld\n",
				    cmd_reply_size);

		return -EINVAL;
	}

	/*
	 * Use this mutex so that the PCI device handles one command request at
	 * a time.
	 */
	mutex_lock(&ne_pci_dev->pci_dev_mutex);

	atomic_set(&ne_pci_dev->cmd_reply_avail, 0);

	rc = ne_submit_request(pdev, cmd_type, cmd_request, cmd_request_size);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in submit cmd request [rc=%d]\n",
				    rc);

		mutex_unlock(&ne_pci_dev->pci_dev_mutex);

		return rc;
	}

	rc = ne_wait_for_reply(pdev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in wait cmd reply [rc=%d]\n",
				    rc);

		mutex_unlock(&ne_pci_dev->pci_dev_mutex);

		return rc;
	}

	rc = ne_retrieve_reply(pdev, cmd_reply, cmd_reply_size);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in retrieve cmd reply [rc=%d]\n",
				    rc);

		mutex_unlock(&ne_pci_dev->pci_dev_mutex);

		return rc;
	}

	atomic_set(&ne_pci_dev->cmd_reply_avail, 0);

	if (cmd_reply->rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in cmd process logic [rc=%d]\n",
				    cmd_reply->rc);

		mutex_unlock(&ne_pci_dev->pci_dev_mutex);

		return cmd_reply->rc;
	}

	mutex_unlock(&ne_pci_dev->pci_dev_mutex);

	return 0;
}

/**
 * ne_reply_handler - Interrupt handler for retrieving a reply matching
 * a request sent to the PCI device for enclave lifetime management.
 *
 * @irq: received interrupt for a reply sent by the PCI device.
 * @args: PCI device private data structure.
 *
 * @returns: IRQ_HANDLED on handled interrupt, IRQ_NONE otherwise.
 */
static irqreturn_t ne_reply_handler(int irq, void *args)
{
	struct ne_pci_dev *ne_pci_dev = (struct ne_pci_dev *)args;

	atomic_set(&ne_pci_dev->cmd_reply_avail, 1);

	/* TODO: Update to _interruptible. */
	wake_up(&ne_pci_dev->cmd_reply_wait_q);

	return IRQ_HANDLED;
}

/**
 * ne_setup_msix - Setup MSI-X vectors for the PCI device.
 *
 * @pdev: PCI device to setup the MSI-X for.
 * @ne_pci_dev: PCI device private data structure.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_setup_msix(struct pci_dev *pdev, struct ne_pci_dev *ne_pci_dev)
{
	int nr_vecs = 0;
	int rc = -EINVAL;

	BUG_ON(!ne_pci_dev);

	nr_vecs = pci_msix_vec_count(pdev);
	if (nr_vecs < 0) {
		rc = nr_vecs;

		dev_err_ratelimited(&pdev->dev,
				    "Failure in getting vec count [rc=%d]\n",
				    rc);

		return rc;
	}

	rc = pci_alloc_irq_vectors(pdev, nr_vecs, nr_vecs, PCI_IRQ_MSIX);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in alloc MSI-X vecs [rc=%d]\n",
				    rc);

		goto err_alloc_irq_vecs;
	}

	/*
	 * This IRQ gets triggered every time the PCI device responds to a
	 * command request. The reply is then retrieved, reading from the MMIO
	 * space of the PCI device.
	 */
	rc = request_irq(pci_irq_vector(pdev, NE_VEC_REPLY),
			 ne_reply_handler, 0, "enclave_cmd", ne_pci_dev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in allocating irq reply [rc=%d]\n",
				    rc);

		goto err_req_irq_reply;
	}

	return 0;

err_req_irq_reply:
	pci_free_irq_vectors(pdev);
err_alloc_irq_vecs:
	return rc;
}

/**
 * ne_pci_dev_enable - Select PCI device version and enable it.
 *
 * @pdev: PCI device to select version for and then enable.
 * @ne_pci_dev: PCI device private data structure.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_pci_dev_enable(struct pci_dev *pdev,
			     struct ne_pci_dev *ne_pci_dev)
{
	u8 dev_enable_reply = 0;
	u16 dev_version_reply = 0;

	BUG_ON(!pdev);
	BUG_ON(!ne_pci_dev);
	BUG_ON(!ne_pci_dev->iomem_base);

	iowrite16(NE_VERSION_MAX, ne_pci_dev->iomem_base + NE_VERSION);

	dev_version_reply = ioread16(ne_pci_dev->iomem_base + NE_VERSION);
	if (dev_version_reply != NE_VERSION_MAX) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci dev version cmd\n");

		return -EIO;
	}

	iowrite8(NE_ENABLE_ON, ne_pci_dev->iomem_base + NE_ENABLE);

	dev_enable_reply = ioread8(ne_pci_dev->iomem_base + NE_ENABLE);
	if (dev_enable_reply != NE_ENABLE_ON) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci dev enable cmd\n");

		return -EIO;
	}

	return 0;
}

/**
 * ne_pci_dev_disable - Disable PCI device.
 *
 * @pdev: PCI device to disable.
 * @ne_pci_dev: PCI device private data structure.
 *
 * @returns: 0 on success, negative return value on failure.
 */
static int ne_pci_dev_disable(struct pci_dev *pdev,
			      struct ne_pci_dev *ne_pci_dev)
{
	u8 dev_disable_reply = 0;

	BUG_ON(!pdev);
	BUG_ON(!ne_pci_dev);
	BUG_ON(!ne_pci_dev->iomem_base);

	iowrite8(NE_ENABLE_OFF, ne_pci_dev->iomem_base + NE_ENABLE);

	/*
	 * TODO: Check for NE_ENABLE_OFF in a loop, to handle cases when the
	 * device state is not immediately set to disabled and going through a
	 * transitory state of disabling.
	 */
	dev_disable_reply = ioread8(ne_pci_dev->iomem_base + NE_ENABLE);
	if (dev_disable_reply != NE_ENABLE_OFF) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci dev disable cmd\n");

		return -EIO;
	}

	return 0;
}

static int ne_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct ne_pci_dev *ne_pci_dev = NULL;
	int rc = -EINVAL;

	ne_pci_dev = kzalloc(sizeof(*ne_pci_dev), GFP_KERNEL);
	if (!ne_pci_dev)
		return -ENOMEM;

	rc = pci_enable_device(pdev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci dev enable [rc=%d]\n", rc);

		goto err_pci_enable_dev;
	}

	rc = pci_request_regions_exclusive(pdev, "ne_pci_dev");
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci request regions [rc=%d]\n",
				    rc);

		goto err_req_regions;
	}

	ne_pci_dev->iomem_base = pci_iomap(pdev, PCI_BAR_NE, 0);
	if (!ne_pci_dev->iomem_base) {
		rc = -ENOMEM;

		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci bar mapping [rc=%d]\n", rc);

		goto err_iomap;
	}

	rc = ne_setup_msix(pdev, ne_pci_dev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in pci dev msix setup [rc=%d]\n",
				    rc);

		goto err_setup_msix;
	}

	rc = ne_pci_dev_disable(pdev, ne_pci_dev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in ne_pci_dev disable [rc=%d]\n",
				    rc);

		goto err_ne_pci_dev_disable;
	}

	rc = ne_pci_dev_enable(pdev, ne_pci_dev);
	if (rc < 0) {
		dev_err_ratelimited(&pdev->dev,
				    "Failure in ne_pci_dev enable [rc=%d]\n",
				    rc);

		goto err_ne_pci_dev_enable;
	}

	atomic_set(&ne_pci_dev->cmd_reply_avail, 0);
	init_waitqueue_head(&ne_pci_dev->cmd_reply_wait_q);
	INIT_LIST_HEAD(&ne_pci_dev->enclaves_list);
	mutex_init(&ne_pci_dev->enclaves_list_mutex);
	mutex_init(&ne_pci_dev->pci_dev_mutex);

	pci_set_drvdata(pdev, ne_pci_dev);

	return 0;

err_ne_pci_dev_enable:
err_ne_pci_dev_disable:
	free_irq(pci_irq_vector(pdev, NE_VEC_REPLY), ne_pci_dev);
	pci_free_irq_vectors(pdev);
err_setup_msix:
	pci_iounmap(pdev, ne_pci_dev->iomem_base);
err_iomap:
	pci_release_regions(pdev);
err_req_regions:
	pci_disable_device(pdev);
err_pci_enable_dev:
	kzfree(ne_pci_dev);
	return rc;
}

static void ne_remove(struct pci_dev *pdev)
{
	struct ne_pci_dev *ne_pci_dev = pci_get_drvdata(pdev);

	if (!ne_pci_dev || !ne_pci_dev->iomem_base)
		return;

	ne_pci_dev_disable(pdev, ne_pci_dev);

	pci_set_drvdata(pdev, NULL);

	free_irq(pci_irq_vector(pdev, NE_VEC_REPLY), ne_pci_dev);
	pci_free_irq_vectors(pdev);

	pci_iounmap(pdev, ne_pci_dev->iomem_base);

	kzfree(ne_pci_dev);

	pci_release_regions(pdev);

	pci_disable_device(pdev);
}

/*
 * TODO: Add suspend / resume functions for power management w/ CONFIG_PM, if
 * needed.
 */
struct pci_driver ne_pci_driver = {
	.name		= "ne_pci_dev",
	.id_table	= ne_pci_ids,
	.probe		= ne_probe,
	.remove		= ne_remove,
};
