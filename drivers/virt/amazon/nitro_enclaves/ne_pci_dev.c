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

	return 0;

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
