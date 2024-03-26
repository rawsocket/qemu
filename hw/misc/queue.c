/*
 * Sparrow: Interprocess Shared Memory Queues
 *
 * Copyright (c) 2024, Meta Platforms, Inc.
 *
 * Developed by Adel Abouchaev <adelab@meta.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <memory.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>

#include "hw/misc/queue.h"

struct QueueHeader {
	uint32_t prod;
	uint32_t cons;
	sem_t prod_sem;
	sem_t cons_sem;
};

static sem_t *create_master_sem(const char *id) {
	return sem_open(id, O_CREAT | O_EXCL, 0600, 0);
}

static sem_t *open_master_sem(const char *id) {
	return sem_open(id, 0);
}

static int close_master_sem(sem_t *sem) {
	return sem_close(sem);
}

static int destroy_master_sem(const char *id, sem_t *sem) {
	int rc = close_master_sem(sem);

	sem_unlink(id);
	return rc;
}

static void *create_queue_memory_map(const char *id, const size_t size_bytes) {
	int fd = shm_open(id, O_RDWR | O_CREAT, 0600);

	if (fd == -1)
		return NULL;

	if (ftruncate(fd, size_bytes) == -1) {
		close(fd);
		return NULL;
	}

	void *mem = mmap(0, size_bytes, PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	if (close(fd) == -1)
		return NULL;

	return mem;
}

static void *open_queue_memory_map(const char *id, const size_t qsize_bytes) {
	struct stat sb;

	int fd = shm_open(id, O_RDWR, 0600);

	if (fd == -1)
		return NULL;

	if (fstat(fd, &sb) == -1) {
		close(fd);
		return NULL;
	}

	if (sb.st_size != qsize_bytes) {
		close(fd);
		return NULL;
	}

	void *mem = mmap(0, qsize_bytes, PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		close(fd);
		return NULL;
	}

	if (close(fd) == -1)
		return NULL;

	return mem;
}

static int unmap_queue_memory(void *mem, const size_t qsize_bytes) {
	if (!mem)
		return 0;

	if (munmap(mem, qsize_bytes) == -1)
		return -EINVAL;

	return 0;
}

static size_t get_queue_memory_size(struct QueueAttrs * const attrs) {
	return sizeof(struct QueueHeader) + attrs->desc_size * attrs->num_descs;
}

int create_queue(struct QueueAttrs * const attrs) {
	attrs->qid[QUEUE_ID_MAX_LEN - 1] = 0;
	sem_unlink(attrs->qid);
	attrs->master_sem = create_master_sem(attrs->qid);

	if (!attrs->master_sem)
		return -EINVAL;

	attrs->mem = create_queue_memory_map(attrs->qid, get_queue_memory_size(attrs));
	if (!attrs->mem) {
		destroy_master_sem(attrs->qid, attrs->master_sem);
		attrs->master_sem = NULL;
		return -EINVAL;
	}

	struct QueueHeader * const hdr = (struct QueueHeader *)attrs->mem;
	hdr->prod = 0;
	hdr->cons = 0;
	attrs->last_cons = 0;
	attrs->last_prod = 0;

	sem_init(&hdr->prod_sem, 1, 0);
	sem_init(&hdr->cons_sem, 1, 0);

	sem_post(attrs->master_sem);
	close_master_sem(attrs->master_sem);

	return 0;
}

int connect_queue(struct QueueAttrs * const attrs, const uint32_t wait_ms) {
	attrs->qid[QUEUE_ID_MAX_LEN - 1] = 0;
	attrs->master_sem = open_master_sem(attrs->qid);

	if (!attrs->master_sem)
		return -EAGAIN;

	struct timespec ts = {0, 0};
	clock_gettime(CLOCK_MONOTONIC, &ts);
	uint64_t wait_ns = (uint64_t)wait_ms * 1000000ULL + ts.tv_nsec;
	ts.tv_sec += wait_ns / 1000000000UL;
	ts.tv_nsec = wait_ns % 1000000000UL;

	int rc = 0;
	do {
		rc = sem_timedwait(attrs->master_sem, &ts);
		if (rc == -1 && errno == EINTR)
			continue;
	} while (0);

	if (rc) {
		close_master_sem(attrs->master_sem);
		return -EAGAIN;
	}

	attrs->mem = open_queue_memory_map(attrs->qid, get_queue_memory_size(attrs));
	if (!attrs->mem) {
		destroy_master_sem(attrs->qid, attrs->master_sem);
		return -EINVAL;
	}

	attrs->last_cons = 0;
	attrs->last_prod = 0;

	/* Handshake is done, master semaphore is not needed anymore */
	destroy_master_sem(attrs->qid, attrs->master_sem);
	attrs->master_sem = NULL;

	return 0;
}

int destroy_queue(struct QueueAttrs * const attrs) {
	int rc = 0;

	rc = unmap_queue_memory(attrs->mem, get_queue_memory_size(attrs));
	rc |= shm_unlink(attrs->qid);

	if (attrs->master_sem) {
		rc |= destroy_master_sem(attrs->qid, attrs->master_sem);
		attrs->master_sem = NULL;
	}

	return rc;
}

static void *get_queue_slot_addr(struct QueueAttrs * const attrs, const uint32_t idx) {
	SPARROW_CHECK(idx < attrs->num_descs, "idx:%d >= num_descs:%ld", idx, attrs->num_descs);

	return (uint8_t *)attrs->mem + sizeof(struct QueueHeader) + idx * attrs->desc_size;
}

void *get_current_prod_desc(struct QueueAttrs * const attrs) {
	struct QueueHeader * const hdr = (struct QueueHeader *)attrs->mem;
	const uint64_t CONS_SEM_WAIT_NS = 10;

	SPARROW_CHECK(attrs->is_a_producer, "Only producer endpoint can enqueue descriptors");

	uint32_t next_prod = (hdr->prod + 1) % attrs->num_descs;
	if (next_prod == attrs->last_cons) {
		struct timespec ts = {0, 0};
		uint64_t wait_ns = CONS_SEM_WAIT_NS;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		wait_ns += ts.tv_nsec;
		ts.tv_sec += wait_ns / 1000000000UL;
		ts.tv_nsec = wait_ns % 1000000000UL;
		sem_timedwait(&hdr->cons_sem, &ts);
		attrs->last_cons = hdr->cons;
		if (next_prod == attrs->last_cons) {
			return NULL;
		}
	}

	return get_queue_slot_addr(attrs, hdr->prod);
}

int advance_prod_and_post(struct QueueAttrs * const attrs) {
	struct QueueHeader * const hdr = (struct QueueHeader *)attrs->mem;
	uint32_t next_prod = (hdr->prod + 1) % attrs->num_descs;

	if (next_prod == hdr->cons) {
		return -EINVAL;
	}

	hdr->prod = next_prod;
	sem_post(&hdr->prod_sem);
	return 0;
}

int enqueue(struct QueueAttrs * const attrs, void * const desc) {
	void *prod_desc = get_current_prod_desc(attrs);
	if (!prod_desc) {
		return -ENOMEM;
	}

	memcpy(prod_desc, desc, attrs->desc_size);
	advance_prod_and_post(attrs);
	return 0;
}

void *get_current_cons_desc(struct QueueAttrs * const attrs) {
	struct QueueHeader * const hdr = (struct QueueHeader *)attrs->mem;
	const uint64_t PROD_SEM_WAIT_NS = 10;

	SPARROW_CHECK(!attrs->is_a_producer, "Only consumer endpoint can dequeue descriptors");

	if (hdr->cons == attrs->last_prod) {
		struct timespec ts = {0, 0};
		uint64_t wait_ns = PROD_SEM_WAIT_NS;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		wait_ns += ts.tv_nsec;
		ts.tv_sec += wait_ns / 1000000000UL;
		ts.tv_nsec = wait_ns % 1000000000UL;
		sem_timedwait(&hdr->prod_sem, &ts);
		attrs->last_prod = hdr->prod;
		if (hdr->cons == attrs->last_prod) {
			return NULL;
		}
	}

	return get_queue_slot_addr(attrs, hdr->cons);
}

int advance_cons_and_post(struct QueueAttrs * const attrs) {
	struct QueueHeader * const hdr = (struct QueueHeader *)attrs->mem;

	if (hdr->cons == hdr->prod) {
		return -EINVAL;
	}

	hdr->cons = (hdr->cons + 1) % attrs->num_descs;
	sem_post(&hdr->cons_sem);
	return 0;
}

int dequeue(struct QueueAttrs * const attrs, void * const desc) {
	void *cons_desc = get_current_cons_desc(attrs);
	if (!cons_desc) {
		return -EAGAIN;
	}

	memcpy(desc, cons_desc, attrs->desc_size);
	advance_cons_and_post(attrs);
	return 0;
}
