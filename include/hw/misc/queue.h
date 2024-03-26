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
#ifndef _SPARROW_QUEUE_C_H_
#define _SPARROW_QUEUE_C_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <execinfo.h>
#include <semaphore.h>
#include <memory.h>
#include <libgen.h>

#define QUEUE_ID_MAX_LEN 128

struct QueueAttrs {
	char qid[QUEUE_ID_MAX_LEN];
	size_t desc_size;
	size_t num_descs;
    sem_t *master_sem;
    void *mem;
	uint32_t last_cons;
	uint32_t last_prod;
	bool is_a_producer;
};

#define sparrow_pr_fmt(fmt) fmt

#define SPARROW_CHECK_BT_MAX_FRAMES 16
static inline void sparrow_check_print_backtrace(uint8_t frames_nr) {
  void *trace[SPARROW_CHECK_BT_MAX_FRAMES];
  char **frames;
  int i, frames_count;

  if (frames_nr > SPARROW_CHECK_BT_MAX_FRAMES) {
    frames_nr = SPARROW_CHECK_BT_MAX_FRAMES;
  }
  frames_count = backtrace(trace, frames_nr);
  frames = backtrace_symbols(trace, frames_count);
  if (frames) {
    fprintf(stderr, "[TRACE] Backtrace %d frames\n", frames_count);
    for (i = 0; i < frames_count; ++i) {
      fprintf(stderr, "[TRACE] %s\n", frames[i]);
    }
    fprintf(stderr, "\n");
    free(frames);
  }
}

#ifndef SPARROW_QUOT
#define SPARROW_QUOT(s) #s
#endif

#ifndef SPARROW_QUOTE
#define SPARROW_QUOTE(s) SPARROW_QUOT(s)
#endif

#define SPARROW_CHECK(cond, format, ...) do { \
  if (!(cond)) { \
    fprintf(stderr, "[CHECK] %s(%s:%d): " sparrow_pr_fmt(format), \
      __func__, \
      basename((char *)__FILE__), \
      __LINE__, \
      ##__VA_ARGS__); \
      sparrow_check_print_backtrace(SPARROW_CHECK_BT_MAX_FRAMES); \
    abort(); \
  } \
} while (0);

#define SPARROW_FAIL(format, ...) SPARROW_CHECK(false, format, ##__VA_ARGS__)

#define SPARROW_CHECK_TRUE(cond) SPARROW_CHECK((cond), "%s", "condition: [" SPARROW_QUOTE(cond) "] is not true")

/*
 *  Creates a queue and initializes the internal structure. Blocks exclusively on
 *  the master queue semaphore to prevent connect_queue from advancing.
 *
 *	This function is concurrency-aware between itself and connect_queue function.
 *  In other cases, this function is not thread safe.
 */
int create_queue(struct QueueAttrs * const attrs);

/*
 *  Connects to a queue created with create_queue function. Waits on the master
 *  queue semaphore to prevent connect_queue from advancing until queue internal
 *  structure is initialized.
 *
 *	This function is concurrency-aware between itself and creqte_queue function.
 *  In other cases, this function is not thread safe.
 */
int connect_queue(struct QueueAttrs * const attrs, const uint32_t wait_ms);

/*
 * Destroys a queue and its shared memory objects.
 */
int destroy_queue(struct QueueAttrs * const attrs);

/*
 * Producer-side API: Get the queue descriptor currently pointed to by the producer.
 *
 * This function is not thread-safe.
 */
void *get_current_prod_desc(struct QueueAttrs * const attrs);

/*
 * Producer-side API: Advance the producer pointer and post the queue semaphore.
 *
 * This function must be called after get_current_prod_desc for proper shared memory
 * operations ordering and consistency.
 *
 * This function is not thread-safe.
 */
int advance_prod_and_post(struct QueueAttrs * const attrs);

/*
 * Producer-side API: Enqueue a descriptor into the queue.
 *
 * This function is not thread-safe.
 */
int enqueue(struct QueueAttrs * const attrs, void * const desc);

/*
 * Consumer-side API: Get the queue descriptor currently pointed to by the consumer.
 *
 * This function is not thread-safe.
 */

void *get_current_cons_desc(struct QueueAttrs * const attrs);
/*
 * Consumer-side API: Advance the consumer pointer and post the queue semaphore.
 *
 * This function is not thread-safe.
 */

int advance_cons_and_post(struct QueueAttrs * const attrs);
/*
 * Consumer-side API: Dequeue a descriptor from the queue.
 *
 * This function must be called after get_current_cons_desc for proper shared memory
 * operations ordering and consistency.
 *
 * This function is not thread-safe.
 */
int dequeue(struct QueueAttrs * const attrs, void * const desc);

#endif  // _SPARROW_QUEUE_C_H_
