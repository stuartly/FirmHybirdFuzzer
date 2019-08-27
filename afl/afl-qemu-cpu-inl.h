/*
   american fuzzy lop - high-performance binary-only instrumentation
   -----------------------------------------------------------------

   Written by Andrew Griffiths <agriffiths@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   Idea & design very much by Andrew Griffiths.

   Copyright 2015, 2016, 2017 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is a shim patched into the separately-distributed source
   code of QEMU 2.10.0. It leverages the built-in QEMU tracing functionality
   to implement AFL-style instrumentation and to take care of the remaining
   parts of the AFL fork server logic.

   The resulting QEMU binary is essentially a standalone instrumentation
   tool; for an example of how to leverage it for other purposes, you can
   have a look at afl-showmap.c.

 */
#include <stdio.h>
#include <sys/shm.h>
#include "config.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

int shm_id;
int has_setup_shm = 0;
unsigned char *afl_area_ptr;

typedef unsigned int   abi_ulong;

abi_ulong  afl_entry_point; /* ELF entry point (_start) */
abi_ulong  afl_start_code;  /* .text start pointer      */
abi_ulong  afl_end_code=(abi_ulong)-1;    /* .text end pointer        */

/* This snippet kicks in when the instruction pointer is positioned at
   _start and does the usual forkserver stuff, not very different from
   regular instrumentation injected via afl-as.h. */

#define AFL_QEMU_CPU_SNIPPET2 do { \
    qemu_log("Tracking exected BB id: 0x%04x\n", itb->pc); \
    afl_setup(); \
    afl_maybe_log(itb->pc); \
  } while (0)



/* Function declarations. */
static inline void afl_setup(void);
static inline void afl_maybe_log(abi_ulong);


/* Set up SHM region and initialize other stuff. */
static void afl_setup(void) {
  if(has_setup_shm == 0){
    FILE *fpr = fopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt", "r");
    if(fpr != NULL){
      has_setup_shm = 1;
      fscanf(fpr,"%d",&shm_id);
      fclose(fpr);
      printf("shm_id: %d\n",shm_id);
    }
  }

  if (has_setup_shm == 0){

    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | 0600);

    if (shm_id < 0) {
        PFATAL("shmget() failed\n");
        exit(1);
    }

    has_setup_shm = 1;

    shmctl(shm_id, IPC_STAT, NULL);

    /* write shm_id into file */
    FILE *fp = fopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt", "w+");
    if(fp == NULL) PFATAL("faile to open file\n");
    u8* shm_str = alloc_printf("%d", shm_id);
    fwrite(shm_str, strlen(shm_str),1,fp);
    fclose(fp);

  }

  afl_area_ptr = shmat(shm_id, NULL, 0);
  if (afl_area_ptr == (unsigned char*)(-1)) {
      PFATAL("shmat() failed\n");
      exit(1);
  }


//  qemu_log("afl_are_ptr addr :%d\n", &afl_area_ptr);

}


/* The equivalent of the tuple logging routine from afl-as.h. */

static void afl_maybe_log(abi_ulong cur_loc) {

  static __thread abi_ulong prev_loc;

  if (cur_loc > afl_end_code || cur_loc < afl_start_code || !afl_area_ptr){

    return;
  }

  if (!afl_area_ptr) PFATAL("afl_are_ptr is NULL");

//  qemu_log("afl_are_ptr :%d\n", &afl_area_ptr);
  /* Looks like QEMU always maps to fixed locations, so ASAN is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc  = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  afl_area_ptr[cur_loc ^ prev_loc] = 1;
  prev_loc = cur_loc >> 1;

  shmdt(afl_area_ptr);
//  qemu_log("#############update\n");

}






