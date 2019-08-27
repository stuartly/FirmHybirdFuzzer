

#include <sys/shm.h>
#include "../afl/config.h"
#include "../afl/debug.h"
#include "../afl/alloc-inl.h"
#include "../afl/hash.h"

unsigned char *afl_area_ptr;
int pre_cksum;

int hit_new_bits(void);
int get_bitmap_size(void);
int get_current_cksum(void);


int get_current_cksum(void){
    /* Read the shm_id into a new buffer. */
    FILE *fp = fopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt", "r");

    if(fp == NULL) PFATAL("open file failed\n");

    char shm_str[129];
    fgets(shm_str, 128, fp);

    int shm_id = atoi(shm_str);

    afl_area_ptr = shmat(shm_id, NULL, 0);
    if (afl_area_ptr == (unsigned char*)(-1)) {
        PFATAL("shmat() failed\n");
        exit(1);
    }

    int cksum = hash32(afl_area_ptr, MAP_SIZE, HASH_CONST);
    shmdt(afl_area_ptr);

    return cksum;
}

int hit_new_bits(void){
    int ret = 0;

    /* Read the shm_id into a new buffer. */
    FILE *fp = fopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt", "r");

    if(fp == NULL) PFATAL("open file failed\n");

    char shm_str[129];
    fgets(shm_str, 128, fp);

    int shm_id = atoi(shm_str);

    afl_area_ptr = shmat(shm_id, NULL, 0);
    if (afl_area_ptr == (unsigned char*)(-1)) {
        PFATAL("shmat() failed\n");
        exit(1);
    }

    int cksum = hash32(afl_area_ptr, MAP_SIZE, HASH_CONST);

    if(pre_cksum != cksum)
        ret = 1;

    pre_cksum = cksum;

    shmdt(afl_area_ptr);
    return ret;
}


#define FF(_b)  (0xff << ((_b) << 3))

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

static u32 count_bytes(u8 *mem) {

    u32 *ptr = (u32 *) mem;
    u32 i = (MAP_SIZE >> 2);
    u32 ret = 0;

    while (i--) {

        u32 v = *(ptr++);

        if (!v) continue;
        if (v & FF(0)) ret++;
        if (v & FF(1)) ret++;
        if (v & FF(2)) ret++;
        if (v & FF(3)) ret++;

    }

    return ret;

}

int get_bitmap_size(void){
    int ret = 0;

    /* Read the shm_id into a new buffer. */
    FILE *fp = fopen("/home/stly/Documents/IoTFuzzing/CORTEX-M4-QEMU/interface/shm_id.txt", "r");

    if(fp == NULL) PFATAL("open file failed\n");

    char shm_str[129];
    fgets(shm_str, 128, fp);

    int shm_id = atoi(shm_str);

    afl_area_ptr = shmat(shm_id, NULL, 0);
    if (afl_area_ptr == (unsigned char*)(-1)) {
        PFATAL("shmat() failed\n");
        exit(1);
    }

    ret = count_bytes(afl_area_ptr);

    shmdt(afl_area_ptr);
    return ret;
}







