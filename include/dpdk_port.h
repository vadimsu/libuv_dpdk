
#ifndef __DPDK_PORT_H__
#define __DPDK_PORT_H__

typedef struct
{
    struct msghdr* msg;
    int current_iovec_idx;
    int current_iovec_offset;
}dpdk_to_iovec_t;

int copy_from_iovec(void *arg,char *buf,int size);

void copy_to_iovec(void *arg,char *buf,int size);

#endif
