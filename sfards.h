#ifndef  __SFARDS_H__
#define  __SFARDS_H__
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "miner.h"

#define PORT_BUF_SIZE		(1024)
#define PORT_MAX_COUNT		(6)
enum PORT_TYPE
{
    PORT_TYPE_SCRYPT = 0,
    PORT_TYPE_SHA256 = 1,
};

struct sfards_rpt
{
    int chipid;
    uint32_t data;
};

struct sfards_port
{
//    struct sfards_port *next;
    char path[64];
    int fd;
    int update;  /* 1 start 2 resart  -1 stop */
    int avail;
    int err_n[16];
    int nonce_n[16];
    uint32_t init_nonce[16];
    uint32_t prev_nonce[16];
    int chip_n;
    int chip_map;
    uint8_t recv_buf[PORT_BUF_SIZE];
    int recv_offset;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    uint32_t nonce[128];
    int chipid[128];
    int ridx;
    int widx;
    uint32_t record[16];
    int curpos;
};

struct sfards_dev
{
    enum PORT_TYPE type;
    int freq;
    struct sfards_port port[PORT_MAX_COUNT];
    int epollfd;
    int pipefd[2];
    pthread_t thr;
};

struct sfards_dev * sfards_new(enum PORT_TYPE type,int freq);
int sfards_port(struct sfards_dev *dev,int index,const char *path);
int sfards_scanhash_scrypt(struct sfards_dev *dev,int thr_id, uint32_t *pdata,
                           unsigned char *scratchbuf, const uint32_t *ptarget,
                           uint32_t max_nonce, unsigned long *hashes_done, 
                           int N,uint32_t retry);
int sfards_scanhash_sha256d(struct sfards_dev *dev,int thr_id, uint32_t *pdata, 
			    const uint32_t *ptarget,
                            uint32_t max_nonce, unsigned long *hashes_done,uint32_t retry);

int sfards_send_sha256d_task(struct sfards_dev *dev,int thr_id,
                             struct stratum_work *stratum_work,uint32_t ntime);
int sfards_wait_sha256d_nonce(struct sfards_dev *dev,int thr_id,
                              struct sfards_rpt *nonce_rpt,int size,struct timespec *ts);

void sfards_destroy(struct sfards_dev *dev);

#endif //__SFARDS_H__


