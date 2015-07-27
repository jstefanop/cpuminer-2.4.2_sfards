#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/uio.h>
#include "sfards.h"
#include "miner.h"

#define SFARDS_CMD_INTERVAL		(4000)

//#define DEBUG_UART
//#define DEBUG_RECV

struct sfards_reg
{
    uint8_t chipid;
    uint8_t unit;
    uint8_t addr;
    uint32_t value;
};

static int sfards_port_setup(struct sfards_port *port,int baud)
{
    const int baudrate[] = {2400,4800,9600,19200,38400,57600,115200};
    const speed_t baudspeed[] = {B2400,B4800,B9600,B19200,B38400,B57600,B115200};
    struct termios options;
    int index;

    for (index = 0;index < sizeof(baudrate) / sizeof(int);index++)
    {
        if (baudrate[index] == baud)
        {
            break;
        }
    }

    if (index >= sizeof(baudrate)/sizeof(int))
    {
        return -1;
    }
    if (tcgetattr(port->fd,&options) < 0)
    {
        return -1;
    }

    cfsetspeed(&options,baudspeed[index]);

    options.c_cflag &= ~(CSIZE | PARENB);
    options.c_cflag |= CS8;
    options.c_cflag |= CREAD;
    options.c_cflag |= CLOCAL;

    options.c_iflag &= ~(IGNBRK | BRKINT | PARMRK |
                         ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    options.c_oflag &= ~OPOST;
    options.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);

    options.c_cc[VTIME] = (cc_t)10;
    options.c_cc[VMIN] = 0;

    if (tcsetattr(port->fd,TCSANOW, &options) < 0)
    {
        return -1;
    }

    return 0;
}

static int sfards_port_write(struct sfards_port *port,uint8_t chipid,uint8_t unit,
                             uint8_t addr,uint32_t *data,int count)
{
    struct iovec iov[2];
    uint8_t hdr[4] = {0x55,};
    uint8_t *p = (uint8_t *)data;
    int total = count * 4 + 4;
    int offset = 0;
    int len;

    hdr[1] = chipid;
    hdr[2] = unit;
    hdr[3] = addr;
#ifdef DEBUG_UART
    printf("%2.2x%2.2x%2.2x%2.2x ",hdr[0],hdr[1],hdr[2],hdr[3]);
    for (len = 0;len < count * 4;len++)
    {
        printf("%2.2x",p[len]);
        if (len % 32 == 31) printf("\n");
    }
    printf("\n");
#endif
    while(offset < total)
    {
        if (offset < 4)
        {    
            iov[0].iov_base = hdr + offset;
            iov[0].iov_len = 4 - offset;
            iov[1].iov_base = p;
            iov[1].iov_len = count * 4;
            len = writev(port->fd,iov,2);
        }
        else
        {
            len = write(port->fd,p + offset - 4,total - offset);
        }
        if (len <= 0)
        {
            return -1;
        }
        offset += len;
    }    
    fsync(port->fd);
    usleep(SFARDS_CMD_INTERVAL);

    return count;
}

static int sfards_port_read(struct sfards_port *port,uint8_t chipid,uint8_t unit,
                            uint8_t addr,struct sfards_rpt *values,int count,int timeout)
{
#define RDBUF_SIZE	(256)
    fd_set rfds;
    struct timeval tv;
    uint8_t buf[RDBUF_SIZE];
    int offset = 0;
    int len,start,n;
    uint32_t zero = 0x00;
    uint8_t cpm = unit == 0xf0 ? 0x00 : 0x04;
 
    if (sfards_port_write(port,chipid,unit,addr | 0x80,&zero,1) <= 0)
    {
        return -1;
    }
    
    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    n = 0;

    for (;;)
    {
        FD_ZERO(&rfds);
        FD_SET(port->fd, &rfds);
        if (select(port->fd + 1, &rfds, NULL, NULL, &tv) <= 0)
        {
            break;
        }
        
        len = read(port->fd,buf + offset,RDBUF_SIZE - offset);
        if (len <= 0)
        {
            return -1;
        }
        offset += len;
        start = 0;
        while(offset - start >= 8)
        {
            if (buf[start] == 0x55)
            {
                if ((chipid == 0xff || buf[start + 1] == chipid)
                    && buf[start + 2] == cpm 
                    && buf[start + 3] == addr)
                {
                    values[n].chipid = buf[start + 1];
                    memcpy(&values[n].data,buf + start + 4,4);
                    if (++n == count)
                    {
                        return count;
                    }
                }
                start += 7;
            }
            start++;
        }
        memmove(buf,buf + start,offset - start);
        offset -= start;
    }
    return n;
}

static uint32_t sfards_port_calc_freq(int freq)
{
    uint32_t pll_od,pll_f;
    int fact = freq / 25;;
    if (fact < 1)
    {
        fact = 1;
    }
    if (fact > 40)
    {
        fact = 40;
    }

    pll_od = fact < 8 ? 8 : 1;
    pll_f = pll_od * fact;

    return (0x0000600d | (pll_f << 17) | (pll_od << 24));
}

static int sfards_port_configure_scrypt(struct sfards_port *port,int freq)
{
    int i,k;
    uint32_t nonce_step = 0x40000000U / ((port->chip_n + 3) >> 2); 
    uint32_t cmd_en_pll   = 0x7fffffff;
    uint32_t cmd_cmp_mode = 0x8000000a;
    uint32_t cmd_init_nonce = 0x00000000;
    uint32_t cmd_set_freq = sfards_port_calc_freq(freq);

    if (sfards_port_write(port,0xff,0xf0,0x00,&cmd_set_freq,1) != 1)
    {
        return -1;
    }
    
    if (sfards_port_write(port,0xff,0xf0,0x02,&cmd_en_pll,1) != 1)
    {
        return -1;
    }
    
    if (sfards_port_write(port,0xff,0xbf,0x30,&cmd_cmp_mode,1) != 1)
    {
        return -1;
    }

    for (i = 0,k = 1;i < 16;i++,k <<= 1)
    {
        if (k & port->chip_map) 
        {
            if (sfards_port_write(port,i,0xbf,0x00,&cmd_init_nonce,1) != 1)
            {
                return -1;
            }
            port->init_nonce[i] = cmd_init_nonce;
            cmd_init_nonce += nonce_step;
        }
    }
    return 0;
}

static int sfards_port_enable_btc_clk(struct sfards_port *port)
{
    int i,k;
    uint32_t value = 0x00000001;
    for (i = 0;i < 8;i++)
    {
        for (k = 2;k <= 6;k++)
        {
            if (sfards_port_write(port,0xff,0xf0,k,&value,1) != 1)
            {
                return -1;
            }
            if (value == 0x00000007 && k == 4) 
            {
                value = 0x07ffffff;
            }
        }
        value = ((value << 1) | 1);
    }
    return 0;
}

static int sfards_port_configure_sha256(struct sfards_port *port,int freq)
{
    int i;
    uint32_t cmd_disable = 0x00000000;    
    uint32_t cmd_enable = 0x00000003;    
    uint32_t cmd_clean[] = {0,0,0,0,0};
    uint32_t cmd_fill = 0xffffffff;
    uint32_t cmd_mode = 0x177e0c18;
    uint32_t cmd_uart = 0xb4811b1f;

    struct sfards_reg vendor_init[10] = 
    {
        {0xff,0xf0,0x54,0x8a5a0002},
        {0xff,0xf0,0x52,0x12a79568},
        {0xff,0xf0,0x55,0x2a7f3382},
        {0xff,0xf0,0x58,0x20141119},
        {0xff,0xf0,0x5a,0x20000000},
        {0xff,0xf0,0x5c,0x00001002},
        {0xff,0xf0,0x60,0x20140619},
        {0xff,0xf0,0x64,0x40961024},
        {0xff,0xf0,0x66,0x1203aaff},
        {0xff,0xf0,0x6a,0x30002201}
    };    

    uint32_t cmd_set_freq = sfards_port_calc_freq(freq);

    if (sfards_port_write(port,0xff,0xf0,0x00,&cmd_set_freq,1) != 1)
    {
        return -1;
    }
    
    if (sfards_port_write(port,0xff,0xf0,0x02,cmd_clean,5) != 5) 
    {
        return -1;
    }

    if (sfards_port_write(port,0xff,0xf0,0x1e,&cmd_disable,1) != 1)
    {
        return -1;
    }

    if (sfards_port_write(port,0xff,0xf0,0x1e,&cmd_enable,1) != 1)
    {
        return -1;
    }
    
    for (i = 0;i < 10;i++)
    {
        if (sfards_port_write(port,vendor_init[i].chipid,
                                   vendor_init[i].unit,
                                   vendor_init[i].addr,
                                   &vendor_init[i].value,1) != 1)
        {
            return -1;
        }
    }

    if (sfards_port_write(port,0xff,0xef,0x1f,&cmd_mode,1) != 1)
    {
        return -1;
    }
    
    if (sfards_port_write(port,0xff,0xef,0x01,&cmd_fill,1) != 1)
    {
        return -1;
    }

    if (sfards_port_write(port,0xff,0xef,0x00,cmd_clean,1) != 1)
    {
        return -1;
    }
    
    if (sfards_port_write(port,0xff,0xf0,0x20,&cmd_uart,1) != 1)
    {
        return -1;
    }
    
    if (sfards_port_enable_btc_clk(port) < 0)
    {
        return -1;
    }

    return 0;
}

static int sfards_port_configure(struct sfards_port *port,enum PORT_TYPE type,int freq)
{
    int n;
    uint32_t cmd_scrypt_auto_cfg = 0xc0000801; 
    uint32_t cmd_sha256_auto_cfg = 0xc0000001; 
    struct sfards_rpt devid[16];
    int chips = sfards_port_read(port,0xff,0xf0,0x75,devid,8,1);
   
    if (chips <= 0)
    {
        return -1;
    }

    if (type == PORT_TYPE_SCRYPT)
    {
        for (n = 0;n < chips;n++)
        {
            if (devid[n].data != 0x47433281)
            {
                return -1;
            }
        }
        if (sfards_port_write(port,0xfe,0xf0,0x7f,&cmd_scrypt_auto_cfg,1) != 1)
        {
            return -1;
        }
    }
    else // if (type == PORT_TYPE_SHA256)
    {
        for (n = 0;n < chips;n++)
        {
            if (devid[n].data != 0x4743328B)
            {
                return -1;
            }
        }
        if (sfards_port_write(port,0xfe,0xf0,0x7f,&cmd_sha256_auto_cfg,1) != 1)
        {
            return -1;
        }
    }
    sleep(2);

    port->chip_map = 0;
    port->chip_n = 0;

    chips = sfards_port_read(port,0xff,0xf0,0x75,devid,16,5);

    if (type == PORT_TYPE_SCRYPT)
    {
        for (n = 0;n < chips;n++)
        {
            if (devid[n].data == 0x47433281 
                && devid[n].chipid < 16 
                && ((1 << devid[n].chipid) & port->chip_map) == 0)
            {
                port->chip_map |= 1 << devid[n].chipid;
                port->chip_n++;
            }
        }
        
        printf("Found Scrypt Port %d Chips Map %2.2x\n",port->chip_n,port->chip_map);

        return sfards_port_configure_scrypt(port,freq);
    }
    else // if (type == PORT_TYPE_SHA256)
    {
        for (n = 0;n < chips;n++)
        {
            if (devid[n].data == 0x4743328B 
                && devid[n].chipid < 16 
                && ((1 << devid[n].chipid) & port->chip_map) == 0)
            {
                port->chip_map |= 1 << devid[n].chipid;
                port->chip_n++;
            }
        }
        
        printf("Found Sha256 Port %d Chips Id Map %2.2x\n",port->chip_n,port->chip_map);

        return sfards_port_configure_sha256(port,freq);
    }
    return 0;
}

static void sfards_port_close(struct sfards_port *port)
{
    close(port->fd);
    port->fd = -1;
    port->avail = 0;
}
 
static int sfards_port_open(struct sfards_port *port,enum PORT_TYPE type,int freq)
{
    port->fd = open(port->path,O_RDWR | O_NOCTTY | O_SYNC);
    if (port->fd < 0)
    {
        return -1;
    }
    if (sfards_port_setup(port,115200) < 0)
    {
        sfards_port_close(port);
        return -1;
    }

    if (sfards_port_configure(port,type,freq) < 0)
    {
        sfards_port_close(port);
        return -1;
    }
    return 0;
}

static void sfards_port_refresh(struct sfards_dev *dev)
{
    struct sfards_port *port = dev->port;
    int i; 
    for (i = 0;i < PORT_MAX_COUNT;i++)
    {
        if (port->path[0] != 0 && port->update != 0)
        {
            sfards_port_close(port);
            if (port->update > 0)
            {
                if (sfards_port_open(port,dev->type,dev->freq) == 0)
                {
                    struct epoll_event ev;
                    ev.events = EPOLLIN;
                    ev.data.ptr = port;
                    epoll_ctl(dev->epollfd,EPOLL_CTL_ADD,port->fd,&ev);
                    port->avail = 1;    
                } 
                port->recv_offset = 0; 
            }
            port->update = 0;
        }
        port++;
    }
}

static void *sfards_port_process(void *arg)
{
#define MAX_EVENTS 5    

    struct sfards_dev *dev = (struct sfards_dev *)arg;
    struct epoll_event ev,events[MAX_EVENTS];
    int nfds,i;
 
    while ((nfds = epoll_wait(dev->epollfd, events, MAX_EVENTS, -1)) > 0)
    {
        for (i = 0;i < nfds;i++)
        {
            if (events[i].data.ptr != NULL)
            {
                int len,k;
                struct sfards_port *port = (struct sfards_port *)events[i].data.ptr;
                len = read(port->fd,port->recv_buf + port->recv_offset,
                           PORT_BUF_SIZE - port->recv_offset);
                if (len <= 0)
                {
                    port->update = 2;
                    sfards_port_refresh(dev);
                }
                else
                {
                    port->recv_offset += len;
                    
                    for (k = 0;k <= port->recv_offset - 8;k++)
                    {                    
                        if (port->recv_buf[k] == 0x55)
                        {
                            if (port->recv_buf[k + 2] & 0x80)
                            {
                                if (((port->widx + 1) & 127) != port->ridx)
                                {
                                    port->nonce[port->widx] =   port->recv_buf[k + 4] 
                                                            | port->recv_buf[k + 5] << 8
                                                            | port->recv_buf[k + 6] << 16
                                                            | port->recv_buf[k + 7] << 24;
                                    port->chipid[port->widx] = port->recv_buf[k + 1] & 15;
                                    port->widx = (port->widx + 1) & 127;
                                    pthread_cond_signal(&port->cond);
                                }
                            }
#ifdef DEBUG_RECV
                            {
                                int l;
                                printf("Recv: ");
                                for (l = 0;l < 8;l++)
                                {
                                    printf("%2.2x ",port->recv_buf[k + l]);
                                }
                                printf("\n");
                            }
#endif
                            k += 7;
                        }
                    }
                    if (k > 0) 
                    {
                        memmove(port->recv_buf,port->recv_buf + k,port->recv_offset - k);
                        port->recv_offset -= k; 
                    }
                }
            }
            else
            {
                uint8_t c = 0;
                if (read(dev->pipefd[0],&c,1) <= 0 || c == 0xFF)
                {
                    return NULL;
                }
                else if (c == 0x01)
                {
                    sfards_port_refresh(dev);
                }
            }
        }
    }

    return NULL;
}

static inline int sfards_thr_exit(struct sfards_dev *dev)
{
    uint8_t c = 0xFF;
    return write(dev->pipefd[1],&c,1);
}

static inline int sfards_thr_refresh(struct sfards_dev *dev)
{
    uint8_t c = 0x01;
    return write(dev->pipefd[1],&c,1);
}

struct sfards_dev * sfards_new(enum PORT_TYPE type,int freq)
{
    struct epoll_event ev;
    struct sfards_dev *dev;
    int i;
    dev = (struct sfards_dev *)malloc(sizeof(struct sfards_dev));
    if (dev != NULL)
    {
        memset(dev,0,sizeof(struct sfards_dev));

        dev->type = type;
        dev->freq = freq;
        dev->epollfd = -1;
        dev->pipefd[0] = -1;
        dev->pipefd[1] = -1;
        dev->thr = 0;

        for (i = 0;i < PORT_MAX_COUNT;i++)
        {
            pthread_mutex_init(&dev->port[i].lock,NULL);
            pthread_cond_init(&dev->port[i].cond,NULL);
            dev->port[i].fd = -1;
        }

        if (pipe(dev->pipefd) < 0)
        {
            sfards_destroy(dev);
            return NULL;
        }
        
        dev->epollfd = epoll_create(5);
        if (dev->epollfd < 0)
        {
            sfards_destroy(dev);
            return NULL;
        }
        
        ev.events = EPOLLIN;
        ev.data.ptr = NULL;
        epoll_ctl(dev->epollfd,EPOLL_CTL_ADD,dev->pipefd[0],&ev);
         
        if (pthread_create(&dev->thr,NULL,sfards_port_process,dev) < 0)
        {
            sfards_destroy(dev);
            return NULL;
        }
    }
    return dev;
}

int sfards_port(struct sfards_dev *dev,int index,const char *path)
{
    struct sfards_port *port;
    
    if (index >= PORT_MAX_COUNT || !path || strlen(path) > 63)  
    {
        return -1;
    }
   
    port = &dev->port[index];
    sfards_port_close(port);
    memset(port,0,sizeof(struct sfards_port));
    strcpy(port->path,path);
    port->fd = -1;
    port->update = 1;
    
    port->ridx = 0;
    port->widx = 0;
    port->curpos = 0;

    sfards_thr_refresh(dev);
    return 0;

}

int sfards_scanhash_scrypt(struct sfards_dev *dev,int thr_id, uint32_t *pdata,
                           unsigned char *scratchbuf, const uint32_t *ptarget,
                           uint32_t max_nonce, unsigned long *hashes_done,
                           int N,uint32_t retry)
{
    struct sfards_port *port = &dev->port[thr_id];
    uint32_t job[36],hash[8];
    uint32_t *target = &job[0];
    uint32_t *midstate = &job[8];
    uint32_t *data = &job[16]; 
    uint32_t nonce;
    uint32_t n = pdata[19] - 1;
    const uint32_t Htarg = ptarget[7];
    int i;
    
    if (port->fd < 0 || !port->avail) 
    {
        return -1;
    }

    memcpy(target,ptarget,32);
    memcpy(data, pdata, 80);
    
    sha256_init(midstate);
    sha256_transform(midstate, data, 0);
    
    if (!retry)
    { 
        for (i = 0;i < 16;i++) 
        {
            port->prev_nonce[i] = port->init_nonce[i];
        }
        sfards_port_write(port,0xff,0xbf,0x01,job,35);
        port->ridx = port->widx;
    }

    while(!work_restart[thr_id].restart)
    {
        struct timespec ts;
        if (port->ridx != port->widx)
        {
            int chipid;
            nonce = port->nonce[port->ridx];
            chipid = port->chipid[port->ridx];
            port->ridx = (port->ridx + 1) & 127;

            data[19] = nonce;
            scrypt_1024_1_1_256(data, hash, midstate, scratchbuf, N);
            if (hash[7] <= Htarg && fulltest(hash, ptarget))
            {
                printf("Got nonce %8.8X, Hash <= Htarget!\n",nonce);
                *hashes_done += nonce - port->prev_nonce[chipid] + 1;
                port->prev_nonce[chipid] = nonce;
                pdata[19] = nonce;
                port->nonce_n[chipid]++;
/*
                printf("Thread %d Nonce[%d %d %d %d %d %d %d %d] Error[%d %d %d %d %d %d %d %d]\n",thr_id, 
                        port->nonce_n[1],port->nonce_n[2],port->nonce_n[3],port->nonce_n[4],
                        port->nonce_n[4],port->nonce_n[6],port->nonce_n[7],port->nonce_n[8],
                        port->err_n[1],port->err_n[2],port->err_n[3],port->err_n[4],
                        port->err_n[5],port->err_n[6],port->err_n[7],port->err_n[8]);
*/
                return 1;
            }
            else 
            {
                port->err_n[chipid]++;
                printf("Invalid nonce! \n");
            }
/*
            printf("Thread %d Nonce[%d %d %d %d %d %d %d %d] Error[%d %d %d %d %d %d %d %d]\n",thr_id, 
                    port->nonce_n[1],port->nonce_n[2],port->nonce_n[3],port->nonce_n[4],
                    port->nonce_n[4],port->nonce_n[6],port->nonce_n[7],port->nonce_n[8],
                    port->err_n[1],port->err_n[2],port->err_n[3],port->err_n[4],
                    port->err_n[5],port->err_n[6],port->err_n[7],port->err_n[8]);
*/
        }
        pthread_mutex_lock(&port->lock);
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&port->cond,&port->lock, &ts);
        pthread_mutex_unlock(&port->lock);
    }

    return 0;
}

int sfards_send_sha256d_task(struct sfards_dev *dev,int thr_id,
                             struct stratum_work *stratum_work,uint32_t ntime)
{
    struct sfards_port *port = &dev->port[thr_id];
    uint32_t start = 0x00000007;
    uint32_t job[13] = {0,};
    int i;
    if (port->fd < 0 || !port->avail)
    {
        return 1;
    }

    if (sfards_port_write(port,0xff,0xef,0x1e,&start,1) != 1) 
    {
        return -1;
    }

    job[1] = stratum_work->target[6];
    memcpy(&job[2],stratum_work->midstate,8 * 4);
    job[10] = stratum_work->data2[0];
    job[12] = stratum_work->data2[2];

    if (sfards_port_write(port,0xff,0xef,0x1e,&start,1) != 1) 
    {
        return -1;
    }

    if (sfards_port_write(port,0xff,0xef,0x00,job,10) != 10) 
    {
        return -1;
    }
    
    for (i = 0;i < 8;i++)
    {
        job[11] = ntime + i;
        if (sfards_port_write(port,i + 1,0xef,0x0a,&job[10],3) != 3) 
        {
            return -1;
        }
    }
    return 0;
}

int sfards_wait_sha256d_nonce(struct sfards_dev *dev,int thr_id,
				struct sfards_rpt *nonce_rpt,int size,struct timespec *ts)
{
    struct sfards_port *port = &dev->port[thr_id];
    uint32_t nonce;
    int chipid;
    int i,count = 0;
    int dup = 0;
    while(!work_restart[thr_id].restart && count == 0)
    {
        while (port->ridx != port->widx && count < size)
        {
            chipid = port->chipid[port->ridx];
            nonce = port->nonce[port->ridx];
            port->ridx = (port->ridx + 1) & 127;
            
            for (i = 0;i < 16;i++) 
            {
		if (port->record[i] == nonce) 
                {
                    dup++;
                    break;
                }
            }
            
            if (dup) 
            {
                continue;
            }
            
            nonce_rpt[count].chipid = chipid;
            nonce_rpt[count].data = nonce;
            port->record[port->curpos] = nonce;
            port->curpos = (port->curpos + 1) & 15;
            count++;
        }

        if (count == 0) 
        {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            if (now.tv_sec > ts->tv_sec 
                || (now.tv_sec == ts->tv_sec && now.tv_nsec > ts->tv_nsec))
            {
                break;
            }

            pthread_mutex_lock(&port->lock);
            
            if (ETIMEDOUT == pthread_cond_timedwait(&port->cond,&port->lock, ts))
            {
                pthread_mutex_unlock(&port->lock);
                break;
            }
            pthread_mutex_unlock(&port->lock);                
        }
    }

    return count;
}
 
void sfards_destroy(struct sfards_dev *dev)
{
    int i;
    if (dev->thr > 0)
    {
        sfards_thr_exit(dev);
        pthread_join(dev->thr,NULL);        
    }
    
    for (i = 0;i < PORT_MAX_COUNT;i++)
    {
        struct sfards_port *port = &dev->port[i];
        if (port->fd > 0)
        {
            close(port->fd);
        }
    }

    close(dev->pipefd[0]);
    close(dev->pipefd[1]);
    close(dev->epollfd);
    free(dev);
}

