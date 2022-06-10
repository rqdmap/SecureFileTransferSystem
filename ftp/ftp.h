#ifndef ftp
#define ftp

#include "rqdmap.h"
#include <random>
#include <cstdio>
#include <cassert>
#include <unistd.h>

#define LIST 0
#define UPLOAD 1
#define DOWNLOAD 2
#define CONTENT 3
#define ACK 4
#define NAK 5
#define FIN 6
#define DELETE 7

#define MAX_SIZE 1000000
#define DELAY 1000

const int M = MAX_SIZE;
struct MQ{
    unsigned char queue[M + 10];
    int head, tail;
    int sockfd;
    
    void init(int sockfd);   //使用连接套接字初始化该消息队列
    void recv();             //读取一次不超过剩余空间的TCP消息
    int size();              //返回队列中字节数
    bool empty();            //返回是否为空
    unsigned char front();   //返回队头元素
    void pop();              //弹出队头元素
    void prt();              //【调试用】顺序打印队列的所有元素值
};

//return a^p % M
unsigned long long quick_pow(ull a, ull p, const ull M);

namespace DH{
    const ull M = 1000000000000000003, a = 2;
};

void write64(unsigned char *buf, ull x);
ull read64(unsigned char *buf);
#endif