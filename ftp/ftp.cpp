#include "ftp.h"

void MQ::init(int _sockfd){
    head = tail = 0;
    sockfd = _sockfd;
}

void MQ::recv(){
    if((tail + 1) % M == head){
            fprintf(stderr, "MQ 满了！");
            return;
        }
        
        int n;
        if(!head) n = (int)read(sockfd, queue + tail, M - 1 - tail);
        else if(tail >= head) n = (int)read(sockfd, queue + tail, M - tail);
        else n = (int)read(sockfd, queue + tail, head - tail - 1);

        tail += n;
        if(tail == M) tail = 0;

        //assert也没有问题，确实不会读到超过M个字节
        // assert(tail <= M);
        // if(tail >= M) tail -= M;
}

int MQ::size(){return (tail + M - head) % M;}

bool MQ::empty(){return head == tail;}

unsigned char MQ::front(){return queue[head];}

void MQ::pop(){
    assert(this->empty() == 0);
    head++; if(head == M) head = 0;
}

void MQ::prt(){
    for(int i = head; i != tail; i = (i == M - 1? 0: i + 1)){
        printf("%d ", queue[i]);
    }
    puts("");
}


ull quick_pow(ull a, ull p, const ull M){
    __int128_t res = a, ans = 1;
    while(p){
        if(p & 1) ans = ans * res % M;
        res = res * res % M;
        p >>= 1;
    }
    return (ull)(ans % M);
}

void write64(unsigned char *buf, ull x){
    for(int i = 0; i < 8; i++){
        buf[i] = x & 0xff;
        x >>= 8;
    }
}

ull read64(unsigned char *buf){
    ull x = 0;
    for(int i = 0; i < 8; i++){
        x |= (ull)buf[i] << (i * 8);
    }
    return x;
}