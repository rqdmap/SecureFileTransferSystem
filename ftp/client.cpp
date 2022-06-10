#include <semaphore.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <sys/time.h>
#include <fcntl.h>
#include <random>
#include "rqdmap.h"
#include "ftp.h"

using namespace std;
default_random_engine e;
uniform_int_distribution<long long > w(0, (long long)1e18);


#define SERVER_PORT 8086

char op[MAX_SIZE + 10], buf[MAX_SIZE + 10], temp[MAX_SIZE + 10];

MQ mq;

int main(int argc, char *argv[]){
    if(argc != 2) {puts(" usage: <IP>"); return 0;}
    int sockfd;
    struct sockaddr_in servaddr;
    socklen_t addr_len = sizeof servaddr;
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        fprintf(stderr, "Create socket error\n");
        exit(1);
    }

    bzero(&servaddr, sizeof servaddr);
    servaddr.sin_family = AF_INET;

    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);

    servaddr.sin_port=htons(SERVER_PORT);

    if(connect(sockfd, (struct sockaddr*)&servaddr, sizeof servaddr) < 0){
        fprintf(stderr, "Connect error\n");
        exit(0);
    }

   
    
    mq.init(sockfd);
    int n;

    e.seed(time(NULL));
    ull base = w(e), pkey, key;
    key = quick_pow(DH::a, base, DH::M);
    // printf("client private key: %llu\n\n", key);
    write64((unsigned char*)buf, key);
    write(sockfd, buf, 8);

    mq.recv();
    unsigned char *p = (unsigned char*)buf;
    for(int i = 0; i < 8; i++){
        p[i] = mq.front(); mq.pop();
    }
    pkey = read64((unsigned char*)buf);
    // printf("server public key: %llu\n\n", pkey);

    ull KEY = quick_pow(pkey, base, DH::M);
    // printf("会话密钥获取完成 \n", KEY);
    FILE *out = fopen("key", "w+");
    fprintf(out, "%llu\n", KEY);
    fflush(out); fclose(out);
    system("./run_des.o -g std.key");

    while(1){
        printf("\n> ");
        scanf("%s", op); 

        if(!strcmp(op, "exit") || !strcmp(op, "quit") || !strcmp(op, "q")){
            buf[0] = NAK; n = 1;
            write(sockfd, buf, 1);

            close(sockfd);
            puts("Bye.");
            return 0;
        }
        else if(!strcmp(op, "list") || !strcmp(op, "ls")){
            puts("");   

            buf[0] = LIST; 
            write(sockfd, buf, 1);

            mq.recv();

            if(mq.front() == NAK){
                mq.pop();
                printf("ls 请求失败\n");
                continue;
            }

            assert(mq.front() == CONTENT); mq.pop();

            int ok = 0;
            while(!ok){
                if(mq.empty()) mq.recv();

                while(!mq.empty()){
                    if(mq.front() == FIN){
                        ok = 1; mq.pop();
                        break;
                    }
                    printf("%c", mq.front()); mq.pop();
                }
            }
            puts("");
        }
        else if(!strcmp(op, "rm") || !strcmp(op, "delete")){
            puts("");

            buf[0] = DELETE; 
            write(sockfd, buf, 1);

            scanf("%s", buf); n = (int)strlen(buf);
            // DEBUG; printf("n %d\n", n);
            write(sockfd, buf, n);

            buf[0] = FIN;
            write(sockfd, buf, 1);

            mq.recv();
            if(mq.front() == NAK){
                mq.pop();
                printf("删除失败\n");   
                continue;
            }

            assert(mq.front() == ACK);
            mq.pop();

            printf("删除完成.\n");
        }
        else if(!strcmp(op, "upload") || !strcmp(op, "up")){
            struct timeval start, end;
            gettimeofday(&start, NULL);

            buf[0] = UPLOAD; write(sockfd, buf, 1);
            
            scanf("%s", op); n = (int)strlen(op);
            write(sockfd, op, n);

            buf[0] = FIN; write(sockfd, buf, 1);

            mq.recv();
            if(mq.front() == NAK){
                printf("\n创建文件失败\n");
                continue;
            }

            assert(mq.front() == ACK);

#ifdef SECURE 
            //在上传步骤中，发送方先在本地将文件加密，密文存储在TEMP中，随后将TEMP发送出去
            
            //op里存储了文件名
            strcpy(buf, "./run_des.o -e std.key ");
            strcat(buf, op);
            strcat(buf, " TEMP");
            puts("");
            system(buf);
            puts("");
            strcpy(op, "TEMP");
#endif

            FILE *in = fopen(op, "rb");

            if(in == NULL){
                DEBUG; fprintf(stderr, "Open file error.\n");
                buf[0] = NAK; write(sockfd, buf, 1);
                continue;
            }


            fseek(in, 0, SEEK_END);
            long size = ftell(in);
            long test = size;
            fclose(in);

            if(size == -1){
                DEBUG; fprintf(stderr, "读取文件长度失败");
                buf[0] = NAK; write(sockfd, buf, 1);
                continue;
            }

            unsigned char* p = (unsigned char*) buf;
            for(int i = 0; i < 8; i++){
                p[i] = test & 0xff;
                // printf("%d ", p[i]);
                test >>= 8;
            }
            printf("\n将要上传 %ld bytes\n", size);
            write(sockfd, buf, 8);

            mq.recv();
            if(mq.front() == NAK){
                mq.pop();
                printf("开辟空间失败");
                continue;
            }

            assert(mq.front() == ACK);

            in = fopen(op, "rb");

            long sum = 0; int fail = 0;
            while((n = fread(buf, 1, MAX_SIZE, in)) > 0){

                if(write(sockfd, buf, n) <= 0){
                    DEBUG; fprintf(stderr, "write sockfd 失败! \n");
                    fail = 1;
                    break;
                }
                sum += n;
                printf("已经传输 %ld bytes\n", sum);
            }

            if(fail){
                DEBUG; fprintf(stderr, "出现错误\n");
                continue;
            }

            assert(sum == size);

            mq.recv();
            assert(mq.front() == ACK);
            printf("\n上传完成\n");
            
            gettimeofday(&end, NULL);
            printf("总共上传耗时 %.5f s\n", ((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000.0) / 1000.0);
        }
        else if(!strcmp(op, "downlowd") || !strcmp(op, "down")){
            struct timeval start, end;
            gettimeofday(&start, NULL);

            buf[0] = DOWNLOAD; write(sockfd, buf, 1);
            scanf("%s", op); n = (int)strlen(op);
            write(sockfd, op, n);

            buf[0] = FIN; write(sockfd, buf, 1);

            mq.recv();
            if(mq.front() == NAK){
                mq.pop();
                DEBUG; fprintf(stderr, "服务器创建文件失败\n");
                continue;
            }

            assert(mq.front() == ACK); mq.pop();

            if(mq.empty()) mq.recv();
            long size = 0;
            assert(mq.size() == 8);
            for(int i = 0; i < 8; i++){
                size |= (unsigned long)mq.front() << (i * 8);
                // printf("%d ", mq.front());
                mq.pop();
            }
            printf("\n文件大小 %ld btyes\n", size);

            buf[0] = ACK; write(sockfd, buf, 1);

            FILE *out = fopen(op, "wb+");

            n = 0;
            long cnt = 0; int fail = 0;
            while(!fail && size > 0){
                if(mq.empty()) mq.recv();

                while(!mq.empty() && size){
                    size--;
                    cnt++;
                    // if(cnt % MAX_SIZE == 0) printf("已经接受 %ld bytes, n %d \n", cnt, n);
                    buf[n++] = mq.front(); mq.pop();
                    if(n == MAX_SIZE){
                        if(fwrite(buf, 1, n, out) < 0){
                            DEBUG; fprintf(stderr, "write file 失败! \n");
                            fail = 1;
                            break;
                        }
                        fflush(out);
                        n = 0;
                    }
                }
            }

            if(fail){
                fclose(out);
                //按道理通知发送方，但是太麻烦了，并且收益较低，所以直接重启服务吧
                exit(0);
            }

            fwrite(buf, 1, n, out); fflush(out);
            fclose(out); 
            assert(mq.empty());

#ifdef SECURE   
            strcpy(buf, "./run_des.o -d std.key ");
            strcat(buf, op);
            strcat(buf, " TEMP");

            puts("");
            system(buf);

            strcpy(buf, "cp TEMP ");
            strcat(buf, op);
            system(buf); system("rm TEMP");

#endif

            puts("");

            buf[0] = ACK; 
            write(sockfd, buf, 1);

            puts("\n下载完成.\n");

            gettimeofday(&end, NULL);
            printf("总共下载耗时 %.5f s\n", ((end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000.0) / 1000.0);
        }
        else{
            puts("Operation invalid!");
        }

    }
    
	return 0;
}

