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
 
char op[MAX_SIZE + 10], temp[MAX_SIZE + 10], buf[MAX_SIZE + 10];

MQ mq;
int main(int argc, char **argv){
    if(argc != 2) {puts(" usage: <IP>"); return 0;}
    int listenfd, connfd;
    struct sockaddr_in servaddr;
    
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if(listenfd < 0){
        fprintf(stderr, "Create socket error\n");
        exit(1);
    }

    int on = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    
    bzero(&servaddr, sizeof servaddr);
    servaddr.sin_family = AF_INET;

    servaddr.sin_addr.s_addr = inet_addr(argv[1]);

    servaddr.sin_port=htons(SERVER_PORT);

    if(bind(listenfd, (struct sockaddr*)&servaddr, sizeof (struct sockaddr)) < 0){
        fprintf(stderr,"Bind error\n");
        exit(1);    
    }

    if(listen(listenfd, 5) < 0){
        fprintf(stderr,"Listen error\n");
        close(listenfd);
        exit(1);
    }

        
    puts("开始监听...");
    
    while(1){
        connfd = accept(listenfd, NULL, NULL);
        if(connfd < 0){
            perror("连接套接字建立失败\n");
            return 0;
        }
        puts("连接成功!");
        int n, quit = 0;
        mq.init(connfd);

        e.seed(time(NULL) + 10);
        ull base = w(e), pkey, key;
        key = quick_pow(DH::a, base, DH::M);
        // printf("server private key: %llu\n\n", key);
        write64((unsigned char*)buf, key);
        write(connfd, buf, 8);

        mq.recv();
        unsigned char *p = (unsigned char*)buf;
        for(int i = 0; i < 8; i++){
            p[i] = mq.front(); mq.pop();
        }
        pkey = read64((unsigned char*)buf);
        // printf("client public key: %llu\n\n", pkey);

        ull KEY = quick_pow(pkey, base, DH::M);

        // printf("会话密钥:  %llu \n\n", KEY);
        FILE *out = fopen("key", "w+");
        fprintf(out, "%llu\n", KEY);
        fflush(out); fclose(out);
        system("./run_des.o -g std.key");

        
        while(1){
            printf("\n就绪中...");
            mq.recv();
            assert(!mq.empty());
            if(mq.front() == NAK){
                quit = 1; break;
            }
            else if(mq.front() == LIST){
                mq.pop();

                FILE *in = popen("ls -al", "r");
                if(in == NULL){
                    fprintf(stderr, "\nList files error.\n");
                    buf[0] = NAK; 
                    if(write(connfd, buf, 1) < 0){
                        fprintf(stderr, "Write error.\n");
                        return 0;
                    }
                    continue;
                }
                buf[0] = CONTENT; write(connfd, buf, 1);
                
                while((n = fread(buf, 1, MAX_SIZE, in)) > 0){
                    // buf[n] = 0; printf("%s\n", buf);
                    if(write(connfd, buf,n) < 0){
                        fprintf(stderr, "Write error.\n");
                        return 0;
                    }
                }   
                
                buf[0] = FIN;
                if(write(connfd, buf, 1) < 0){
                    fprintf(stderr, "Write error.\n");
                    return 0;
                }

                pclose(in);
                puts("\nList responce finished.\n");
            }
            else if(mq.front() == DELETE){
                mq.pop();

                int ok = 0, n = 0;
                while(!ok){
                    if(mq.empty()) mq.recv();
                    while(!mq.empty()){
                        if(mq.front() == FIN){
                            ok = 1; mq.pop(); buf[n] = 0;
                            break;
                        }
                        buf[n++] = mq.front();
                        mq.pop();
                    }
                }
                
                //Only valid when file exists!
                strcpy(op, "ls -al | awk '{print $9}' | grep -w "); 
                strcat(op, buf);  
                // DEBUG; printf("\n查找文件 %s 是否存在...\n", op);

                FILE *in = popen(op, "r");
                if(fread(temp, 1, MAX_SIZE, in) == 0){
                    fprintf(stderr, "\nServer: 文件不存在!\n");
                    buf[0] = NAK;
                    write(connfd, buf, 1);
                    continue;
                }
                pclose(in);

                strcpy(op, "rm "); strcat(op, buf);
                in = popen(op, "r");

                if(in == NULL){
                    fprintf(stderr, "Remove files error.\n");
                    buf[0] = NAK;
                    write(connfd, buf, 1);
                    continue;
                }

                n = fread(buf + 3, 1, MAX_SIZE, in);
                assert(n == 0);
                buf[0] = ACK;
                write(connfd, buf, 1);
                pclose(in);
                puts("\nRemove responce finished.\n");
            }
            else if(mq.front() == UPLOAD){
                mq.pop();

                int ok = 0, n = 0;
                while(!ok){
                    if(mq.empty()) mq.recv();
                    while(!mq.empty()){
                        if(mq.front() == FIN){
                            ok = 1; mq.pop(); temp[n] = 0;
                            break;
                        }
                        temp[n++] = mq.front();
                        mq.pop();
                    }
                }

                
                printf("\n即将上传文件 %s\n", temp);

                FILE *out = fopen(temp, "wb+");
                fclose(out);
                if(out == NULL){
                    fprintf(stderr, "Create files error.\n");
                    buf[0] = NAK; n = 1;
                    write(connfd, buf, n);
                    continue;
                }

                buf[0] = ACK;
                write(connfd, buf, 1);

                mq.recv();
                if(mq.front() == NAK){
                    mq.pop();
                    strcpy(op, "rm "); strcat(op, temp);
                    system(op);
                    fprintf(stderr, "\n发送方终止了传送\n");
                    continue;
                }

                long size = 0;
                assert(mq.size() == 8);
                for(int i = 0; i < 8; i++){
                    size |= (unsigned long)mq.front() << (i * 8);
                    // printf("%d ", mq.front());
                    mq.pop();
                }
                printf("\n文件大小 %ld btyes\n", size);


                int fd = open(temp ,O_RDWR);
                if(fd < 0){
                    fprintf(stderr, "Open files error.\n");
                    buf[0] = NAK; n = 1;
                    write(connfd, buf, n);
                    continue;
                }

                if(ftruncate(fd, size) < 0){
                    fprintf(stderr, "Memrary allocat error.\n");
                    buf[0] = NAK; n = 1;
                    write(connfd, buf, n);
                    continue;
                }
                close(fd);

                buf[0] = ACK; write(connfd, buf, 1);


                out = fopen(temp, "wb+");
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

#ifdef SECURE   
                //服务器接受完成后，接受的密文目前存储在temp文件中，将密文解密后存储在TEMP中
                //再调用cp指令用TEMP覆盖原先的文件，删除TEMP, 最终完成传输过程。

                //temp里存储了文件名
                strcpy(buf, "./run_des.o -d std.key ");
                strcat(buf, temp);
                strcat(buf, " TEMP");
                puts("");
                system(buf);

                strcpy(buf, "cp TEMP ");
                strcat(buf, temp);
                system(buf); system("rm TEMP");

#endif

                assert(mq.empty());

                puts("");
                buf[0] = ACK; 
                write(connfd, buf, 1);

                puts("\nUpload finished.\n");
            }
            else if(mq.front() == DOWNLOAD){
                mq.pop();

                //读取将要下载的文件名到temp中
                int ok = 0, n = 0;
                while(!ok){
                    if(mq.empty()) mq.recv();
                    while(!mq.empty()){
                        if(mq.front() == FIN){
                            ok = 1; mq.pop(); temp[n] = 0;
                            break;
                        }
                        temp[n++] = mq.front();
                        mq.pop();
                    }
                }


#ifdef SECURE 
            strcpy(buf, "./run_des.o -e std.key ");
            strcat(buf, temp);
            strcat(buf, " TEMP");
            puts("");
            system(buf);
            puts("");

            strcpy(temp, "TEMP");
#endif

                FILE *in = fopen(temp, "rb");
                if(in == NULL){
                    DEBUG; fprintf(stderr, "Open file error.\n");
                    buf[0] = NAK; write(connfd, buf, 1);
                    continue;
                }

                

                fseek(in, 0, SEEK_END);
                long size = ftell(in);
                long test = size;
                fclose(in);

                if(size == -1){
                    DEBUG; fprintf(stderr, "读取文件长度失败");
                    buf[0] = NAK; write(connfd, buf, 1);
                    continue;
                }

                // printf("读取到 %d bytessss\n", size);

                buf[0] = ACK; write(connfd, buf, 1);

                unsigned char* p = (unsigned char*) buf;
                for(int i = 0; i < 8; i++){
                    p[i] = test & 0xff;
                    // printf("%d ", p[i]);
                    test >>= 8;
                }
                printf("\n将要上传 %ld bytes\n", size);
                write(connfd, buf, 8);

                mq.recv();
                if(mq.front() == NAK){
                    mq.pop();
                    DEBUG; fprintf(stderr, "客户端终止了请求");
                    continue;
                }

                assert(mq.front() == ACK); mq.pop();


                in = fopen(temp, "rb");
                long sum = 0; int fail = 0;
                while((n = fread(buf, 1, MAX_SIZE, in)) > 0){

                    if(write(connfd, buf, n) <= 0){
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
                
                mq.recv(); assert(mq.front() == ACK); mq.pop();
                printf("\n下载完成\n");

            }
        }

        if(quit){
            puts("\n当前连接所有内容均传输完成, 关闭连接\n"); fflush(stdout);
            close(connfd);
        }
        
    }

    return 0;
}
