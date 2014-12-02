#ifndef _INNER_H_
#define _INNER_H_

// 内部进程自定义协议
// 用于FTP服务进程与nobody进程进行通信

// FTP服务进程向nobody进程请求的命令
#define INNER_GET_DATA_FD     1
#define INNER_ACTIVE_PASV       2
#define INNER_PASV_LISTEN       3
#define INNER_PASV_ACCEPT       4

// nobody进程对FTP服务进程的应答
#define INNER_OK         1
#define INNER_BAD        2

void InSendCmd(int fd, char cmd);
char InGetCmd(int fd);
void InSendResult(int fd, char res);
char InGetResult(int fd);

void InGetInt(int fd, int the_int);
int InGetInt(int fd);
void InSendIp(int fd, const char *buf, unsigned int len);
void InRecvIp(int fd, char *buf, unsigned int len);
void InSendFd(int sock_fd, int fd);
int InRecvFd(int sock_fd);


#endif /* _INNER_H_ */

