#ifndef _INNER_H_
#define _INNER_H_

// �ڲ������Զ���Э��
// ����FTP���������nobody���̽���ͨ��

// FTP���������nobody�������������
#define INNER_GET_DATA_FD     1
#define INNER_ACTIVE_PASV       2
#define INNER_PASV_LISTEN       3
#define INNER_PASV_ACCEPT       4

// nobody���̶�FTP������̵�Ӧ��
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

