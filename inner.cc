#include "inner.h"
#include "common.h"
#include "util.h"
#include "socket.h"

void InSendCmd(int fd, char cmd)
{
	int ret;
	ret = writen(fd, &cmd, sizeof(cmd));
	if (ret != sizeof(cmd))
	{
		fprintf(stderr, "InSendCmd error\n");
		exit(EXIT_FAILURE);
	}
}

char InGetCmd(int fd)
{
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if (ret == 0)
	{
		printf("ftp process exit\n");
		exit(EXIT_SUCCESS);
	}
	if (ret != sizeof(res))
	{
		fprintf(stderr, "InGetCmd error\n");
		exit(EXIT_FAILURE);
	}

	return res;
}

void InSendResult(int fd, char res)
{
	int ret;
	ret = writen(fd, &res, sizeof(res));
	if (ret != sizeof(res))
	{
		fprintf(stderr, "InSendResult error\n");
		exit(EXIT_FAILURE);
	}
}

char InGetResult(int fd)
{
	char res;
	int ret;
	ret = readn(fd, &res, sizeof(res));
	if (ret != sizeof(res))
	{
		fprintf(stderr, "InGetResult error\n");
		exit(EXIT_FAILURE);
	}

	return res;
}

void InGetInt(int fd, int the_int)
{
	int ret;
	ret = writen(fd, &the_int, sizeof(the_int));
	if (ret != sizeof(the_int))
	{
		fprintf(stderr, "InGetInt error\n");
		exit(EXIT_FAILURE);
	}
}

int InGetInt(int fd)
{
	int the_int;
	int ret;
	ret = readn(fd, &the_int, sizeof(the_int));
	if (ret != sizeof(the_int))
	{
		fprintf(stderr, "InGetInt error\n");
		exit(EXIT_FAILURE);
	}

	return the_int;
}

void InSendIp(int fd, const char *buf, unsigned int len)
{
	InGetInt(fd, (int)len);
	int ret = writen(fd, buf, len);
	if (ret != (int)len)
	{
		fprintf(stderr, "InSendIp error\n");
		exit(EXIT_FAILURE);
	}
}

void InRecvIp(int fd, char *buf, unsigned int len)
{
	unsigned int recv_len = (unsigned int)InGetInt(fd);
	if (recv_len > len)
	{
		fprintf(stderr, "InRecvIp error\n");
		exit(EXIT_FAILURE);
	}

	int ret = readn(fd, buf, recv_len);
	if (ret != (int)recv_len)
	{
		fprintf(stderr, "InRecvIp error\n");
		exit(EXIT_FAILURE);
	}
}

void InSendFd(int sock_fd, int fd)
{
	send_fd(sock_fd, fd);
}

int InRecvFd(int sock_fd)
{
	return recv_fd(sock_fd);
}


