#include "common.h"
#include "util.h"
#include "session.h"
#include "inner.h"
#include "config.h"
#include "socket.h"

void onSigchld(int sig);

int main(void)
{
	loadConfig();
	daemon(0, 0);

	if (getuid() != 0)
	{
		log_exit("ftpd: must be started as root");
	}

	signal(SIGCHLD, onSigchld);
	int listenfd = tcp_server(g_cfg.listen_address.c_str(), g_cfg.listen_port);
	int conn;
	pid_t pid;
	struct sockaddr_in addr;

	while (1)
	{
		conn = accept_timeout(listenfd, &addr, 0);
		if (conn == -1)
			log_exit("accept_tinmeout");

		unsigned int ip = addr.sin_addr.s_addr;
		
		ipCountMap[ip]++;

		pid = fork();
		if (pid == -1)
		{
			log_exit("fork");
		}

		if (pid == 0)
		{
			close(listenfd);
			signal(SIGCHLD, SIG_IGN);
			Session* ss = new Session(conn, ip);
			ss->start();
		}
		else
		{
			pidIpMap.insert(std::make_pair<int, int>(pid, ip));
			close(conn);
		}
	}
	return 0;
}


void onSigchld(int sig)
{
	// ��һ���ͻ����˳���ʱ����ô�ÿͻ��˶�Ӧip��������Ҫ��1��
	// ��������������ģ������ǿͻ����˳���ʱ��
	// ��������Ҫ֪������ͻ��˵�ip�������ͨ����s_pid_ip_hash���ҵõ���
	
	pid_t pid;
	while ((pid = waitpid(-1, NULL, WNOHANG)) > 0)
	{
		unsigned int ip = pidIpMap[pid];
		std::map<int, int>::iterator it = ipCountMap.find(ip);
		if (it != ipCountMap.end())
		{
			if (--(it->second) == 0)
			{
				ipCountMap.erase(it);
			}
		}
		pidIpMap.erase(pidIpMap.find(pid)); // ɾ�������Ŀ
	}

}

