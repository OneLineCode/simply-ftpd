#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "common.h"

struct SVR_CONFIG
{
	int pasv_enable;
	int port_enable;
	unsigned int listen_port;
	unsigned int max_clients;
	unsigned int max_per_ip;
	unsigned int accept_timeout;
	unsigned int connect_timeout;
	unsigned int idle_session_timeout;
	unsigned int data_connection_timeout;
	unsigned int local_umask;
	unsigned int upload_max_rate;
	unsigned int download_max_rate;
	std::string listen_address;
	SVR_CONFIG()
	{
		pasv_enable = 1;
		port_enable = 1;
		listen_port = 21;
		max_clients = 2000;
		max_per_ip = 50;
		accept_timeout = 60;
		connect_timeout = 60;
		idle_session_timeout = 300;
		data_connection_timeout = 300;
		local_umask = 077;
		upload_max_rate = 0;
		download_max_rate = 0;
		listen_address = "127.0.0.1";
	}
};

class Config
{
public:
	Config(const char* filename);
	~Config();

	char* get(const char* name);
private:
	void _LoadFile(const char* filename);
	void _ParseLine(char* line);
	char* _TrimSpace(char* name);

	bool isLoadOk;
	std::map<std::string, std::string> configMap;
};

extern SVR_CONFIG g_cfg;   //服务器全局配置
extern std::map<int, int> ipCountMap;// ip与个这个ip的客户端数 的映射
extern std::map<int, int> pidIpMap; // pid 与 ip的映射

void loadConfig();
#endif //_CONFIG_H_

