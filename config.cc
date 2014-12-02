#include "config.h"
#include "util.h"
#include "session.h"

SVR_CONFIG g_cfg;   //服务器全局配置
std::map<int, int> ipCountMap;// ip与个这个ip的客户端数 的映射
std::map<int, int> pidIpMap; // pid 与 ip的映射

Config::Config(const char* filename)
{
	_LoadFile(filename);
}
Config::~Config()
{
	
}

char* Config::get(const char* name)
{
	if (!isLoadOk)
		return NULL;

	char* value = NULL;
	std::map<std::string, std::string>::iterator it = configMap.find(name);

	if (it != configMap.end())
	{
		value = (char*)it->second.c_str();
	}

	return value;
}
void Config::_LoadFile(const char* filename)
{
	FILE* fp = fopen(filename, "r");
	if (!fp)
	{
		log("can not open %s\n", filename);
		return ;
	}

	char buf[256];
	for (;;)
	{
		char* p = fgets(buf, 256, fp);
		if (!p)
			break;

		size_t len = strlen(buf);
		if (buf[len - 1] == '\n')
			buf[len - 1] = 0;		// remove \n at the end

		char* ch = strchr(buf, '#'); // remove string start with #
		if (ch)
			*ch = 0;

		if (strlen(buf) == 0)
			continue;

		_ParseLine(buf);
	}

	fclose(fp);
	isLoadOk = true;
}
void Config::_ParseLine(char* line)
{
	char* p = strchr(line, '=');
	if (p == NULL)
		return ;

	*p = 0;
	char* key = _TrimSpace(line);
	char* value = _TrimSpace(p + 1);
	if (key && value)
	{
		configMap.insert(std::make_pair(key, value));
	}
}
char* Config::_TrimSpace(char* name)
{
	// remove starting space or tab
	char* start_pos = name;
	while ( (*start_pos == ' ') || (*start_pos == '\t') )
	{
		start_pos++;
	}

	if (strlen(start_pos) == 0)
		return NULL;

	// remove ending space or tab
	char* end_pos = name + strlen(name) - 1;
	while ( (*end_pos == ' ') || (*end_pos == '\t') )
	{
		*end_pos = 0;
		end_pos--;
	}

	int len = (int)(end_pos - start_pos) + 1;
	if (len <= 0)
		return NULL;

	return start_pos;
}


void loadConfig()
{
	Config config_file(FTP_CONF);
	g_cfg.pasv_enable = atoi(config_file.get("pasv_enable"));
	g_cfg.port_enable= atoi(config_file.get("port_enable"));
	g_cfg.listen_port= atoi(config_file.get("listen_port"));
	g_cfg.max_clients = atoi(config_file.get("max_clients"));
	g_cfg.max_per_ip = atoi(config_file.get("max_per_ip"));
	g_cfg.accept_timeout = atoi(config_file.get("accept_timeout"));
	g_cfg.connect_timeout = atoi(config_file.get("connect_timeout"));
	g_cfg.idle_session_timeout = atoi(config_file.get("idle_session_timeout"));
	g_cfg.data_connection_timeout= atoi(config_file.get("data_connection_timeout"));
	g_cfg.local_umask = strOctalToUint(config_file.get("local_umask"));
	g_cfg.upload_max_rate = atoi(config_file.get("upload_max_rate"));
	g_cfg.download_max_rate = atoi(config_file.get("download_max_rate"));
	g_cfg.listen_address = config_file.get("listen_address");
	
	for (int i = 0; cmd_array[i].cmd != NULL; i++)
	{
		cmd_map.insert(std::make_pair(cmd_array[i].cmd, cmd_array[i].seq));
	}
}


