#ifndef _SESSION_H_
#define _SESSION_H_

#include "common.h"

extern std::map<std::string, int> cmd_map;

typedef struct ftpcmd
{
	const char *cmd;
	//void (*cmd_handler)();
	int seq;
} ftpcmd_t;
extern ftpcmd_t cmd_array[FTP_MAX_CMD]; //�����ǲ���ȫ����


class Session
{
public:
	Session(int conn, unsigned int  ip);
	~Session();
	void start();
	void checkLimits();
	void runServiceProcess();
	void runNobodyProcess();

	int getCtrlFd();
	int getDataFd();
	bool getTransferring();
	void setTransferring(bool isTransferring);
	void setAbor(bool abor);


	void ftp_reply(int status, const char *text);
	static void ftp_reply(int ctrlFd, int status, const char *text);
	void ftp_lreply(int status, const char *text);

	static void handleAlarmTimeout(int sig);
	static void handleSigalrm(int sig);
	static void handleSigurg(int sig);
	void startSessionAlarm(void);
	void startDataAlarm(void);

	void checkAbor();

	int list(int detail);
	void limitRate(int bytes_transfered, int is_upload);
	void upload(int is_append);

	int getPortFd();
	int getPasvFd();
	int getTransferFd();
	int portActive();
	int pasvActive();

	void onUser();
	void onPass();
	void onCwd();
	void onCdUp();
	void onQuit();
	void onPort();
	void onPasv();
	void onType();

	void onRetr();
	void onStor();
	void onAppe();
	void onList();
	void onNlist();
	void onRest();
	void onAbor();
	void onPwd();
	void onMkd();
	void onRmd();
	void onDele();
	void onRnfr();
	void onRnto();
	void onSite();
	void onSyst();
	void onFeat();
	void onSize();
	void onStat();
	void onNoop();
	void onHelp();


	void onSiteChmod(char *chmod_arg);
	void onSiteUmask(char *umask_arg);


	// nobody����
	void innerGetDataFd();
	void innerPasvActive();
	void innerPasvListen();
	void innerPasvAccept();
private:

	// ��������
	uid_t uid_;
	int ctrlFd_;
	char cmdline_[MAX_COMMAND_LINE];
	char cmd_[MAX_COMMAND];
	char arg_[MAX_ARG];

	// ����
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;

	// ��������
	struct sockaddr_in *portAddr_;
	int pasv_listen_fd_;
	int dataFd_;
	//bool data_process_;// ���ݴ�����
	bool isTransferring_;// ���ݴ�����

	// ���ӽ���ͨ��
	int parentFd_;
	int childFd_;

	// FTPЭ��״̬
	int is_ascii_;
	long long restart_pos_;
	char *rnfr_name_;
	//int abor_received_;
	bool abor_;

	// ��Session����������
	static unsigned int num_clients;
	//
	unsigned int ip_;
};

/*
typedef struct session
{
	// ��������
	uid_t uid;
	int ctrl_fd;
	char cmdline[MAX_COMMAND_LINE];
	char cmd[MAX_COMMAND];
	char arg[MAX_ARG];

	// ��������
	struct sockaddr_in *port_addr;
	int pasv_listen_fd;
	int data_fd;
	int data_process;

	// ����
	unsigned int bw_upload_rate_max;
	unsigned int bw_download_rate_max;
	long bw_transfer_start_sec;
	long bw_transfer_start_usec;


	// ���ӽ���ͨ��
	int parent_fd;
	int child_fd;

	// FTPЭ��״̬
	int is_ascii;
	long long restart_pos;
	char *rnfr_name;
	int abor_received;

	// ����������
	unsigned int num_clients;
	unsigned int num_this_ip;
} session_t;
*/

extern Session* g_SessPtr; // for signal

int capset(cap_user_header_t hdrp, const cap_user_data_t datap);

void minimize_privilege(void);

#endif /* _SESSION_H_ */

