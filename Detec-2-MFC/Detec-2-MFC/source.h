#include<string>
#include<iostream>
#include<pcap.h>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include<atlstr.h>

#include "Detec-2-MFCDlg.h"

#include "stdafx.h"
#include<Packet32.h>
#include<stdlib.h>
#include<thread>
#include<conio.h>

#pragma comment(lib,"mpr.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"Packet.lib")

#pragma pack(push) // 保持对齐方式
#pragma pack(1) // 设定1字节对齐






///函数作用,输出网卡信息
void output(PIP_ADAPTER_INFO pIpAdapterInfo);

void GetSelfMac(char* pDevName);

int recvArpPacket(CDetec2MFCDlg *cDetec2MFCDlg);

unsigned char *BuildArpPacket(unsigned char *source_mac, unsigned long srcIP, unsigned long destIP);

int sendArpPacket();

void start_detect(CDetec2MFCDlg *cDetec2MFCDlg);