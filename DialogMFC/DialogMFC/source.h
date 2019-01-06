#include<string>
#include<iostream>
#include<pcap.h>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include<atlstr.h>
#include<vector>
#include "stdafx.h"
#pragma comment(lib,"mpr.lib")
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"ws2_32.lib")


#define BROADMAC        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} //广播MAC
#define EH_TYPE            0x0806                            //ARP类型
#define ARP_HRD            0X0001                            //硬件类型：以太网接口类型为        
#define ARP_PRO            0x0800                            //协议类型：IP协议类型为X0800
#define ARP_HLN            0x06                            //硬件地址长度：MAC地址长度为B
#define ARP_PLN            0x04                            //协议地址长度：IP地址长度为B
#define ARP_REQUEST        0x0001                            //操作：ARP请求为
#define ARP_REPLY        0x0002                            //操作：ARP应答为
#define ARP_THA            {0,0,0,0,0,0}                    //目的MAC地址：ARP请求中该字段没有意义，设为；ARP响应中为接收方的MAC地址
#define ARP_PAD            {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} //18字节的填充数据
#define SPECIAL            0x70707070                        //定义获得自己MAC地址的特殊源IP，.112.112.112
#define ETH_HRD_DEFAULT    {BROADMAC, {0,0,0,0,0,0}, htons(EH_TYPE)} //广播ARP包帧头
#define ARP_HRD_DEFAULT    {htons(ARP_HRD), htons(ARP_PRO), ARP_HLN, ARP_PLN, htons(ARP_REQUEST), {0,0,0,0,0,0}, 0, ARP_THA, 0, ARP_PAD}
#define IPTOSBUFFERS 12
#define WM_PACKET    WM_USER + 105    //用户自定义消息
#define HAVE_REMOTE


std::vector<std::vector<std::string>> GetNameAndIp(const std::string &ip_start, const std::string &ip_end);

void SplitString(const std::string &srcString, std::vector<std::string> &resultVector, const std::string &pattern);

unsigned long str_ip_to_num(std::string ipString);