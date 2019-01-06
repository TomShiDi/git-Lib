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


#define BROADMAC        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF} //�㲥MAC
#define EH_TYPE            0x0806                            //ARP����
#define ARP_HRD            0X0001                            //Ӳ�����ͣ���̫���ӿ�����Ϊ        
#define ARP_PRO            0x0800                            //Э�����ͣ�IPЭ������ΪX0800
#define ARP_HLN            0x06                            //Ӳ����ַ���ȣ�MAC��ַ����ΪB
#define ARP_PLN            0x04                            //Э���ַ���ȣ�IP��ַ����ΪB
#define ARP_REQUEST        0x0001                            //������ARP����Ϊ
#define ARP_REPLY        0x0002                            //������ARPӦ��Ϊ
#define ARP_THA            {0,0,0,0,0,0}                    //Ŀ��MAC��ַ��ARP�����и��ֶ�û�����壬��Ϊ��ARP��Ӧ��Ϊ���շ���MAC��ַ
#define ARP_PAD            {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} //18�ֽڵ��������
#define SPECIAL            0x70707070                        //�������Լ�MAC��ַ������ԴIP��.112.112.112
#define ETH_HRD_DEFAULT    {BROADMAC, {0,0,0,0,0,0}, htons(EH_TYPE)} //�㲥ARP��֡ͷ
#define ARP_HRD_DEFAULT    {htons(ARP_HRD), htons(ARP_PRO), ARP_HLN, ARP_PLN, htons(ARP_REQUEST), {0,0,0,0,0,0}, 0, ARP_THA, 0, ARP_PAD}
#define IPTOSBUFFERS 12
#define WM_PACKET    WM_USER + 105    //�û��Զ�����Ϣ
#define HAVE_REMOTE


std::vector<std::vector<std::string>> GetNameAndIp(const std::string &ip_start, const std::string &ip_end);

void SplitString(const std::string &srcString, std::vector<std::string> &resultVector, const std::string &pattern);

unsigned long str_ip_to_num(std::string ipString);