
#include "stdafx.h"
#include "source.h"
#include "Detec-2-MFCDlg.h"


//arp数据包
struct arp_head
{
	unsigned short hardware_type;//硬件类型
	unsigned short protocol_type;//协议类型
	unsigned char add_len;//硬件地址长度
	unsigned char pro_len;//协议地址长度
	unsigned short option;//操作类型，arp请求与应答，rarp请求与应答
	unsigned char sour_addr[6];//源MAC
	unsigned long sour_ip;//源IP
	unsigned char dest_addr[6];//目的MAC
	unsigned long dest_ip;//目的IP

};

struct ethernet_head
{
	unsigned char dest_mac[6];//目的MAC地址
	unsigned char source_mac[6];//源MAC地址
	unsigned short eh_type;//帧类型
};


//发送的数据包
struct arp_packet
{
	ethernet_head eth;//以太网首部
	arp_head arp;//arp包
	unsigned char padding[18];//填充数据
};






