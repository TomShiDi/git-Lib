#include <winsock2.h>
#include <string>
#include <iostream>
#include<conio.h>
#include<thread>

#pragma comment(lib,"ws2_32.lib")
#define BUF_SIZE 128


WSADATA wsd;
SOCKET sHost;
SOCKADDR_IN servAddr;
char buf[BUF_SIZE];
int retVal;
char sendData[BUF_SIZE];

int recvMessage()
{
	while (true)
	{
		while (true)
		{
			ZeroMemory(buf, BUF_SIZE);
			retVal = recv(sHost, buf, sizeof(buf)+1, 0);
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK)
				{
					Sleep(100);
					//printf("waiting back msg!\n");
					continue;
				}
				else if (err == WSAETIMEDOUT || err == WSAENETDOWN)
				{
					printf("recv failed!\n");
					closesocket(sHost);
					WSACleanup();
					return -1;
				}
				break;
			}
			break;

		}
		printf("Recv From Server:%s\n", buf);
	}
}

int sendMessage()
{
	ZeroMemory(buf, BUF_SIZE);
	std::string str = "";
	strcpy_s(buf, str.c_str());
	
	while (true)
	{
		char c;
		
		if (_kbhit())
		{
			if ((c = _getch()) != '\r'){
				str.assign("");
				str.push_back(c);
				std::cout << c;

				strcat_s(sendData, sizeof(sendData), str.c_str());
			}
			else
			{
				std::cout << std::endl;
				//printf("输入的内容为: %s", str.c_str());

				//获取系统时间
				/*SYSTEMTIME st;
				GetLocalTime(&st);
				char sDateTime[30];
				sprintf_s(sDateTime, "%4d-%2d-%2d %2d:%2d:%2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

				char msg[BUF_SIZE];

				sprintf_s(msg, "%s:  Message - %s", sDateTime, sendData);*/
				while (true)
				{
					std::cout << "sendData: " << sendData << std::endl;
					retVal = send(sHost, sendData, strlen(sendData), 0);
					if (SOCKET_ERROR == retVal)
					{
						int err = WSAGetLastError();
						if (err == WSAEWOULDBLOCK)
						{
							Sleep(500);
							continue;
						}
						else
						{
							printf("send failed!\n");
							closesocket(sHost);
							WSACleanup();
							return -1;
						}
					}
					ZeroMemory(sendData, BUF_SIZE);
					break;

				}
			}
		}
	}
	
}

int main(int argc, char* argv[])
{
	
	//初始化Socket
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("WSAStartup failed!\n");
		return -1;
	}
	//创建Socket
	sHost = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sHost)
	{
		printf("socket failed!\n");
		WSACleanup();
		return -1;
	}
	//设置Socket为非阻塞模式
	int iMode = 1;
	retVal = ioctlsocket(sHost, FIONBIO, (u_long FAR*)&iMode);
	if (retVal == SOCKET_ERROR)
	{
		printf("ioctlsocket failed!\n");
		WSACleanup();
		return -1;
	}
	//设置服务器Socket地址
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(9990);
	servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");//htonl(INADDR_ANY);

	int sServerAddlen = sizeof(servAddr);

	//连接到服务器
	while (true)
	{
		retVal = connect(sHost, (LPSOCKADDR)&servAddr, sizeof(servAddr));
		if (SOCKET_ERROR == retVal)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK || err == WSAEINVAL)
			{
				Sleep(500);
				continue;
			}
			else if (err == WSAEISCONN)
			{
				printf("Client connect success ......");
				break;
			}
			else
			{
				printf("connection failed!\n");
				closesocket(sHost);
				WSACleanup();
				return -1;
			}
		}
	}

	std::thread thread_recv(recvMessage);
	std::thread thread_send(sendMessage);
	//收发数据
	while (true)
	{
		/*printf("Please input a string to send:");
		std::string str;
		std::getline(std::cin, str);
		ZeroMemory(buf, BUF_SIZE);
		strcpy_s(buf, str.c_str());
		while (true)
		{
			retVal = send(sHost, buf, strlen(buf), 0);
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK)
				{
					Sleep(500);
					continue;
				}
				else
				{
					printf("send failed!\n");
					closesocket(sHost);
					WSACleanup();
					return -1;
				}
			}
			break;

		}*/

		/*while (true)
		{
			ZeroMemory(buf, BUF_SIZE);
			retVal = recv(sHost, buf, sizeof(buf)+1, 0);
			if (SOCKET_ERROR == retVal)
			{
				int err = WSAGetLastError();
				if (err == WSAEWOULDBLOCK)
				{
					Sleep(100);
					printf("waiting back msg!\n");
					continue;
				}
				else if (err == WSAETIMEDOUT || err == WSAENETDOWN)
				{
					printf("recv failed!\n");
					closesocket(sHost);
					WSACleanup();
					return -1;
				}
				break;
			}
			break;

		}
		printf("Recv From Server:%s\n", buf);
		if (strcmp(buf, "quit") == 0)
		{
			printf("quit!\n");
			break;
		}*/
	}

	closesocket(sHost);
	WSACleanup();
	system("pause");

	return 0;
}