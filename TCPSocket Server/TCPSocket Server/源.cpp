
#include <winsock2.h>
#include <iostream>
#include<thread>
#include<conio.h>
#include<string>


#pragma comment(lib,"ws2_32.lib")

#define BUF_SIZE 128

char sendData[128];

sockaddr_in addrServ;

WSADATA wsd;
SOCKET sServer;
SOCKET sClient;
int retVal;
char buf[BUF_SIZE];

sockaddr_in addrClient;

int sendMessage()
{
	
	std::string str1 = "";
	while (true)
	{
		char c;
		
		if (_kbhit())
		{
			if ((c = _getch()) != '\r'){
				str1.assign("");
				str1.push_back(c);
				std::cout << c;
				
				strcat_s(sendData, sizeof(sendData), str1.c_str());
			}
			else
			{
				std::cout << std::endl;
				//printf("���������Ϊ: %s", str1.c_str());

				//��ȡϵͳʱ��
				SYSTEMTIME st;
				GetLocalTime(&st);
				char sDateTime[30];
				sprintf_s(sDateTime, "%4d-%2d-%2d %2d:%2d:%2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

				char msg[BUF_SIZE];

				sprintf_s(msg, "%s:  Message - %s", sDateTime, sendData);


				while (true)
				{
					retVal = send(sClient, msg, strlen(msg), 0);
					if (SOCKET_ERROR == retVal)
					{
						int err = WSAGetLastError();
						if (err == WSAEWOULDBLOCK)
						{
							Sleep(100);
							continue;
						}
						else
						{
							printf("send failed!\n");
							closesocket(sServer);
							closesocket(sClient);
							WSACleanup();
							return -1;
						}

					}
					ZeroMemory(sendData, BUF_SIZE);
					break;
				}
			}
		}//end if (_kbhit())

	}
	return 0;
}

int recvMessage()
{
	while (true)
	{
		ZeroMemory(buf, BUF_SIZE);
		retVal = recv(sClient, buf, BUFSIZ, 0);
		if (SOCKET_ERROR == retVal)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK)
			{
				Sleep(100);
				continue;
			}
			else if (err == WSAETIMEDOUT || err == WSAENETDOWN)
			{
				printf("recv failed!\n");
				closesocket(sServer);
				closesocket(sClient);
				WSACleanup();
				return -1;
			}
		}

			//��ȡϵͳʱ��
			SYSTEMTIME st;
			GetLocalTime(&st);
			char sDateTime[30];
			sprintf_s(sDateTime, "%4d-%2d-%2d %2d:%2d:%2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
			//��ӡ�����Ϣ
			printf("%s,Recv From Client [%s:%d]:%s\n", sDateTime, inet_ntoa(addrClient.sin_addr), addrClient.sin_port, buf);
			//����ͻ��˷��͡�quit���ַ�������������˳�
			if (strcmp(buf, "quit") == 0)
			{
				retVal = send(sClient, "quit", strlen("quit"), 0);
				break;
			}
			/*else
			{
				char msg[BUF_SIZE];
				sprintf_s(msg, "Message received - %s", buf);
				while (true)
				{
					retVal = send(sClient, msg, strlen(msg), 0);
					if (SOCKET_ERROR == retVal)
					{
						int err = WSAGetLastError();
						if (err == WSAEWOULDBLOCK)
						{
							Sleep(100);
							continue;
						}
						else
						{
							printf("send failed!\n");
							closesocket(sServer);
							closesocket(sClient);
							WSACleanup();
							return -1;
						}

					}
					break;
				}*/
	}
		
}

int main(int argc, char* argv[])
{
	

	ZeroMemory(sendData, sizeof(sendData));

	//��ʼ��Socket
	if (WSAStartup(MAKEWORD(2, 2), &wsd) != 0)
	{
		printf("WSAStartup failed!\n");
		return -1;
	}
	//�������ڼ�����Socket
	sServer = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sServer)
	{
		printf("socket failed!\n");
		WSACleanup();
		return -1;
	}
	//����SocketΪ������ģʽ
	int iMode = 1;
	retVal = ioctlsocket(sServer, FIONBIO, (u_long FAR*)&iMode);
	if (retVal == SOCKET_ERROR)
	{
		printf("ioctlsocket failed!\n");
		WSACleanup();
		return -1;
	}
	//���÷�����Socket��ַ
	
	addrServ.sin_family = AF_INET;
	addrServ.sin_port = htons(9990);
	addrServ.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	//��Socket Server�����ص�ַ
	retVal = bind(sServer, (const struct sockaddr*)&addrServ, sizeof(sockaddr_in));
	if (retVal == SOCKET_ERROR)
	{
		printf("bind failed!\n");
		closesocket(sServer);
		WSACleanup();
		return -1;
	}
	//����
	retVal = listen(sServer, 1);
	if (retVal == SOCKET_ERROR)
	{
		printf("listen failed!\n");
		closesocket(sServer);
		WSACleanup();
		return -1;
	}
	//���ܿͻ�����
	printf("TCP Server start...\n");
	//sockaddr_in addrClient;
	int addrClientlen = sizeof(addrClient);
	//ѭ���ȴ�
	while (true)
	{
		sClient = accept(sServer, (sockaddr FAR*)&addrClient, &addrClientlen);
		if (INVALID_SOCKET == sClient)
		{
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK)
			{
				Sleep(100);
				continue;
			}
			else
			{
				printf("accept failed!\n");
				closesocket(sServer);
				WSACleanup();
				return -1;
			}
		}
		break;

	}
	std::thread thread_send(sendMessage);
	std::thread thread_recv(recvMessage);
	//ѭ�����ܿͻ��˵����ݣ�ֱ���ͻ��˷���quit������˳�
	while (true)
	{
	//	ZeroMemory(buf, BUF_SIZE);
	//	retVal = recv(sClient, buf, BUFSIZ, 0);
	//	if (SOCKET_ERROR == retVal)
	//	{
	//		int err = WSAGetLastError();
	//		if (err == WSAEWOULDBLOCK)
	//		{
	//			Sleep(100);
	//			continue;
	//		}
	//		else if (err == WSAETIMEDOUT || err == WSAENETDOWN)
	//		{
	//			printf("recv failed!\n");
	//			closesocket(sServer);
	//			closesocket(sClient);
	//			WSACleanup();
	//			return -1;
	//		}
	//	}
	//	//��ȡϵͳʱ��
	//	SYSTEMTIME st;
	//	GetLocalTime(&st);
	//	char sDateTime[30];
	//	sprintf_s(sDateTime, "%4d-%2d-%2d %2d:%2d:%2d", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
	//	//��ӡ�����Ϣ
	//	printf("%s,Recv From Client [%s:%d]:%s\n", sDateTime, inet_ntoa(addrClient.sin_addr), addrClient.sin_port, buf);
	//	//����ͻ��˷��͡�quit���ַ�������������˳�
	//	if (strcmp(buf, "quit") == 0)
	//	{
	//		retVal = send(sClient, "quit", strlen("quit"), 0);
	//		break;
	//	}
	//	else
	//	{
	//		char msg[BUF_SIZE];
	//		sprintf_s(msg, "Message received - %s", buf);
	//		while (true)
	//		{
	//			retVal = send(sClient, msg, strlen(msg), 0);
	//			if (SOCKET_ERROR == retVal)
	//			{
	//				int err = WSAGetLastError();
	//				if (err == WSAEWOULDBLOCK)
	//				{
	//					Sleep(100);
	//					continue;
	//				}
	//				else
	//				{
	//					printf("send failed!\n");
	//					closesocket(sServer);
	//					closesocket(sClient);
	//					WSACleanup();
	//					return -1;
	//				}

	//			}
	//			break;
	//		}
		//}
	}

	//�ͷ�Socket
	closesocket(sServer);
	closesocket(sClient);
	WSACleanup();

	system("pause");
	return 0;
}