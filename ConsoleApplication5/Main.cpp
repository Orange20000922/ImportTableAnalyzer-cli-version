// ConsoleApplication5.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <string>
#include <vector>
#include <sstream>
#include "ImageTable.h"
#include "cli.h"
#include "cmd.h"
using namespace std;
string PrintAllCommand::name = "printallcommand -list";
string HelpCommand::name = "help |name";
string QueueDLLsCommand::name = "queuedllsname |file";
string GetProcessFuncAddressCommand::name = "getfuncaddr |file |name";
string IATHookDLLCommand::name = "IATHook |file |pid";
string ExitCommand::name = "exit";
string PrintAllFunction::name = "printallfunc |file";
string IATHookByNameCommand::name = "IATHook |file |name";
string IATHookByCreateProc::name = "IATHook |file |file";
int main()
{
	//CLI 初始化
	CLI cli = CLI();
	cout << "这里是Orange的系统文件分析工具，输入 'help ' 获取帮助信息。" << endl;
	cout << "version:0.1.0" << endl;
	// 命令循环
	while (true) {
		string command = string();
		cout << "Command> ";
		getline(cin, command);
		cli.Run(command);
	}
	return 0;
}
