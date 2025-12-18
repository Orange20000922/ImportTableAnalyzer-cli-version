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
int main()
{
    //TUI代码编写在此处
	CLI cli = CLI();
	cout << "这里是Orange的系统文件分析工具，输入 'help ' 获取帮助信息。" << endl;
	while (true) {
		string command = string();
		cout << "Command> ";
		getline(cin, command);
		cli.Run(command);
	}
	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
