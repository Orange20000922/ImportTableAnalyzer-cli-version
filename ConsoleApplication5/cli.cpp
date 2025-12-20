#include "cli.h"
#include <iostream>
#include "ImageTable.h"
#include <string>
#include <queue>
#include <vector>
#include <Windows.h>
#include "climodule.h"
#include "cmd.h"
#include <sstream>
// 静态成员变量定义
vector<queue<string>> CLI::commands = vector<queue<string>>();
queue<string> CLI::args = queue<string>();
bool CLI::initialized = false;
void CLI::Run(string& command)
{
	//解析命令
	queue<string> theargs = SplitString(command, ' ');
	queue<string> theargsCopy = theargs; // 保存参数副本用于后续处理
	vector<queue<string>> thecommands = GetCommands();
	vector<queue<string>> subcommands = vector<queue<string>>();
    int count1 = 0;
	if (thecommands.empty()) {
		return;
	}
    while (!theargs.empty()) {   
        for (auto currentcommand : thecommands) {
            queue<string> tempcommand = currentcommand;
            if (currentcommand.size() >= 2) {
                for (int i = 0; i < count1; i++) {
                    currentcommand.pop();
                }
            }
            if (currentcommand.front().compare(theargs.front()) == 0) {
                subcommands.push_back(tempcommand);
            }
            else {
                if (currentcommand.front().find('|') != string::npos) {
                    if (currentcommand.front().compare("|file") == 0) {
                        HANDLE hFile = CreateFileA(theargs.front().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            subcommands.push_back(tempcommand);
                            CloseHandle(hFile);
                        }
                    }
                    if (currentcommand.front().compare("|pid") == 0) {
                        try {
                            int pid = stoi(theargs.front());
                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
                            if (hProcess != NULL) {
                                subcommands.push_back(tempcommand);
                                CloseHandle(hProcess);
                            }
                        }
                        catch (std::invalid_argument&) {
                            cout << "invalid argument for PID" << endl;
                        }
                        catch (std::out_of_range&) {
                            cout << "PID out of range" << endl;
                        }
                    }
                    if (currentcommand.front().compare("|name") == 0) {
                        HANDLE hFile = CreateFileA(theargs.front().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                        if (hFile==INVALID_HANDLE_VALUE) {
                            subcommands.push_back(tempcommand);
                            argsinstances.push_back((LPVOID)new string(theargs.front()));
                        }
                        else {
                            CloseHandle(hFile);
                        }
                    }
                }
            }
        }
          if (thecommands.size()!=1) {
              thecommands.clear();
              for (queue<string> command : subcommands) {
                  thecommands.push_back(command);
              }
              subcommands.clear();
          }
		theargs.pop();
        count1++;
    }
    if (thecommands.size()==1) {
		string currectcommandname = string();
        while (!thecommands[0].empty()) {
            if (!currectcommandname.empty()) {
                currectcommandname += " ";
            }
            currectcommandname += thecommands[0].front();
            if (thecommands[0].front().find('|') != string::npos && !theargsCopy.empty()) {
                if (thecommands[0].front().compare("|file") == 0) {
                    argsinstances.push_back((LPVOID)new string(theargsCopy.front()));
                }
                if (thecommands[0].front().compare("|pid") == 0) {
                    argsinstances.push_back((LPVOID)new string(theargsCopy.front()));
                }
                if (thecommands[0].front().compare("|name") == 0) {
                    argsinstances.push_back((LPVOID)new string(theargsCopy.front()));
                }
            }
            if (!theargsCopy.empty()) {
                theargsCopy.pop();
            }
            thecommands[0].pop();
        }  
		CLIModule* climodule = new CLIModule();
		LPVOID commandclassptr = climodule->GetModuleClassPtrByName(currectcommandname);
        if (commandclassptr==0) {
			cout << "Command class pointer is null." << endl;
        }
        if (commandclassptr != nullptr) {
			// 根据命令名称执行相应的命令
            if (PrintAllCommand::CheckName(currectcommandname)&&climodule->GetModuleFlagByName(currectcommandname)) {
				PrintAllCommand* printallcommand = (PrintAllCommand*)commandclassptr;
                printallcommand->Execute(currectcommandname);
            }
            if (HelpCommand::CheckName(currectcommandname) && climodule->GetModuleFlagByName(currectcommandname)) {
                HelpCommand* helpcommand = (HelpCommand*)commandclassptr;
				helpcommand->AcceptArgs(argsinstances);
                helpcommand->Execute(currectcommandname);
            }
            if (QueueDLLsCommand::CheckName(currectcommandname) && climodule->GetModuleFlagByName(currectcommandname)) {
				QueueDLLsCommand* queuedllscommand = (QueueDLLsCommand*)commandclassptr;
                queuedllscommand->AcceptArgs(argsinstances);
                queuedllscommand->Execute(currectcommandname);
            }
            if (GetProcessFuncAddressCommand::CheckName(currectcommandname) && climodule->GetModuleFlagByName(currectcommandname)) {
                GetProcessFuncAddressCommand* getprocessfuncaddresscommand = (GetProcessFuncAddressCommand*)commandclassptr;
                getprocessfuncaddresscommand->AcceptArgs(argsinstances);
                getprocessfuncaddresscommand->Execute(currectcommandname);
            }
            if (ExitCommand::CheckName(currectcommandname) && climodule->GetModuleFlagByName(currectcommandname)) {
				ExitCommand* exitcommand = (ExitCommand*)commandclassptr;
				exitcommand->Execute(currectcommandname);
            }
            if (IATHookDLLCommand::CheckName(currectcommandname)&&climodule->GetModuleFlagByName(currectcommandname)) {
                IATHookDLLCommand* iathookcommand = (IATHookDLLCommand*)commandclassptr;
                iathookcommand->AcceptArgs(argsinstances);
                iathookcommand->Execute(currectcommandname);
            }
            if (PrintAllFunction::CheckName(currectcommandname)&&climodule->GetModuleFlagByName(currectcommandname)) {
                PrintAllFunction* printfunccommand = (PrintAllFunction*)commandclassptr;
                printfunccommand->AcceptArgs(argsinstances);
                printfunccommand->Execute(currectcommandname);
            }
            if (IATHookByCreateProc::CheckName(currectcommandname)&&climodule->GetModuleFlagByName(currectcommandname)) {
				IATHookByCreateProc* iathookbycreateproccommand = (IATHookByCreateProc*)commandclassptr;
                iathookbycreateproccommand->AcceptArgs(argsinstances);
				iathookbycreateproccommand->Execute(currectcommandname);
            }
        }
        delete climodule;
    }
    else {
		cout << "Command not found or ambiguous command." << endl;
    }
	// 清理参数实例 - 释放动态分配的string对象
    for (LPVOID ptr : argsinstances) {
        delete (string*)ptr;
    }
    argsinstances.clear();
}
queue<string> CLI::SplitString(string& str, char delimiter)
{
	queue<string> theargs = queue<string>();
    int count = 0;
    while(str.find(delimiter,count)!=string::npos){
		int index = str.find(delimiter, count);
        int tokenLength = index - count;
        if (tokenLength>0) {
            string token = string();
            token = str.substr(count, tokenLength);
            count = str.find(delimiter, count) + 1;
            theargs.push(string(token));
        }
        else {
            break;
        }
    }
	theargs.push(string(str.substr(count, str.length() - count)));
    return theargs;
}
 void CLI::ParseCommands(string& thecommand,LPVOID instanceptr)
{
	queue<string> cmdQueue = SplitString(thecommand, ' ');
	commands.push_back(cmdQueue);
	CLIModule::RegisterModule(thecommand, (LPVOID)instanceptr, TRUE);
}
 CLI::CLI()
 {
     if (!initialized) {
         ParseCommands(PrintAllCommand::name,PrintAllCommand::GetInstancePtr());
         ParseCommands(HelpCommand::name, HelpCommand::GetInstancePtr());
         ParseCommands(QueueDLLsCommand::name, QueueDLLsCommand::GetInstancePtr());
         ParseCommands(GetProcessFuncAddressCommand::name, GetProcessFuncAddressCommand::GetInstancePtr());
         ParseCommands(ExitCommand::name, ExitCommand::GetInstancePtr());
         ParseCommands(IATHookDLLCommand::name,IATHookDLLCommand::GetInstancePtr());
         ParseCommands(IATHookByNameCommand::name,IATHookByNameCommand::GetInstancePtr());
         ParseCommands(PrintAllFunction::name,PrintAllFunction::GetInstancePtr());
		 ParseCommands(IATHookByCreateProc::name, IATHookByCreateProc::GetInstancePtr());
         initialized = true;
     }
 }
 CLI::~CLI()
 {
	 CLIModule::UnregisterModules();
     delete analyzer;
 }
