#include "cli.h"
#include <iostream>
#include "ImageTable.h"
#include <string>
#include <queue>
#include <vector>
#include <Windows.h>
#include "climodule.h"
#include "cmd.h"
// 静态成员变量定义
vector<queue<string>> CLI::commands = vector<queue<string>>();
queue<string> CLI::args = queue<string>();
bool CLI::initialized = false;
void CLI::Run(string& command)
{
	queue<string> theargs = SplitString(command, ' ');
	vector<queue<string>> thecommands = GetCommands();
	vector<queue<string>> subcommands = vector<queue<string>>();
    int count = 0;
    int count1 = 0;
    int commandcount = 0;
	if (thecommands.empty()) {
		return;
	}
	int* sizes = new int[thecommands.size()+1];
	ZeroMemory(sizes, sizeof(int) * (thecommands.size() + 1));
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
                            argsinstances.push_back((LPVOID)new string(theargs.front()));
                        }
                        CloseHandle(hFile);
                    }
                    if (currentcommand.front().compare("|pid") == 0) {
                        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, stoi(theargs.front()));
                        if (hProcess != INVALID_HANDLE_VALUE) {
                            subcommands.push_back(tempcommand);
                            argsinstances.push_back((LPVOID)new string(theargs.front()));
                        }
                        CloseHandle(hProcess);
                    }
                    if (currentcommand.front().compare("|name") == 0) {
                        subcommands.push_back(tempcommand);
                        cout << theargs.front() << endl;
                        argsinstances.push_back((LPVOID)new string(theargs.front()));
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
            thecommands[0].pop();
        }
		
		CLIModule* climodule = new CLIModule();
		LPVOID commandclassptr = climodule->GetModuleClassPtrByName(currectcommandname);
        if (commandclassptr==0) {
			cout << "Command class pointer is null." << endl;
        }
        if (commandclassptr != nullptr) {
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
        }
        delete climodule;
    }
    argsinstances.clear();
    delete[] sizes;
}
queue<string> CLI::SplitString(string& str, char delimiter)
{
	queue<string> theargs = queue<string>();
    int count = 0;
    while(str.find(delimiter,count)!=string::npos){
		int index = str.find(delimiter, count);
        int tokenLength = index - count;
		string token = string();
		token = str.substr(count, tokenLength);
        count = str.find(delimiter, count) + 1;
		theargs.push(string(token));
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
         initialized = true;
     }
 }
 CLI::~CLI()
 {
     delete analyzer;
 }
