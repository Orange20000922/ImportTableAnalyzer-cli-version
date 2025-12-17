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
void CLI::Run(string& command)
{
	queue<string> theargs = SplitString(command, ' ');
	vector<queue<string>> thecommands = GetCommands();
    vector<queue<string>>::iterator it = thecommands.begin();
	vector<queue<string>> subcommands = vector<queue<string>>();
	vector<queue<string>>::iterator sit = subcommands.begin();
	vector<LPVOID> argsinstances = vector<LPVOID>();
    int count = 0;
    int commandcount = 0;

	if (thecommands.empty()) {
		return;
	}

	int* sizes = new int[thecommands.size()+1];
	ZeroMemory(sizes, sizeof(int) * (thecommands.size() + 1));
    vector<int> lowersizes = vector<int>();
	vector<int> uppersizes = vector<int>();
	int middlesize = 0;
	int maxsize = 0;
    for (size_t i = 0; i < thecommands.size(); i++) {
		sizes[i] = (int)thecommands[i].size();
        middlesize = sizes[0];
        if (sizes[i]>=middlesize) {
			uppersizes.push_back(sizes[i]);
        }
        else {
			lowersizes.push_back(sizes[i]);
        }
    }
    while (uppersizes.size()>1) {
		middlesize = uppersizes[0];
        lowersizes.clear();
        uppersizes.clear();
        if (sizes[count] >= middlesize) {
            uppersizes.push_back(sizes[count]);
        }
        else {
            lowersizes.push_back(sizes[count]);
        }
        count++;
    }

	// 检查越界
	if (uppersizes.empty()) {
		delete[] sizes;
		return;
	}
	maxsize = uppersizes[0];
    while (!theargs.empty()) {
        if (count<maxsize) {
          while (it != thecommands.end()) {
              queue<string> currentcommand = *it;
			  queue<string> tempcommand = currentcommand;
              for (int i = 0; i < count; i++) {
				  currentcommand.pop();
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
                              argsinstances.push_back((LPVOID)&theargs.front());
                          }
                          CloseHandle(hFile);
                      }
                      if (currentcommand.front().compare("|pid") == 0) {
                          HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, stoi(theargs.front()));
                          if (hProcess != INVALID_HANDLE_VALUE) {
                              subcommands.push_back(tempcommand);
                              argsinstances.push_back((LPVOID)&theargs.front());
                          }
                          CloseHandle(hProcess);
                      }
                      if (currentcommand.front().compare("|name")==0) {
                          subcommands.push_back(tempcommand);
                          argsinstances.push_back((LPVOID)&theargs.front());
                      }
                  }
              }
              it++;
           }
		  thecommands = subcommands;
		  subcommands.clear();
        }
		theargs.pop();
        count++;
    }
    if (thecommands.size()==1) {
		string currectcommandname = string();
        while (!thecommands[0].empty()) {
            currectcommandname += thecommands[0].front() + " ";
            thecommands[0].pop();
        }
		CLIModule* climodule = new CLIModule();
		LPVOID commandclassptr = climodule->GetModuleClassPtrByName(currectcommandname);
        if (commandclassptr != nullptr) {
            if (PrintAllCommand::CheckName(currectcommandname)&&climodule->GetModuleFlagByName(currectcommandname)) {
				PrintAllCommand* printallcommand = (PrintAllCommand*)commandclassptr;
                printallcommand->Execute(currectcommandname);
            }
            if (HelpCommand::CheckName(currectcommandname) && climodule->GetModuleFlagByName(currectcommandname)) {
                HelpCommand* helpcommand = (HelpCommand*)commandclassptr;
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
    }
    delete[] sizes;
}
queue<string> CLI::SplitString(string& str, char delimiter)
{
    int count = 0;
    while(str.find(delimiter,count)!=string::npos){
		int index = str.find(delimiter, count);
        int tokenLength = index - count;
		string token = string();
		token = str.substr(count, tokenLength);
        count = str.find(delimiter, count) + 1;
		args.push(string(token));
    }
	args.push(string(str.substr(count, str.length() - count)));
    return args;
}
 void CLI::ParseCommands(string& command,LPVOID instanceptr)
{
	queue<string> cmdQueue = SplitString(command, ' ');
	commands.push_back(cmdQueue);
	CLIModule::RegisterModule(command, (LPVOID)instanceptr, TRUE);
}
 CLI::CLI()
 {
     ParseCommands(PrintAllCommand::name,PrintAllCommand::GetInstancePtr());
	 ParseCommands(HelpCommand::name, HelpCommand::GetInstancePtr());
	 ParseCommands(QueueDLLsCommand::name, QueueDLLsCommand::GetInstancePtr());
	 ParseCommands(GetProcessFuncAddressCommand::name, GetProcessFuncAddressCommand::GetInstancePtr());
	 ParseCommands(ExitCommand::name, ExitCommand::GetInstancePtr());
 }
 CLI::~CLI()
 {
     delete analyzer;
 }
