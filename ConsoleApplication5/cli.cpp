#include "cli.h"
#include <iostream>
#include "ImageTable.h"
#include <string>
#include <queue>
#include <vector>
#include <Windows.h>
void CLI::Run(string command)
{
	queue<string> theargs = SplitString(command, ' ');
	ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
	vector<queue<string>> thecommands = GetCommands();
    int count = 0;
	int* sizes = new int[thecommands.size()+1];
	ZeroMemory(sizes, sizeof(int) * (thecommands.size() + 1));
    vector<int> lowersizes = vector<int>();
	vector<int> uppersizes = vector<int>();
	int middlesize = 0;
	int maxsize = 0;
    for (int i = 0; i < thecommands.size();i++) {
		sizes[i] = thecommands[i].size();
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
	maxsize = uppersizes[0];
    while (!theargs.empty()) {
        if (count<maxsize) {
            
        }
        count++;
    }
}
queue<string> CLI::SplitString(string& str, char delimiter)
{
    int count = 0;
    while(str.find(delimiter,count)!=string::npos){
		int index = str.find(delimiter, count);
        int tokenLength = index - count;
        char* token = new char[tokenLength+3];
        for (int i = count; i < str.find(delimiter, count) - count; i++) {
			token[i-count] = str.c_str()[i];
        }
        token[tokenLength] = '\0';
        count = str.find(delimiter, count) + 1;
		args.push(string(token));
        delete token;
    }
    return args;
}
void CLI::ParseCommands(string& command)
{
	commands = vector<queue<string>>();
	queue<string> cmdQueue = SplitString(command, ' ');
	commands.push_back(cmdQueue);
}
