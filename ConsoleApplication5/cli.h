#pragma once
#include <string>
#include <queue>
#include <vector>
#include <Windows.h>
using namespace std;
class CLI
{
private:
	vector<queue<string>> commands = vector<queue<string>>();
	queue<string> args = queue<string>();
	public:
		void Run(string command);
    private:
		queue<string> SplitString(string& str, char delimiter);
		void ParseCommands(string& commmand);
		vector<queue<string>> GetCommands() { return commands; };
};