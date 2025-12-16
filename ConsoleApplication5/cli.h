#pragma once
#include <string>
#include <queue>
#include <vector>
#include <Windows.h>
#include "ImageTable.h"
using namespace std;
class CLI
{
private:
    static  vector<queue<string>> commands ;
	static  queue<string> args;
	ImageTableAnalyzer* analyzer = new ImageTableAnalyzer();
	public:
		void Run(string& command);
		static queue<string> SplitString(string& str, char delimiter);
	    static void ParseCommands(string& commmand,LPVOID instanceptr);
		static vector<queue<string>> GetCommands() { return commands; };
public:
	CLI();
	~CLI();
};