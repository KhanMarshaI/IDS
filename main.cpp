#include <iostream>
#include <list>
#include <algorithm>
#include <string>
#include <cctype>
#include <unordered_map> 
#include <ctime>
#include <regex>
using namespace std;

string eventSevereLevel(string s) {
	//Built in Hash Table
	unordered_map<string, string> umap;
	umap["failed_login_attempts"] = "Moderate";
	umap["application_access_denied"] = "Moderate";
	umap["port_scan"] = "Severe";
	umap["suspicious_extension"] = "Moderate";
	umap["blacklisted_IP_address"] = "Severe";
	umap["unusual_activity"] = "Severe";
	umap["unauthorized_IP_address"] = "Severe";
	umap["unusual termination for active user"] = "Extremely Severe";
	umap["log integrity check failed"] = "Extremely Severe";
	umap["DoS_attack"] = "Critical";
}

string extractIPAdd(string s) {
	string pattern = "\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b";
	string IP_Add;
	regex expression(pattern);
	smatch match;

	if (regex_search(s, match, expression)) {
		IP_Add = match.str(); //method of smatch class, allows access of matched substring as a string
	}
	return IP_Add;
}

class logData {
public:
	string eventName, eventSeverity, sourceIP,protocol;
	time_t eventTime;
	int source_port;
	int destination_port;
	logData(string log) {
		//eventName = eN;
		//eventSeverity = eventSevereLevel(eventName);
		sourceIP = extractIPAdd(log);
	}

	void display() {
		cout << "Source IP = " << sourceIP << endl;
	}
};

class hashTable {
	list<logData>* hash;
	int size;
public:
	hashTable() {
		size = 10;
		hash = new list<logData>[size];
	}

	const int chars = 256; //Number of chars in input
	const int p = 11; //any prime number
	int hashFunction(logData l) {
		int bucket = 0;
		int len = l.eventName.length();
		for (int i = 0; i < len; i++) {
			bucket = ( bucket * chars + tolower(l.eventName[i]) ) % p;
		}
		return (bucket + p) % p;
	}

	void insert(string log) {
		
	}
};

int main() {
	logData l("Authentication failure : User 'admin' failed to log in from IP address 192.168.1.10.");
	l.display();
	/*hashTable h;
	cout << h.hashFunction(l) << endl;
	cout << h.hashFunction(l1) << endl;*/
}