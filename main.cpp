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
	umap["Authentication failure"] = "Moderate";
	umap["Access denied"] = "Moderate";
	umap["Network intrusion detected"] = "Severe";
	umap["Suspicious activity"] = "Moderate";
	umap["Security alert"] = "Severe";
	umap["Anomalous behavior"] = "Severe";
	umap["Unauthorized access attempt"] = "Moderate";
	umap["Security breach"] = "Extremely Severe";
	umap["Denial of Service (DoS) attack detected"] = "Critical";
	umap["Login failure"] = "Moderate";

	return umap[s];
}

void extractIPAdd(string s, string*& sIP, string*& dIP) {
	regex pattern(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
	smatch match;

	while (regex_search(s, match, pattern)) {
		if (sIP) {
			sIP = new string(match[0]);
		}
		s = match.suffix().str();  // Update string to ignore preceding elements
		if (regex_search(s, match, pattern)) {
			if (dIP) {
				dIP = new string(match[0]);
			}
		}
		break;
	}
}

string extractEventName(string s) {
	size_t colonPos = s.find(":");
	if (colonPos != string::npos) {
		return s.substr(0, colonPos);
	}
	return "";
}

class logData {
public:
	string eventName, eventSeverity, protocol;
	time_t eventTime;
	int source_port;
	int destination_port;
	string* sourceIP;
	string* destIP;
	logData(string log) {
		eventName = extractEventName(log);
		eventSeverity = eventSevereLevel(eventName);
		sourceIP = new string;
		destIP = new string;
		extractIPAdd(log, sourceIP, destIP);
	}

	void display() {
		cout << "Event Name = " << eventName << endl;
		cout << "Event Severity = " << eventSeverity << endl;
		cout << "Source IP = " << *sourceIP << endl;
		cout << "Destination IP = " << *destIP << endl;
	}
	
	~logData() {
		delete sourceIP;
		delete destIP;
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
	logData l("Authentication failure: User 'admin' failed to log in from IP address 192.168.1.10 192.168.1.20 TCP 22 54321");
	l.display();
	/*hashTable h;
	cout << h.hashFunction(l) << endl;
	cout << h.hashFunction(l1) << endl;*/
}