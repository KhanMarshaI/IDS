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
	umap["ERROR"] = "Low";
	umap["DEBUG"] = "None";
	umap["INFO"] = "None";
	umap["WARNING"] = "None";

	return umap[s];
}

void extractIPAdd(string s, string& sIP, string& dIP) {
	regex pattern(R"(\b(?:\d{1,3}\.){3}\d{1,3}\b)");
	smatch match;

	while (regex_search(s, match, pattern)) {
		sIP = match[0];
		s = match.suffix().str();  // Update string to ignore preceding elements
		if (regex_search(s, match, pattern)) {
			dIP = match[0];
		}
		break;
	}
}

//string extractEventName(string s) {
//	size_t colonPos = s.find(":"); //returns index
//	if (colonPos != string::npos) { //index isn't invalid
//		string res = s.substr(0, colonPos);
//		if (res != "ERROR" && res != "WARNING" && res != "INFO" && res != "DEBUG") return res;
//	}
//	return "";
//}

string extractEventName(string s, string& time) {
	// Combine timestamp and event name patterns
	regex timestamp_pattern(R"(\*\*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\*\*)");
	smatch match;

	if (regex_search(s, match, timestamp_pattern)) {
		time = match[1].str();
		s = s.substr(match.position() + match.length()); // String after timestamp
	}

	size_t colonPos = s.find(":");
	if (colonPos != string::npos) {
		// Find the first non-timestamp character before the colon
		size_t startPos = s.find_first_not_of("**0123456789:- ", 0);
		if (startPos < colonPos) {
			return s.substr(startPos, colonPos - startPos); // Extract event name excluding timestamp
		}
	}
	return "";
}

void extractEventProtocol(string s, string& protocol, string& sourcePort, string& destPort) {
	regex pattern(R"((TCP|UDP)\s+(\d+(-\d+)?)\s+(\d+(-\d+)?))");
	smatch match;

	if (regex_search(s, match, pattern)) {
		protocol = match[1].str();                
		sourcePort = match[2].str();        
		destPort = match[4].str(); 
	}
	else {
		protocol = "";
		sourcePort = "";
		destPort = "";
	}
}

class logData {
public:
	string eventName, eventSeverity, protocol;
	string eventTime;
	string source_port;
	string destination_port;
	string sourceIP;
	string destIP;
	logData(string log) {
		eventName = extractEventName(log, eventTime);
		if (eventName == "") return; //avoid calling functions
		eventSeverity = eventSevereLevel(eventName);
		extractIPAdd(log, sourceIP, destIP);
		extractEventProtocol(log, protocol, source_port, destination_port);
	}

	void display() {
		cout << "Timestamp = " << eventTime << endl;
		cout << "Event Name = " << eventName << endl;
		cout << "Event Severity = " << eventSeverity << endl;
		cout << "Source IP = " << sourceIP << endl;
		cout << "Destination IP = " << destIP << endl;
		cout << "Protocol = " << protocol << endl;
		cout << "Source Port = " << source_port << endl;
		cout << "Destination Port = " << destination_port << endl;
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
	logData l("**2024-05-16 02:31:00** INFO: System update installed. Version: 2.1.0 127.0.0.1 127.0.0.1 TCP 22 54321");
	l.display();
	/*hashTable h;
	cout << h.hashFunction(l) << endl;
	cout << h.hashFunction(l1) << endl;*/
}