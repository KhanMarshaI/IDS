#include "stdafx.h"
using namespace std;

enum severity { None = 0, Low = 1, Moderate = 2, Severe = 3, Critical = 4 };
severity eventSevereLevel(string s) {
	//Built in Hash Table
	
	unordered_map<string, severity> umap;
	umap["Authentication failure"] = Moderate;
	umap["Access denied"] = Moderate;
	umap["Network intrusion detected"] = Severe;
	umap["Suspicious activity"] = Moderate;
	umap["Security alert"] = Severe;
	umap["Anomalous behavior"] = Severe;
	umap["Unauthorized access attempt"] = Moderate;
	umap["Security breach"] = Critical;
	umap["Denial of Service (DoS) attack detected"] = Critical;
	umap["Login failure"] = Moderate;
	umap["ERROR"] = Low;
	umap["DEBUG"] = None;
	umap["INFO"] = None;
	umap["WARNING"] = None;

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

time_t parseTime(string& timestamp) {
	std::tm tm = { 0 };  // Initialize tm structure to zero
	std::istringstream ss(timestamp);
	ss >> std::get_time(&tm, "%Y-%m-%d %H:%M:%S");  // Parse the string into tm structure

	if (ss.fail()) {
		throw runtime_error("Failed to parse time");
	}

	return mktime(&tm);  // Convert tm structure to time_t
}

string formatTime(time_t time) {
	char buffer[26];
	ctime_s(buffer, sizeof(buffer), &time);
	return string(buffer);
}

string extractEventName(string s, time_t& time) {
	// Combine timestamp and event name patterns
	regex timestamp_pattern(R"((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}))");
	smatch match;

	if (regex_search(s, match, timestamp_pattern)) {
		string t = match[1].str();
		time = parseTime(t);
		s = s.substr(match.position() + match.length()); // String after timestamp
	}

	size_t colonPos = s.find(":");
	if (colonPos != string::npos) {
		// Find the first non-timestamp character before the colon
		size_t startPos = s.find_first_not_of("0123456789:- ", 0);
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
	string eventName, protocol;
	severity eventSeverity;
	time_t eventTime;
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

	string intToSeverity(severity e) {
		switch (e) {
		case 0:
			return "None";
			break;
		case 1:
			return "Low";
			break;
		case 2: 
			return "Moderate";
			break;
		case 3:
			return "Severe";
			break;
		case 4:
			return "Critical";
			break;
		default:
			return "";
			break;
		}
	}

	void display() {
		cout << "Timestamp = " << formatTime(eventTime); // ctime function does \n on its own
		cout << "Event Name = " << eventName << endl;
		cout << "Event Severity = " << intToSeverity(eventSeverity) << endl;
		cout << "Source IP = " << sourceIP << endl;
		cout << "Destination IP = " << destIP << endl;
		cout << "Protocol = " << protocol << endl;
		cout << "Source Port = " << source_port << endl;
		cout << "Destination Port = " << destination_port << endl << endl;
	}
};

class hashTable {
	list<logData>* hash;
	int size;
	int count;
	int low_c, mod_c, sev_c, crit_c, none_c;
public:
	hashTable() {
		size = 14;
		hash = new list<logData>[size];
	}

	~hashTable() {
		delete[] hash;
	}

	const int chars = 256; //Number of chars in input
	const int p = 14; // same as size only used in hashFunction
	// making p = size will crash the program
	int hashFunction(logData l) {
		int bucket = 0;
		int len = l.eventName.length();
		for (int i = 0; i < len; i++) {
			bucket = ( bucket * chars + tolower(l.eventName[i]) ) % p;
		}
		return (bucket + p) % p;
	}

	int hashFunction(string s) {
		int bucket = 0;
		int len = s.length();
		for (int i = 0; i < len; i++) {
			bucket = (bucket * chars + tolower(s[i])) % p;
		}
		return (bucket + p) % p;
	}

	void insert(logData log) {
		int idx = hashFunction(log);
		hash[idx].push_back(log);
		count++;
	}

	void display() {
		if (hash->empty()) {
			cout << "Empty Table" << endl;
			return;
		}
		for (int i = 0; i < size; i++) {
			cout << i << ": ";
			for (auto it = hash[i].begin(); it != hash[i].end(); it++) {
				cout << it->eventName << ", ";
			}
			cout << endl;
		}
	}

	void searchByName() {
		string en;
		cout << "Enter event name (case-sensitive): ";
		getline(cin >> ws, en);
		int idx = hashFunction(en);
		for (auto it = hash[idx].begin(); it != hash[idx].end(); it++) {
			if (it->eventName.compare(en) == 0) {
				it->display();
			}
		}
	}

	void searchBySeverity() {
		int s;
		cout << "Enter Severity: (0-4)";
		cin >> s;

		for (int i = 0; i < size; i++) {
			for (auto it = hash[i].begin(); it != hash[i].end(); it++) {
				if (it->eventSeverity == s) {
					it->display();
				}
			}
		}
	}

	void displayAll() {
		if (hash->empty()) {
			cout << "Empty Table" << endl;
			return;
		}
		for (int i = 0; i < size; i++) {
			for (auto it = hash[i].begin(); it != hash[i].end(); it++) {
				it->display();
			}
		}
	}
	
	int partition(vector<logData>& arr, int low, int high)
	{
		int pivot = arr[high].eventSeverity;
		int i = (low - 1);

		for (int j = low; j <= high; j++)
		{
			if (arr[j].eventSeverity > pivot)
			{
				i++;
				swap(arr[i], arr[j]);
			}
		}
		swap(arr[i + 1], arr[high]);
		return (i + 1);
	}


	void quickSort(vector<logData>& arr, int low, int high)
	{
		if (low < high)
		{
			int pi = partition(arr, low, high);
			quickSort(arr, low, pi - 1);
			quickSort(arr, pi + 1, high);
		}
	}

	void sortBySeverity(vector<logData>& v) {
		if (v.empty()) return;
		/*for (int i = 0; i < v.size(); i++) {
			for (int j = i + 1; j < v.size(); j++) {
				if (v[i].eventSeverity > v[j].eventSeverity) {
					swap(v[i], v[j]);
				}
			}
		}*/
		quickSort(v, 0, v.size() - 1);
	}

	void updateEventCount() {
		for (int i = 0; i < size; i++) {
			for (auto it = hash[i].begin(); it != hash[i].end(); it++) {
				switch (it->eventSeverity) {
				case 0:
					none_c++;
					break;
				case 1:
					low_c++;
					break;
				case 2:
					mod_c++;
					break;
				case 3:
					sev_c++;
					break;
				case 4:
					crit_c++;
					break;
				default:
					break;
				}
			}
		}
	}

	void summarize() {
		updateEventCount();
		cout << "Total number of events: " << count << endl;
		cout << "Critical Events: " << crit_c << "\t" << "Severe Events: " << sev_c << "\t" << "Moderate Events: " << mod_c
			<< "\t" << "Low Events: " << low_c << "\t" << "None Events: " << none_c << endl;
	}
};

vector<logData> readLogs() {
	string line;
	string path;
	vector<logData> logs;

	cout << "Enter path to read logs from (including file name): ";
	cin >> path;
	int len = path.length();
	if (!path.empty() && path[0] == '"' && path[len-1] == '"') {
		path = path.substr(1, path.size() - 2);
	}

	ifstream file(path);
	if (!file.is_open()) {
		cout << "Fail to open file" << endl;
		return logs;
	}
	while (getline(file, line)) {
		logData l(line);
		logs.push_back(l);
	}

	file.close();
	return logs;
}

void displayVecLogs(vector<logData>& log) {
	for (int i = 0; i < log.size(); i++) {
		log[i].display();
	}
}

hashTable vecToHTable(vector<logData>& v) {
	hashTable h;
	for (int i = 0; i < v.size(); i++) {
		h.insert(v[i]);
	}
	return h;
}

void menu() {
	cout << "Marshal's Intrusion Detection System - V1.0" << endl;
	vector<logData> logs = readLogs();
	hashTable h = vecToHTable(logs);

	int choice;
	while (1) {
		system("cls");
		cout << "Marshal's Intrusion Detection System - V1.0" << endl;
		cout << "Select the operation to perform." << endl;
		cout << "1. Display Raw Hash Table." << endl;
		cout << "2. Display All Network Events." << endl;
		cout << "3. Sort Network Events. (By Severity)" << endl;
		cout << "4. Display sorted Network Events." << endl;
		cout << "5. Search Network Events By Name." << endl;
		cout << "6. Search Network Events By Severity." << endl;
		cout << "7. Summarize." << endl;
		cout << "8. Exit." << endl;
		cin >> choice;
		switch (choice) {
		case 1:
			system("cls"); //same as running cls on terminal
			h.display();
			_getch(); //mvsc compiler produces error on getch so prefix it with "_"
			break;
		case 2:
			system("cls");
			h.displayAll();
			_getch();
			break;
		case 3:
			system("cls");
			h.sortBySeverity(logs);
			cout << "Sorted." << endl;
			_getch();
			break;
		case 4:
			system("cls");
			displayVecLogs(logs);
			_getch();
			break;
		case 5:
			system("cls");
			h.searchByName();
			_getch();
			break;
		case 6:
			system("cls");
			h.searchBySeverity();
			_getch();
			break;
		case 7:
			system("cls");
			h.summarize();
			_getch();
			break;
		case 8:
			cout << "Exiting..." << endl;
			return;
		default:
			cout << "Incorrect choice." << endl;
			break;
		}
	}
}

int main() {
	menu();
}