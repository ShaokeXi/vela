#include "backends/traffic_analysis/traffic_digest.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <arpa/inet.h>

namespace P4 {

std::string intIpToString(uint32_t ip_int) {
    struct in_addr addr;
    addr.s_addr = htonl(ip_int);
    char ip_str[INET_ADDRSTRLEN];

    const char* result = inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);

    if (result != nullptr) {
        return std::string(ip_str);
    } else {
        return "";
    }
}

// Alternative manual conversion if inet_ntop is not suitable/available
/*
std::string intIpToStringManual(uint32_t ip_int) {
    std::stringstream ss;
    ss << ((ip_int >> 24) & 0xFF) << "."
       << ((ip_int >> 16) & 0xFF) << "."
       << ((ip_int >> 8) & 0xFF) << "."
       << (ip_int & 0xFF);
    return ss.str();
}
*/

std::vector<TrafficRecord> parseTrafficTrace(const std::string &filename) {
    std::vector<TrafficRecord> records;
    std::ifstream infile(filename);
    std::string line;
    int lineNum = 0;

    if (!infile.is_open()) {
        throw TrafficParseException("Could not open traffic trace file: " + filename);
    }

    std::cerr << "Parsing traffic trace: " << filename << std::endl;

    while (std::getline(infile, line)) {
        lineNum++;
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::stringstream ss(line);
        TrafficRecord record;
        std::string srcIpIntStr, dstIpIntStr;

        if (!(ss >> record.timestamp >> record.pktLen >> srcIpIntStr >> dstIpIntStr >>
              record.srcPort >> record.dstPort >> record.protocol /* >> ignored_flowid - if present */)) {
            if (ss.eof() && !srcIpIntStr.empty()) { 
            } else {
                 std::cerr << "Warning: Malformed line " << lineNum << ": " << line << std::endl;
                 continue;
            }
        }

        // Convert IP integer strings to uint32_t, then to dot-decimal string
        try {
            // Assuming base 10 for the integer strings in the file
            uint32_t srcIpInt = std::stoul(srcIpIntStr);
            uint32_t dstIpInt = std::stoul(dstIpIntStr);

            record.srcIP = intIpToString(srcIpInt);
            record.dstIP = intIpToString(dstIpInt);

            if (record.srcIP.empty() || record.dstIP.empty()) {
                std::cerr << "Warning: Skipping line " << lineNum << " due to IP conversion error." << std::endl;
                continue;
            }

        } catch (const std::invalid_argument& ia) {
            std::cerr << "Warning: Skipping line " << lineNum << " due to non-integer IP string: '" 
                      << srcIpIntStr << "' or '" << dstIpIntStr << "'. Error: " << ia.what() << std::endl;
            continue;
        } catch (const std::out_of_range& oor) {
            std::cerr << "Warning: Skipping line " << lineNum << " due to out-of-range IP integer: '" 
                      << srcIpIntStr << "' or '" << dstIpIntStr << "'. Error: " << oor.what() << std::endl;
            continue;
        }

        records.push_back(record);
    }

    infile.close();
    std::cerr << "Parsed " << records.size() << " traffic records." << std::endl;
    return records;
}

ControlPlaneRules parseControlPlaneRules(const std::string &filename) {
    ControlPlaneRules rules;
    std::ifstream infile(filename);
    std::string line;
    int lineNum = 0;

    if (!infile.is_open()) {
        throw TrafficParseException("Could not open control plane rules file: " + filename);
    }

    std::cerr << "Parsing control plane rules: " << filename << std::endl;

    while (std::getline(infile, line)) {
        lineNum++;
        if (line.empty() || line[0] == '#') {
            continue;
        }

        std::stringstream ss(line);
        std::string srcIpKey, dipValue;

        if (!(ss >> srcIpKey >> dipValue)) {
             std::cerr << "Warning: Malformed rule line " << lineNum << ": " << line << std::endl;
             continue;
        }

        rules[srcIpKey] = dipValue;
    }

    infile.close();
    std::cerr << "Parsed " << rules.size() << " control plane rules." << std::endl;
    return rules;
}

} // namespace P4 