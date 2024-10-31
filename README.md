# PRODIGY_CS_05

Develop a packet sniffer tool that captures and analyzes network packets. Display relevant information such as source and destination IP addresses, protocols, and payload data. Ensure the ethical use of the tool for educational purposes.

install scapy if you haven’t already:

pip install scapy

Explanation:

Packet Filtering and Capture: The sniff function captures packets using the IP filter and processes each one with packet_callback. The count=10 limits the capture to 10 packets for testing purposes.

Packet Analysis:

IP Information: If the packet has an IP layer, it extracts source and destination IPs.

Protocol Detection: Identifies TCP or UDP packets and fetches their source and destination ports.

Payload Extraction: If the packet has payload data, it’s printed in the output.

Output: The program prints packet details, including source IP, destination IP, protocol, ports, and any payload data.

Ethical Considerations:

Packet sniffing is only legal if you have explicit permission to capture and analyze network traffic. Unauthorized packet sniffing is considered illegal and unethical. Always ensure the target network belongs to you or that you have obtained clear consent from the network’s administrators.
