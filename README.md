# Go-Back-N
An implementation of Go-Back-N protocol.
## Features
* Cycler array is used to store packet window, making it compatible for transfering unlimited larget file.
* Dynamically swtiching window size among 1,2, and 4 based on TIMEOUT event. When all ACKs received, switch to larger window size, but when there is ACK loss, slow down to size 1 window
