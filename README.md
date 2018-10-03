# Go-Back-N
An implementation of Go-Back-N protocol.
## Features
* Cycler array is used to store packet window, making it compatible for transfering unlimited larget file.
* Dynamically swtiching window size among 1,2, and 4 based on TIMEOUT event. When all ACKs received, switch to larger window size, but when there is ACK loss, slow down to size 1 window
## Usage
create input file with name <input-file>, it can be of any type: pdf, jpeg, etc.<br/>
`make` </br>
launch receiver </br>
`./receiver <port> <output-file> `</br>
launch sender</br>
`./sender 127.0.0.1 <port> <input file>`</br>
## Play with it
Change packet loss rate and corrupt rate in file `gbn.h`, they are configured by `LOSS_PROB` and `CORR_PROB`.
