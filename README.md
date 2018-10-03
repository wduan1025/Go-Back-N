# Go-Back-N
An implementation of Go-Back-N protocol.This is a collaborative work with [kennch](https://github.com/kennch).
## Feature
* Cycler array is used to store packet window, making it compatible for transfering unlimited larget file.
* Dynamically swtiching window size among 1,2, and 4 based on TIMEOUT event. When all ACKs received, switch to larger window size, but when there is ACK loss, slow down to size 1 window
## Usage
create input file with name <input-file>, it can be of any type: pdf, jpeg, etc.<br/>
`make` </br>
launch receiver </br>
`./receiver <port> <output-file> `</br>
launch sender</br>
`./sender 127.0.0.1 <port> <input file>`</br>

## C Standard
We use **C99** for this lab.

## External source
The logger used in this lab is credited to [rxi/log.c](https://github.com/rxi/log.c)

## Play with it
Change packet loss rate and corrupt rate in file `gbn.h`, they are configured by `LOSS_PROB` and `CORR_PROB`.
## Enable Logger Output
The logger for this lab is disabled by default, in order to optimize its performance. To enable logging output, go to ```gbn.c```, and find ```gbn_init()```.
```
log_set_quiet(1);
log_set_level(LOG_DEBUG);
```
Changing ```log_set_quiet(1)``` to ```log_set_quiet(0)``` enables logging output. You can also change the logging level by modifying ```log_set_level(LOG_DEBUG)```. For more usages, you can have a reference on [rxi/log.c](https://github.com/rxi/log.c)
