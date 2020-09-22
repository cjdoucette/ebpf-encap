# ebpf-encap
eBPF program to perform IPIP encapsulation

This code is based on the example here: https://github.com/fzakaria/ebpf-mpls-encap-decap

## Usage

To build the BPF program, run:

    $ make

There will be warnings that are safe to ignore.

To insert the BPF program to perform IPIP encapsulation, run:

    $ sudo ip route add 172.31.3.200/32 encap bpf xmit obj ipip.bpf sec ipip_encap dev ens5

The program may output verification warnings, but it should load. To verify, run:

    $ ip route show

In the results, you should see an entry like:

    172.31.3.200  encap bpf xmit ipip.bpf:[ipip_encap] dev ens5 scope link

To enable debugging, run:

    # ./ipip.bin enable
    # echo 1 > /sys/kernel/debug/tracing/tracing_on
    # cat /sys/kernel/debug/tracing/trace_pipe

And then send a packet to the address that matches the routing rule:

    $ nc -w 0 -u 172.31.3.200 8080 <<< 'Hello, world!'
