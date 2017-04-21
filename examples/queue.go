package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/vishvananda/netlink"
)

import "C"

const source string = `
#include <bcc/proto.h>

struct hdr_key {
  u64 mac;
};

BPF_TABLE("hash", struct hdr_key, int, mac_stats, 1024);

int handle_ingress(struct __sk_buff *skb) {
  bpf_trace_printk("ingress");
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  bpf_trace_printk("ingress got packet from =%x\n", ethernet->src);
  bpf_clone_redirect(skb, 150, 1/*ingress*/);
  // int* v = mac_stats.lookup(ethernet->src);
  //
  // if (v) {
  //   lock_xadd(*v, 1);
  // }
  return 1;
}

int handle_egress(struct __sk_buff *skb) {
  bpf_trace_printk("egress");
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  bpf_trace_printk("egress got packet from =%x\n", ethernet->dst);
  bpf_clone_redirect(skb, 150, 0/*ingress*/);
  // int* v = mac_stats.lookup(ethernet->dst);
  //
  // if (v) {
  //   lock_xadd(*v, 1);
  // }

  return 1;
}
`

func main() {
	b := bpf.NewModule(source, []string{})
	defer b.Close()

	fd, err := b.LoadTcFilter("handle_egress")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load the bpf program %s", err)
		os.Exit(1)
	}

	link, err := netlink.LinkByName("veth2")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get the link for ifc veth2 %s", err)
		os.Exit(1)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "ingress",
	}
	// This feature was added in kernel 4.5
	if err := netlink.QdiscAdd(qdisc); err != nil {
		fmt.Fprintf(os.Stderr, "Failed adding clsact qdisc, unsupported kernel")
		os.Exit(1)
	}
	defer netlink.QdiscDel(qdisc)

	filterattrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  syscall.ETH_P_ALL,
		Priority:  1,
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           fd,
		Name:         "handle_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load the filter %s", err)
		os.Exit(1)
	}
	defer netlink.FilterDel(filter)

	fmt.Fprintf(os.Stderr, "GO GO GO")

	// syncKprobe, err := m.LoadKprobe("hello_sys_sync")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to load kprobe__sys_sync: %s\n", err)
	// 	os.Exit(1)
	// }
	//
	// err = m.AttachKprobe("sys_sync", syncKprobe)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to attach kprobe__sys_fchownat: %s\n", err)
	// 	os.Exit(1)
	// }

	// b.PrintTrace()

	// chownKretprobe, err := m.LoadKprobe("kretprobe__sys_fchownat")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to load kretprobe__sys_fchownat: %s\n", err)
	// 	os.Exit(1)
	// }
	//
	// err = m.AttachKretprobe("sys_fchownat", chownKretprobe)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to attach kretprobe__sys_fchownat: %s\n", err)
	// 	os.Exit(1)
	// }

	// table := bpf.NewTable(m.TableId("chown_events"), m)

	// channel := make(chan []byte)

	// perfMap, err := bpf.InitPerfMap(table, channel)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
	// 	os.Exit(1)
	// }

	// file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer file.Close()
	//
	// scanner := bufio.NewScanner(file)
	// for scanner.Scan() {
	// 	fmt.Println(scanner.Text())
	// }
	//
	// if err := scanner.Err(); err != nil {
	// 	log.Fatal(err)
	// }

	// file, err := os.Open("/sys/kernel/debug/tracing/trace_pipe") // For read access.
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// data := make([]byte, 100)
	// count, err := file.Read(data)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// fmt.Printf("read %d bytes: %q\n", count, data[:count])

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	//
	// go func() {
	// 	var event chownEvent
	// 	for {
	// 		data := <-channel
	// 		err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
	// 		if err != nil {
	// 			fmt.Printf("failed to decode received data: %s\n", err)
	// 			continue
	// 		}
	// 		filename := (*C.char)(unsafe.Pointer(&event.Filename))
	// 		fmt.Printf("uid %d gid %d pid %d called fchownat(2) on %s (return value: %d)\n",
	// 			event.Uid, event.Gid, event.Pid, C.GoString(filename), event.ReturnValue)
	// 	}
	// }()

	// perfMap.Start()
	<-sig
	// perfMap.Stop()
}
