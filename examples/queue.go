package main

import (
	"encoding/binary"
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
  u32 mac;
};

// BPF_HASH(mac2if, struct hdr_key, int);
// BPF_HASH(mac2if, u32, u32);
// BPF_HASH(conf, int, struct hdr_key, 1);
BPF_HASH(conf, int, int, 1);

int handle_ingress(struct __sk_buff *skb) {
  bpf_trace_printk("ingress");
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

  bpf_trace_printk("ingress got packet from =%x\n", ethernet->src);
  bpf_clone_redirect(skb, 150, 1/*ingress*/);
  // int* v = mac2if.lookup(ethernet->src);
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

  bpf_trace_printk("egress got packet from %x to %x\n", ethernet->src, ethernet->dst);
	// struct hdr_key vk = {13};
	int vk = 0;
	// int* v = mac2if.lookup(&vk);
	int one = 1;
  // struct hdr_key *v = conf.lookup(&one);
  int *v = conf.lookup(&one);
	if (v) {
		bpf_trace_printk("egress lookup GOOD send to %d\n", *v);
		bpf_clone_redirect(skb, *v, 0/*ingress*/);
	} else {
		bpf_trace_printk("egress lookup FAILED send to 2\n");
		bpf_clone_redirect(skb, 2, 0/*ingress*/);
	}

  return 1;
}
`

func main() {
	b := bpf.NewModule(source, []string{})
	defer b.Close()

	table := bpf.NewTable(b.TableId("conf"), b)

	// fallbackLink, err := netlink.LinkByName("eth0")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to get the link for ifc eth0 %s", err)
	// 	os.Exit(1)
	// }
	// zero := byte{0}
	// table.Set(string(0), fallbackLink.Attrs().Index)

	// mac, err := net.ParseMAC("5e:7c:60:3e:ab:5d")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to parse mac %s", err)
	// 	os.Exit(1)
	// }

	index := 1
	bs := make([]byte, 4)
	x := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(index))
	binary.BigEndian.PutUint32(x, uint32(index))

	err := table.Set("1", "13")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed insert key %s\n", err)
		os.Exit(1)
	}

	ch := table.Iter()
	for elem := range ch {
		fmt.Printf("%s --> %s\n", elem.Key, elem.Value)
	}

	// fmt.Printf("mac:%s\n", hex.EncodeToString(mac))
	// macKey := fmt.Sprint(mac)
	// fmt.Printf("macs len:%d\n", len(string(mac[:6])))
	// table.Set("0", "0")

	fd, err := b.LoadTcFilter("handle_egress")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load the bpf program %s\n", err)
		os.Exit(1)
	}

	link, err := netlink.LinkByName("veth2")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get the link for ifc veth2 %s\n", err)
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
		fmt.Fprintf(os.Stderr, "Failed adding clsact qdisc, unsupported kernel\n")
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
		fmt.Fprintf(os.Stderr, "Failed to load the filter %s\n", err)
		os.Exit(1)
	}
	defer netlink.FilterDel(filter)

	fmt.Fprintf(os.Stderr, "GO GO GO\n\n")

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
