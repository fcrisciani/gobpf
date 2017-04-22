package main

import (
	"encoding/binary"
	"fmt"
	"net"
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

BPF_HASH(mac2if, struct hdr_key, int);
// BPF_HASH(mac2if, u32, u32);
// BPF_HASH(conf, int, struct hdr_key, 1);
// BPF_HASH(conf, int, int, 1);

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
	struct hdr_key vk = {ethernet->dst};
	int* v = mac2if.lookup(&vk);
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

func mac2Key(macStr string) []byte {
	mac, err := net.ParseMAC(macStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse mac %s", err)
		return nil
	}
	mm := make([]byte, 8)
	for i := 0; i < 6; i++ {
		mm[i] = mac[5-i]
	}
	return mm
}

func insertMacEntry(t *bpf.Table, mac string, ifIndex int) error {
	vmMacKey := mac2Key(mac)
	vmIfIndex := ifIndex
	vmLeaf := make([]byte, 4)
	binary.LittleEndian.PutUint32(vmLeaf, uint32(vmIfIndex))
	err := t.SetBytes(vmMacKey, vmLeaf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed insert key %s\n", err)
		return err
	}
	return nil
}

func main() {
	b := bpf.NewModule(source, []string{})
	defer b.Close()

	table := bpf.NewTable(b.TableId("mac2if"), b)

	// fallbackLink, err := netlink.LinkByName("eth0")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to get the link for ifc eth0 %s", err)
	// 	os.Exit(1)
	// }
	// zero := byte{0}
	// table.Set(string(0), fallbackLink.Attrs().Index)

	if insertMacEntry(table, "66:42:e6:da:fd:9b", 11) != nil {
		fmt.Fprintf(os.Stderr, "Failed insert entry vm1\n")
		os.Exit(1)
	}
	if insertMacEntry(table, "5e:7c:60:3e:ab:5d", 13) != nil {
		fmt.Fprintf(os.Stderr, "Failed insert entry vm2\n")
		os.Exit(1)
	}

	// buf := new(bytes.Buffer)
	// err = binary.Write(buf, binary.BigEndian, mac)
	// macFlip := new(bytes.Buffer)
	// binary.Write(macFlip, binary.LittleEndian, mac)
	// fmt.Fprintf(os.Stderr, "Little endian: %p\n", macFlip)
	// macFlip = new(bytes.Buffer)
	// binary.Write(macFlip, binary.BigEndian, mac)
	// fmt.Fprintf(os.Stderr, "Big endian: %p\n", macFlip)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "UPS in binary %s\n", err)
	// 	os.Exit(1)
	// }

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

	// link, err := netlink.LinkByName("veth2")
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Failed to get the link for ifc veth2 %s\n", err)
	// 	os.Exit(1)
	// }

	attrs1 := netlink.QdiscAttrs{
		LinkIndex: 11,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc1 := &netlink.GenericQdisc{
		QdiscAttrs: attrs1,
		QdiscType:  "ingress",
	}
	// This feature was added in kernel 4.5
	if err := netlink.QdiscAdd(qdisc1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed adding clsact qdisc, unsupported kernel\n")
		os.Exit(1)
	}
	defer netlink.QdiscDel(qdisc1)

	filterattrs1 := netlink.FilterAttrs{
		LinkIndex: 11,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  syscall.ETH_P_ALL,
		Priority:  1,
	}
	filter1 := &netlink.BpfFilter{
		FilterAttrs:  filterattrs1,
		Fd:           fd,
		Name:         "handle_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter1); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load the filter %s\n", err)
		os.Exit(1)
	}
	defer netlink.FilterDel(filter1)

	attrs2 := netlink.QdiscAttrs{
		LinkIndex: 13,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc2 := &netlink.GenericQdisc{
		QdiscAttrs: attrs2,
		QdiscType:  "ingress",
	}
	// This feature was added in kernel 4.5
	if err := netlink.QdiscAdd(qdisc2); err != nil {
		fmt.Fprintf(os.Stderr, "Failed adding clsact qdisc, unsupported kernel\n")
		os.Exit(1)
	}
	defer netlink.QdiscDel(qdisc2)

	filterattrs2 := netlink.FilterAttrs{
		LinkIndex: 13,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  syscall.ETH_P_ALL,
		Priority:  1,
	}
	filter2 := &netlink.BpfFilter{
		FilterAttrs:  filterattrs2,
		Fd:           fd,
		Name:         "handle_egress",
		DirectAction: true,
	}
	if err := netlink.FilterAdd(filter2); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load the filter %s\n", err)
		os.Exit(1)
	}
	defer netlink.FilterDel(filter2)

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
