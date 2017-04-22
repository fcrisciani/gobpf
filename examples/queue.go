package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"

	bpf "github.com/iovisor/gobpf/bcc"
	"github.com/vishvananda/netlink"
)

import "C"

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

func ip2Key(ipStr string) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		fmt.Fprintf(os.Stderr, "Failed to parse IP")
		return nil
	}

	mm := make([]byte, 4)
	for i := 0; i < 4; i++ {
		mm[i] = ip[15-i]
	}
	return mm
}

func insertMacEntry(t *bpf.Table, mac string, ifIndex int) error {
	macKey := mac2Key(mac)
	ifIndexTmp := ifIndex
	ifLeaf := make([]byte, 4)
	binary.LittleEndian.PutUint32(ifLeaf, uint32(ifIndexTmp))
	err := t.SetBytes(macKey, ifLeaf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed insert key %s\n", err)
		return err
	}
	return nil
}

func insertIPEntry(t *bpf.Table, ip, mac string) error {
	ipKey := ip2Key(ip)
	fmt.Fprintf(os.Stderr, "Ip key is %x\n", ipKey)
	macLeaf := mac2Key(mac)
	err := t.SetBytes(ipKey, macLeaf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed insert key %s\n", err)
		return err
	}
	return nil
}

func main() {
	source, err := ioutil.ReadFile("./bpf_switch.c")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read the source file %s\n", err)
		os.Exit(1)
	}

	b := bpf.NewModule(string(source), []string{})
	defer b.Close()

	mac2if := bpf.NewTable(b.TableId("mac2if"), b)
	ip2mac := bpf.NewTable(b.TableId("ip2mac"), b)

	if insertMacEntry(mac2if, "66:42:e6:da:fd:9b", 11) != nil {
		fmt.Fprintf(os.Stderr, "Failed insert entry vm1\n")
		os.Exit(1)
	}
	if insertMacEntry(mac2if, "5e:7c:60:3e:ab:5d", 13) != nil {
		fmt.Fprintf(os.Stderr, "Failed insert entry vm2\n")
		os.Exit(1)
	}
	if insertIPEntry(ip2mac, "10.0.0.1", "66:42:e6:da:fd:9b") != nil {
		fmt.Fprintf(os.Stderr, "Failed insert IP entry vm1\n")
		os.Exit(1)
	}
	if insertIPEntry(ip2mac, "10.0.0.2", "5e:7c:60:3e:ab:5d") != nil {
		fmt.Fprintf(os.Stderr, "Failed insert IP entry vm2\n")
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

	ch := mac2if.Iter()
	for elem := range ch {
		fmt.Printf("%s --> %s\n", elem.Key, elem.Value)
	}

	ch = ip2mac.Iter()
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
