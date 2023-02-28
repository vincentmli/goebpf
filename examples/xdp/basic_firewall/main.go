// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/dropbox/goebpf"
	"github.com/go-ini/ini"
)

type ipAddressList []string
type portList []string

var iface = flag.String("iface", "", "Interface to bind XDP program to")
var file = flag.String("file", "", "Timed internet groups IPs/CIRDs members")
var group = flag.String("group", "", "Add IPs/CIRDs to specific timed internet group, use together with -drop")
var attach = flag.Bool("attach", false, "Attach XDP program")
var off = flag.Bool("off", false, "Remove group member IPs/CIDRs, use together with -group and -file")
var elf = flag.String("elf", "ebpf_prog/xdp_fw.elf", "clang/llvm compiled binary file")
var ipList ipAddressList
var ports portList

func main() {
	flag.Var(&ipList, "drop", "IPv4 CIDR to DROP traffic from, repeatable")
	flag.Var(&ports, "port", "port to DROP traffic to, repeatable")
	flag.Parse()

	// Create eBPF system
	bpf := goebpf.NewDefaultEbpfSystem()
	// Load .ELF files compiled by clang/llvm
	err := bpf.LoadElf(*elf)
	if err != nil {
		fatalError("LoadElf() failed: %v", err)
	}
	printBpfInfo(bpf)

	//Attach XDP program to interface
	if *attach != false {
		if *iface == "" {
			fatalError("-iface is required.")
		}
		// Get XDP program. Name simply matches function from xdp_fw.c:
		//      int firewall(struct xdp_md *ctx) {
		xdp := bpf.GetProgramByName("firewall")
		if xdp == nil {
			fatalError("Program 'firewall' not found.")
		}

		// Load XDP program into kernel
		err = xdp.Load()
		if err != nil {
			fatalError("xdp.Load(): %v", err)
		}

		// Attach to interface
		err = xdp.Attach(*iface)
		if err != nil {
			fatalError("xdp.Attach(): %v", err)
		}
		//defer xdp.Detach()
	}

	if len(ports) != 0 {
		// Get eBPF maps
		portMap := bpf.GetMapByName("port_map")
		if portMap == nil {
			fatalError("port_map eBPF map not exist!")
		}
		// Add eBPF map ports
		fmt.Println("Adding port ...")
		for index, p := range ports {
			fmt.Printf("%s\n", p)
			u64, err := strconv.ParseUint(p, 10, 32)
			if err != nil {
				fmt.Println(err)
			}
			err = portMap.Insert(uint16(u64), index)
			if err != nil {
				fatalError("Unable to insert into eBPF port_map: %v", err)
			}

		}
	}

	if *off != false {
		//Group member delete

		if *file == "" && len(ipList) == 0 {
			fatalError("-off requires -file %s or -drop %s!", *file, len(ipList))
		}

		// Delete specific group members from file or all groups and members from file
		if *file != "" {

			cfg, err := ini.Load(*file)
			if err != nil {
				fmt.Printf("Fail to read file: %v", err)
				os.Exit(1)
			}

			// Delete specific group members from file
			if *group != "" {
				// Get eBPF maps
				groupMapName := bpf.GetMapByName(*group)
				if groupMapName == nil {
					fatalError("Delete group member but eBPF map  %s not exist", *group)
				}

				// get slices of timed internet group member ips/cidrs
				ips := cfg.Section(*group).Key("member").Strings(",")

				// Delete eBPF map IPv4 addresses
				fmt.Println("Deleting IPv4 addresses...")
				for _, ip := range ips {
					fmt.Printf("%s\n", ip)
					err := groupMapName.Delete(goebpf.CreateLPMtrieKey(ip))
					if err != nil {
						fatalError("Unable to delete from eBPF map: %v", err)
					}

				}
			} else { //Delete all groups and members
				secNames := cfg.SectionStrings()
				for _, name := range secNames {
					if name == "DEFAULT" { //ignore ini DEFAULT
						continue
					}
					fmt.Printf("%s\n", name)

					// Get eBPF maps
					groupMapName := bpf.GetMapByName(name)
					if groupMapName == nil {
						fmt.Printf("Delete group member but eBPF map not exists%s\n", name)
						continue
					}

					// get slices of timed internet group member ips/cidrs
					ips := cfg.Section(name).Key("member").Strings(",")

					// Delete eBPF map with IPv4 addresses
					fmt.Println("Deleting IPv4 addresses...")
					for _, ip := range ips {
						fmt.Printf("%s\n", ip)
						err := groupMapName.Delete(goebpf.CreateLPMtrieKey(ip))
						if err != nil {
							fatalError("Unable to delete from eBPF map: %v", err)
						}

					}
				}

			}
		}
		// Temporarily delete members from specific group from -drop
		if len(ipList) != 0 {
			if *group == "" {
				fatalError("-drop requires -group %s", *group)
			}
			// Get eBPF maps
			groupMapName := bpf.GetMapByName(*group)
			if groupMapName == nil {
				fatalError("%s Delete group member but eBPF map not exist!", *group)
			}
			// Delete eBPF map with IPv4 addresses to block
			fmt.Println("Delete IPv4 addresses...")
			fmt.Printf("Group map name:%s\n", *group)
			for _, ip := range ipList {
				fmt.Printf("%s\n", ip)
				err := groupMapName.Delete(goebpf.CreateLPMtrieKey(ip))
				if err != nil {
					fatalError("Unable to delete from eBPF map: %v", err)
				}

			}
		}
	} else {
		// Group member addtion logic

		if *file == "" && len(ipList) == 0 {
			fatalError("group member addition  requires -file %s or -drop %s!", *file, len(ipList))
		}

		// Add temporary specific group member from -drop
		// -drop <IPs/CIDRs> -group <group>
		if len(ipList) != 0 {
			if *group == "" {
				fatalError("group member addtion -drop requires -group %s", *group)
			}
			// Get eBPF maps
			groupMapName := bpf.GetMapByName(*group)
			if groupMapName == nil {
				fatalError("%s eBPF map not exist!", groupMapName)
			}

			// Populate eBPF map with IPv4 addresses to block
			fmt.Println("Blacklisting IPv4 addresses...")
			fmt.Printf("Group map name:%s\n", *group)
			for index, ip := range ipList {
				fmt.Printf("%s\n", ip)
				err := groupMapName.Insert(goebpf.CreateLPMtrieKey(ip), index)
				if err != nil {
					fatalError("Unable to Insert into eBPF map: %v", err)
				}

			}
		}

		// either add specific group member from file or add all groups and  members from file
		// -file <file> -group <group>
		// or
		// -file <file>
		if *file != "" {

			cfg, err := ini.Load(*file)
			if err != nil {
				fmt.Printf("Fail to read file: %v", err)
				os.Exit(1)
			}

			if *group != "" { // Add specific group members from file
				// Get eBPF maps
				groupMapName := bpf.GetMapByName(*group)
				if groupMapName == nil {
					fatalError("%s Add group member but eBPF map not exist!", *group)
				}
				// get slices of timed internet group member ips/cidrs
				ips := cfg.Section(*group).Key("member").Strings(",")

				// Add eBPF map IPv4 addresses
				fmt.Println("Adding IPv4 addresses...")
				for index, ip := range ips {
					fmt.Printf("%s\n", ip)
					err := groupMapName.Insert(goebpf.CreateLPMtrieKey(ip), index)
					if err != nil {
						fatalError("Unable to insert into eBPF map: %v", err)
					}

				}
			} else { //Add all groups and all members

				secNames := cfg.SectionStrings()
				for _, name := range secNames {
					if name == "DEFAULT" { //ignore ini DEFAULT
						continue
					}
					fmt.Printf("%s\n", name)

					// Get eBPF maps
					groupMapName := bpf.GetMapByName(name)
					if groupMapName == nil {
						fmt.Printf("Add group member but eBPF map not exists%s\n", name)
						continue
					}

					// get slices of timed internet group member ips/cidrs
					ips := cfg.Section(name).Key("member").Strings(",")

					// Populate eBPF map with IPv4 addresses to block
					fmt.Println("Blacklisting IPv4 addresses...")
					for index, ip := range ips {
						fmt.Printf("%s\n", ip)
						err := groupMapName.Insert(goebpf.CreateLPMtrieKey(ip), index)
						if err != nil {
							fatalError("Unable to Insert into eBPF map: %v", err)
						}

					}
				}
			}

			fmt.Println()
		}
	}

	// Add CTRL+C handler
	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	fmt.Println("XDP program successfully loaded and attached. Counters refreshed every second.")
	fmt.Println("Press CTRL+C to stop.")
	fmt.Println()

	/*

		// Print stat every second / exit on CTRL+C
		ticker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-ticker.C:
				fmt.Println("IP                 DROPs")
					for i := 0; i < len(ipList); i++ {
						value, err := matches.LookupInt(i)
						if err != nil {
							fatalError("LookupInt failed: %v", err)
						}
						fmt.Printf("%18s    %d\n", ipList[i], value)
					}
					fmt.Println()
			case <-ctrlC:
				fmt.Println("\nDetaching program and exit")
				return
			}
		}
	*/
}

func fatalError(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func printBpfInfo(bpf goebpf.System) {
	fmt.Println("Maps:")
	for _, item := range bpf.GetMaps() {
		fmt.Printf("\t%s: %v, Fd %v\n", item.GetName(), item.GetType(), item.GetFd())
	}
	fmt.Println("\nPrograms:")
	for _, prog := range bpf.GetPrograms() {
		fmt.Printf("\t%s: %v, size %d, license \"%s\"\n",
			prog.GetName(), prog.GetType(), prog.GetSize(), prog.GetLicense(),
		)

	}
	fmt.Println()
}

// Implements flag.Value
func (i *ipAddressList) String() string {
	return fmt.Sprintf("%+v", *i)
}

// Implements flag.Value
func (i *ipAddressList) Set(value string) error {
	if len(*i) == 16 {
		return errors.New("Up to 16 IPv4 addresses supported")
	}
	// Validate that value is correct IPv4 address
	if !strings.Contains(value, "/") {
		value += "/32"
	}
	if strings.Contains(value, ":") {
		return fmt.Errorf("%s is not an IPv4 address", value)
	}
	_, _, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	// Valid, add to the list
	*i = append(*i, value)
	return nil
}

// Implements flag.Value
func (p *portList) String() string {
	return fmt.Sprintf("%+v", *p)
}

// Implements flag.Value
func (p *portList) Set(value string) error {
	//add to the list
	*p = append(*p, value)
	return nil
}
