// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ethereum/go-ethereum/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main KCC network.
var MainnetBootnodes = []string{
	"enode://2e43f99b5364a6d900ae97b528784dfec28596600ec4ceb7ef6661307e4075e19b12c94c17ab53cd3e049c8731dd671568da3825e867b70afd89768ab4af73b9@64.176.81.70:30303",
	"enode://5e519a311a094aa54fe419f1f9a9739574f77dd397d0a51f6df5363a489cb65e3bc2ef55f247894f2d064cfb02dec69346c59a7399211be0173faa8658686ca1@139.180.156.26:30303",
	"enode://1f0bddd4bd802026ca9de92b9f2eeac211133ad7ce44cbc7c9d461e409d08a6b286d1f803c62c4e128a55616158eb3b65b98604ef059cabda0345e22bda16769@139.180.140.138:30303",
	"enode://698335b47efe83510578efa45dfb8abf9eae97b3ab70250c1f154e41988f62105bf2936ba319e803d93f2a2d3f45e241e8f30fb626436b30f9c8faffbc162004@78.141.242.210:30303",
	"enode://1c563d67ea842d2b1557d24eba18984b792b26c2faf763da8dafa41ed66a934ababb9a0fe9927023b31a18fbb9cab1ae110d41277030ee9eea0865656c63ebea@78.141.192.241:30303",
	"enode://45cbc62e37854b7246ffcd2472d4bc564201e76e30fd5f327fce3b3c41622763c8a0bed6e1116d091d9cb54ed9147b2717e164314acee0976ab5df7798b828c1@45.63.100.155:30303",
	"enode://3394215bf7532397103acf89d2fe79ac345c58d52f2178338a38531d14a34deffe300405cf4fed34a3431991649041f56ca9bf85b793cc4435277fe08601119f@95.179.146.19:30303",
	"enode://e8e7c0ec344546143a33e1819f84c7512a2bd5da4c842c301f6b86a63213fe7059ce88bac8449ad5eb1ed14a3eaaa4ada7dbbc04888d1cc5258aab6ec896b56d@209.250.254.243:30303",
	"enode://b1fdd63dafd4550dbea08eb68fdfdc74f2531ac59df403c5d4ab4fb7544291312abd053fc53a6754aee440dcada0540e6519777fd0d130ed4f1118bd4c72c603@198.13.51.199:30303",
	"enode://b70b63d1759b70e6ecaa577ad3e5beb2c21f2322e5ca704d3fdfb0443ff5ece8426beb8ed1f14278b77ccdbbfa173d6def3c7b349f82a10286dee0ebd435da37@78.141.211.93:30303",
	"enode://e55672b33c9ea3288aec625c985aef670bc0f053ae8297831b23cba10a5c5c073199074a852eaa01fdb19dcbea42733dbdc28e1cdf5dcbd2644b407574746beb@167.179.67.138:30303",
	"enode://4a26aa2579be193c8f3479ef82b3e1416aa55b451209f17aa5ffdb78e7d1acc1cf3cea94d98b19837c280159df744243d54f09e5473e27795e7d9a92fd834865@139.180.184.141:30303",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the test network.
var TestnetBootnodes = []string{
	"enode://153283f7aab215030c7fc2c59b0080dd9e92730d82c1789a7687c169fcc162e09355ffdd7fd089dc90a8c05b3f8d6e3d12adc80c2114505446ca57bd8652a527@45.32.119.7:30303", // kcc-testnet-node-boot-01
	"enode://7d62bbc17b75e1c29dc9288b06126c052acd61ef6c8a739f1f0751816db9387e901319d71e7182897e90f9e76e2f9c56775516e783de6122ff7ef733da9e2da6@66.42.52.214:30303", // kcc-testnet-node-boot-01
	"enode://b6c1be9a1abf3e3ee781681b46717962a5068179ce7b0ed2823761bbf2081afca70fac2ea005507601ea164871a35033860845c0063cf311ea0a63fab4ad5b8d@149.28.144.12:30303",  // kcc-testnet-node-boot-02
	"enode://faa15c03299f852a460b6ba3f3742f171fd702e790eb83b7f03addf3dcb36e53aae891ddd2d3c34b32b30553e3d99860df97dc97ebc9b205f1bbd891fa6d0169@149.28.157.109:30303", // kcc-testnet-node-boot-03
	"enode://6267cb4280f9c450e6b8418ddb717fc6b4b9610b1e60d75b0dff81ee01cb7492713e2a25440b4e3348a060b326908ef2599d8bacbed945621f40599ec4dc33fe@45.76.158.151:30303", // kcc-testnet-node-boot-04
	"enode://a1b466d6986f28cee47f597685172fd5a7c5cd9ec9bd8827357a506192ee3068083a50d892e9a72a649928c2b1f31b6809c900e90687a26924966a89628c5d9c@45.77.248.33:30303",   // kcc-testnet-node-sync-01
}

var V5Bootnodes []string

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	return ""
}
