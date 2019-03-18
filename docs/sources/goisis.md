# GoISIS: IS-IS implementation in Go

## これは何？

Go 言語で書かれた IS-IS 実装です。

まだ経路情報を FIB に入れる仕組みを用意していないのでトポロジー情報を収集して計算結果の経路を表示するくらいしかできません。

あと L2 のアタッチビットの処理とかエクスターナルの扱いをちゃんとしてません。

認証もまだ実装してません。

全体的にまだ書きなぐった状態なのでこれから徐々に綺麗にしていきたい所存。

最終的には SRv6 SID TLV に対応して TI-LFA に対応したり GoBGP と連携して BGP-LS 対応とかしたい。

## 使い方

まず go get コマンドで goisisd(デーモン) と goisis(goisisd とやりとりするコマンド) をコンパイルします。

```
$ go get github.com/m-asama/golsr/cmd/goisis
$ go get github.com/m-asama/golsr/cmd/goisisd
```

次に以下のような goisisd の設定ファイル goisisd.toml を作ります。

```
[config]
  system-id = "4a6f.ee64.a2c0"
  area-address-list = ["01", "02"]

[[interfaces]]
  [interfaces.config]
    name = "lo"

[[interfaces]]
  [interfaces.config]
    name = "eth12"
    #interface-type = "point-to-point"
  [interfaces.priority.config]
    value = 70

[[interfaces]]
  [interfaces.config]
    name = "eth13"
    #interface-type = "point-to-point"
  [interfaces.priority.config]
    value = 70
```

そして goisisd を実行します。

```
$ sudo goisisd -f ./goisisd.toml
```

隣接一覧を表示するには以下のコマンドを実行します。

```
$ sudo goisis interface adjacency
Interface                 : eth12
NeighborType              : ADJ_TYPE_LEVEL1_LAN
NeighborSysid             : faa56cc9adad
NeighborExtendedCircuitId : 0
NeighborSnpa              : 2e08db03b646
Usage                     : ADJ_USAGE_LEVEL1
HoldTimer                 : 97
NeighborPriority          : 64
Lastuptime                : %!s(uint32=0)
State                     : ADJ_3WAY_STATE_UP

Interface                 : eth12
NeighborType              : ADJ_TYPE_LEVEL2_LAN
NeighborSysid             : faa56cc9adad
NeighborExtendedCircuitId : 0
NeighborSnpa              : 2e08db03b646
Usage                     : ADJ_USAGE_LEVEL2
HoldTimer                 : 97
NeighborPriority          : 64
Lastuptime                : %!s(uint32=0)
State                     : ADJ_3WAY_STATE_UP

... 中略 ...
```

LSDB 一覧を表示するには以下のコマンドを実行します。

```
$ sudo goisis database linkstate all
Level             : L1
LspId             : 4a6fee64a2c00000
Checksum          : 0x9eaf
RemainingLifetime : 67
Sequence          : 0x0004(4)
Ipv4Addresses     : []
Ipv6Addresses     : []
Ipv4TeRouterid    : 
Ipv6TeRouterid    : 
ProtocolSupported : []
DynamicHostname   : 

Level             : L1
LspId             : 4a6fee64a2c00300
Checksum          : 0x21fa
RemainingLifetime : 67
Sequence          : 0x0004(4)
Ipv4Addresses     : []
Ipv6Addresses     : []
Ipv4TeRouterid    : 
Ipv6TeRouterid    : 
ProtocolSupported : []
DynamicHostname   : 

... 中略 ...
```

経路情報を表示するには以下のコマンドを実行します。

```
$ sudo goisis route all all
LV PREFIX                          DIST I/F      NEXTHOP                       
L1 192.168.2.0/24                    20 eth12    192.168.12.2                  
L2 192.168.2.0/24                    20 eth12    192.168.12.2                  
L1 192.168.3.0/24                    20 eth13    192.168.13.3                  
L2 192.168.3.0/24                    20 eth13    192.168.13.3                  
L1 192.168.4.0/24                    30 eth13    192.168.13.3                  
                                        eth12    192.168.12.2                  
L2 192.168.4.0/24                    30 eth13    192.168.13.3                  
                                        eth12    192.168.12.2                  
L1 2001:db8:0:2::/64                 20 eth12    fe80::2c08:dbff:fe03:b646     
L2 2001:db8:0:2::/64                 20 eth12    fe80::2c08:dbff:fe03:b646     
L1 2001:db8:0:3::/64                 20 eth13    fe80::d869:acff:feab:731      
L2 2001:db8:0:3::/64                 20 eth13    fe80::d869:acff:feab:731      
L1 2001:db8:0:4::/64                 30 eth13    fe80::d869:acff:feab:731      
                                        eth12    fe80::2c08:dbff:fe03:b646     
L2 2001:db8:0:4::/64                 30 eth13    fe80::d869:acff:feab:731      
                                        eth12    fe80::2c08:dbff:fe03:b646     
```
