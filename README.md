# clean-dns
Clean DNS with eBPF 

利用eBPF tc egress/ingress filter丢弃被 ***污染的DNS应答包

<b>在aarch64 Linux上可用，amd64需要修改config.mk。</b>
<b>内核需要开启eBPF支持。</b>

# Build
make

# Run
clean-dns wan   // load

clean-dns wan --unload  // unload

上游DNS服务器需要设置为8.8.8.8/8.8.4.4或者2001:4860:4860::8888/2001:4860:4860::8844

