
SUBSTRATE_CMD := ../node/target/debug/suter-node
all: chain_spec.raw

chain_spec.test:
	$(SUBSTRATE_CMD) build-spec --chain=local > $@

chain_spec.json:
	$(SUBSTRATE_CMD) build-spec --chain=local > $@

chain_spec.raw: chain_spec.json
	$(SUBSTRATE_CMD) build-spec --chain $^ --raw > $@

%.subkey:
	subkey -e -n substrate generate > $@

%.launch: %.subkey
	$(SUBSTRATE_CMD) --base-path /tmp/$@ \
	--chain ./chain_spec.raw \
	--key="$(lastword $(shell awk "/key/ {print $$4}" $^))" \
	--port 30333 \
	--name LaunchNode \
	--validator

%.peer: %.subkey
	$(SUBSTRATE_CMD) --base-path /tmp/$@ \
	--chain ./chain_spec.raw \
	--key="$(lastword $(shell awk "/key/ {print $$4}" $^))" \
	--port 30335 \
	--name peerNode \
	--validator \
# --bootnodes /ip4/127.0.0.1/tcb/30333/p2p/QmXpe9CaMWTqAQtg68zs482ymd6LmSGbBwd4vKyR8n5bMX



%.local: %.subkey
	$(SUBSTRATE_CMD) --base-path /tmp/$@ \
	#--chain=local \
	--key //Alice \
	--port 30333 \
	--name LaunchLocal \
	--validator

%.localpeer: %.subkey
	$(SUBSTRATE_CMD) --base-path /tmp/$@ \
	--chain=local \
	--key //Bob \
	--port 30333 \
	--name LaunchLocalPeer \
	--validator



killports:
	sudo lsof -i -P -n

install-pkgs:
	opam install lwt
	opam install lwt_ssl
	opam install yojson

restart:
	rm -rf nodeA.launch
	rm -rf nodeB.peer
	rm -rf nodeA.local
	rm -rf /tmp/nodeA.launch
	rm -rf /tmp/nodeA.local
	rm -rf /tmp/nodeB.localpeer
	rm -rf /tmp/nodeB.peer

clean:
	rm -rf chain_spec.json
	rm -rf chain_spec.raw
