# Ubuntu 20 (or similar)
# apt-get install verilator gtkwave

# Yosys is too old on Ubuntu 20
# build yourself

# Wavedrom: Use pre-built package

# sudo apt-get install libreadline-dev tcl-dev

# sudo apt-get install nodejs npm
# sudo npm install -g netlistsvg

# Run all commands of one make target in the same shell, by default
.ONESHELL:

.PHONY: spinal clean simulate repl sim_repl build blackwire rtl

build: rtl

# CI/CD runs "make test"
test: build formal sim_extract sim_counter code_analysis

code_analysis:
	grep -rne '.m2sPipe().s2mPipe()' src/main/scala && \
	echo "Check reverse use of .m2sPipe().s2mPipe()." || true

# generate Verilog, VHDL and SystemVerilog RTL
# this requires external VHDL modules
blackwire:
blackwire: src/main/scala/blackwire/BlackwireReceive.scala
blackwire: src/main/scala/blackwire/BlackwireReceiveFmax.scala
	set -e
	sbt " \	
	runMain blackwire.BlackwireReceive; \
	runMain blackwire.BlackwireReceiveFmax; \
	"

# generate Verilog, VHDL and SystemVerilog RTL
rtl: src/main/scala/blackwire/BlackwireWireguardType4.scala
	set -e
	sbt " \
	runMain blackwire.BlackwireWireguardType4; \
	"

clean:
	rm -rf simWorkspace *.svg formalWorkdir

%.json: %.ys %.v
	set -e
	yosys $< -o $@

%.svg: %.json
	set -e
	netlistsvg $< -o $@

# The paths in .gtkw files are absolute, not very handy
# make them relative 
fix_gtkw:
	sed -i -e "s@$(PWD)@.@" *.gtkw
	sed -i -e "s@./SpinalCorundum@.@" *.gtkw
