transcript on
if {[file exists rtl_work]} {
	vdel -lib rtl_work -all
}
vlib rtl_work
vmap work rtl_work

vlog -sv -work work +incdir+D:/School/UCSD/ECE111/Projects/6\ Final {D:/School/UCSD/ECE111/Projects/6 Final/super_hash_processor.sv}

