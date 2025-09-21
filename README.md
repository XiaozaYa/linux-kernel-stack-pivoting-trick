# linux-kernel-stack-pivoting-trick
some tricks for Linux kernel stack pivoting in CTF \[with smap|smep|kaslr\]

## direct mapping area [physmap]
- condition: leak physmap address
- exploit: mmap\[or other ways\] to spray rop chain

## DB_stack [in per-cpu cpu_entry_area]
- condition: leak per-cpu cpu_entry_area
- exploit: trigger hardware breakpoint to place rop chain in DB_stack

## a area after kernel data
- condition: leak kbase
- exploit: mmap\[or other ways\] to spray rop chain
