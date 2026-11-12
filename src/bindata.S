/* The BIN base set, compiled into the binary as it is in the repository (gzip). */
    .section .rodata
    .global bin_table_gz
    .global bin_table_gz_end
    .hidden bin_table_gz
    .hidden bin_table_gz_end
bin_table_gz:
    .incbin "data/bin-table.csv.gz"
bin_table_gz_end:
    .section .note.GNU-stack,"",%progbits
