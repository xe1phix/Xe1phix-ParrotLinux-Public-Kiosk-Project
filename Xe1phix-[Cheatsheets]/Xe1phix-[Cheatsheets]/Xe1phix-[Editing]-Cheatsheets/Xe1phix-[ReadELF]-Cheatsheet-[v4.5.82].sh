#!/bin/sh

readelf --all
readelf --file-header
readelf --program-headers          # Display the program headers
readelf --segments                 # An alias for --program-headers
readelf --section-headers     # Display the sections' header
readelf --sections                 # An alias for --section-headers
readelf --section-groups           # Display the section groups
readelf --section-details     # Display the section details
readelf --headers                  #  Equivalent to: -h -l -S
readelf --syms                     # Display the symbol table
readelf --dyn-syms                 # Display the dynamic symbol table
readelf --notes                    # Display the core notes (if present)
readelf --relocs                   #  Display the relocations (if present)
readelf --unwind                   # Display the unwind info (if present)
readelf --dynamic                  # Display the dynamic section (if present)


readelf --histogram                #  Display histogram of bucket list lengths
readelf --hex-dump=                # Dump the contents of section <number|name> as bytes
readelf --string-dump=             # Dump the contents of section <number|name> as strings

readelf -w[lLiaprmfFsoRt] or
readelf --debug-dump[=rawline,=decodedline,=info,=abbrev,=pubnames,=aranges,=macro,=frames,
               =frames-interp,=str,=loc,=Ranges,=pubtypes,
               =gdb_index,=trace_info,=trace_abbrev,=trace_aranges]

