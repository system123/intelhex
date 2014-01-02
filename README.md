IntelHex
========

Parse [Intel HEX][wp] files, dump them as binary.

CLI example:

    ./intel_hex.rb < firmware.hex > firmware.bin

Ruby example:

    IntelHex::Hex.new(instream).binary.dump(outstream)

[wp]: http://en.wikipedia.org/wiki/Intel_HEX
