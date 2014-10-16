#!/usr/bin/env ruby

# Parse Intel HEX files, dump them as binary.
# http://en.wikipedia.org/wiki/Intel_HEX
#
# Execute this file to read HEX from stdin, dump binary to stdout.
# Or do some variation of IntelHex::Hex.new(instream).binary.dump(outstream)
#
# Author: Paul Annesley
# License: MIT (open source)

module IntelHex

  # Represents the Intel Hex file given by input.
  class Hex

    # input: an input stream which responds to `each_line`.
    def initialize(input)
      @input = input
    end

    # yields each IntelHex::Line objects.
    def each_line
      number = 0
      @input.each_line do |text|
        number += 1
        next if text =~ %r{\A\s*\z}
        yield(Line.parse(number, text))
      end
    end

    # IntelHex::Binary representation of the Intel Hex file.
    def binary
      Binary.new(self)
    end

  end

  # Binary representation/conversion from an IntelHex::Hex object.
  class Binary

    # reader: IntelHex::Hex instance.
    def initialize(reader)
      @base_address = 0x0000
      @buffer = nil
      @eof = false
      @reader = reader
    end

    def to_io
      @buffer ||= assemble
    end

    # Dump the binary to the given output stream.
    def dump(output)
      io = to_io
      io.rewind
      output.write(io.read)
    end

    private

    def assemble
      require "stringio"
      @buffer = StringIO.new
      @reader.each_line do |line|
        raise("Unexpected line after EOF record") if @eof
        line.validate!
        handle_line(line)
      end
      raise("Missing EOF line") unless @eof
      @buffer.rewind
      @buffer
    end

    def handle_line(line)
      case line.type_name
      when "DATA"
        @buffer.seek(resolve_address(line.address))
        @buffer.write(line.data_as_binary)
      when "EOF"
        @eof = true
      when "EXTENDED_SEGMENT_ADDRESS"
        @base_address = line.data_as_integer << 4
      when "START_SEGMENT_ADDRESS"
        @register_cs = line.data[0]
        @register_ip = line.data[1]
      else
        raise("Unhandled line type: #{line.to_s}")
      end
    end

    # Applies extended addressing to the given line-local address.
    def resolve_address(address)
      @base_address + address
    end

  end

  class Line < Struct.new(:number, :size, :address, :type, :data, :checksum)

    PATTERN = %r{
      \A
      :
      (\h{2})  # size
      (\h{4})  # address
      (\h{2})  # type
      (\h*)    # data
      (\h{2})  # checksum
      \s*
      \z
    }x

    TYPES = [
      "DATA",
      "EOF",
      "EXTENDED_SEGMENT_ADDRESS",
      "START_SEGMENT_ADDRESS",
      "EXTENDED_LINEAR_ADDRESS",
      "START_LINEAR_ADDRESS",
    ]

    def self.parse(number, text)
      md = PATTERN.match(text)
      raise "Invalid line: '#{text}'" unless md
      c = md.captures
      new(
        number,
        c[0].to_i(16),
        c[1].to_i(16),
        c[2].to_i(16),
        c[3].scan(/../).map { |hex| hex.to_i(16) },
        c[4].to_i(16),
      )
    end

    def data_as_binary
      data.pack("C*")
    end

    def data_as_hex(separator = "")
      data.map { |byte| "%02X" % byte }.join(separator)
    end

    def data_as_integer
      result = 0
      data.reverse.each_with_index do |byte, i|
        result += (byte << (i * 8))
      end
      result
    end

    def expected_checksum
      address_sum = (address & 0xFF) + (address >> 8)
      if data.any?
        data_sum = data.inject(:+) & 0xFF
      else
        data_sum = 0
      end
      sum = size + address_sum + type + data_sum
      (0x100 - (sum & 0xFF)) & 0xFF
    end

    def to_s
      "%04d: %s: %d bytes from 0x%04X: %s%s" % [
        number,
        type_name,
        size,
        address,
        data_as_hex(" "),
        valid? ? "" : " (INVALID CHECKSUM)",
      ]
    end

    def to_str
      ":%02X%04X%02X%s%02X" % [
        size,
        address,
        type,
        data_as_hex,
        checksum,
      ]
    end

    def type_name
      TYPES[type]
    end

    # Whether the checksum is valid for the data.
    def valid?
      checksum == expected_checksum
    end

    def validate!
      unless valid?
        raise("Checksum failed for line %d, expected %02X, got %02X\n%s" % [
          number,
          expected_checksum,
          checksum,
          to_s
        ])
      end
    end

  end

end

if $0 == __FILE__
  case ARGV[0]
  when "explain"
    IntelHex::Hex.new($stdin).each_line do |line|
      puts line.to_s
    end
  else
    # Read hex (ASCII) from stdin, write binary to stdout.
    IntelHex::Hex.new($stdin).binary.dump($stdout)
  end
end
