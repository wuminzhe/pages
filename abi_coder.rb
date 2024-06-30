# Generated from https://github.com/wuminzhe/abi_coder_rb
module AbiCoderRb
  def decode_array(type, data)
    size = decode_uint256(data[0, 32])
    raise DecodingError, "Too many elements: #{size}" if size > 100_000
    subtype = type.subtype
    if subtype.dynamic?
      raise DecodingError, "Not enough data for head" unless data.size >= 32 + 32 * size
      start_positions = (1..size).map { |i| 32 + decode_uint256(data[32 * i, 32]) }
      start_positions.push(data.size)
      outputs = (0...size).map { |i| data[start_positions[i]...start_positions[i + 1]] }
      outputs.map { |out| decode_type(subtype, out) }
    else
      (0...size).map { |i| decode_type(subtype, data[(32 + subtype.size * i)..]) }
    end
  end
end
module AbiCoderRb
  def decode_fixed_array(type, data)
    l = type.dim
    subtype = type.subtype
    if subtype.dynamic?
      start_positions = (0...l).map { |i| decode_uint256(data[32 * i, 32]) }
      start_positions.push(data.size)
      outputs = (0...l).map { |i| data[start_positions[i]...start_positions[i + 1]] }
      outputs.map { |out| decode_type(subtype, out) }
    else
      (0...l).map { |i| decode_type(subtype, data[subtype.size * i, subtype.size]) }
    end
  end
end
module AbiCoderRb
  def decode_primitive_type(type, data)
    result =
      case type
      when Uint
        decode_uint256(data[0, 32])
      when Int
        abi_to_int_signed(bin_to_hex(data[0, 32]), type.bits)
      when Bool
        data[31] == BYTE_ONE
      when String
        size = decode_uint256(data[0, 32])
        data[32...(32 + size)].force_encoding("UTF-8")
      when Bytes
        size = decode_uint256(data[0, 32])
        data[32...(32 + size)]
      when FixedBytes
        data[0, type.length]
      when Address
        bin_to_hex(data[12...32]).force_encoding("UTF-8")
      else
        raise DecodingError, "Unknown primitive type: #{type.class.name} #{type.format}"
      end
    result = after_decoding_action.call(type.format, result) if after_decoding_action
    result
  end
  private
  def decode_uint256(bin)
    bin_to_hex(bin).to_i(16)
  end
end
module AbiCoderRb
  def decode_tuple(type, data)
    decode_types(type.types, data)
  end
  private
  def decode_types(types, data)
    start_positions = start_positions(types, data)
    types.map.with_index do |type, index|
      start_position = start_positions[index]
      decode_type(type, data[start_position..])
    end
  end
  def start_positions(types, data)
    start_positions = ::Array.new(types.size)
    offset = 0
    types.each_with_index do |type, index|
      if type.dynamic?
        start_positions[index] = decode_uint256(data[offset, 32])
        offset += 32
      else
        start_positions[index] = offset
        offset += type.size
      end
    end
    start_positions
  end
end
module AbiCoderRb
  def decode(type_str, data)
    raise DecodingError, "Empty data" if data.nil? || data.empty?
    decode_type(Type.parse(type_str), data)
  end
  private
  def decode_type(type, data)
    case type
    when Tuple ## todo: support empty (unit) tuple - why? why not?
      decode_tuple(type, data)
    when FixedArray # static-sized arrays
      decode_fixed_array(type, data)
    when Array
      decode_array(type, data)
    else
      decode_primitive_type(type, data)
    end
  end
end
module AbiCoderRb
  def encode_array(type, args, packed = false)
    raise ArgumentError, "arg must be an array" unless args.is_a?(::Array)
    _encode_array(type: type, args: args, packed: packed)
  end
  private
  def _encode_array(type:, args:, packed: false)
    head = "".b
    tail = "".b
    head += encode_uint256(args.size) if type.is_a?(Array) && !packed
    subtype = type.subtype
    args.each do |arg|
      if subtype.dynamic?
        raise "#{type.class} with dynamic inner type is not supported in packed mode" if packed
        head += encode_uint256(32 * args.size + tail.size) # 当前数据的位置指针
        tail += encode_type(subtype, arg)
      else
        head += encode_type(subtype, arg)
      end
    end
    head + tail
  end
end
module AbiCoderRb
  def encode_fixed_array(type, args, packed = false)
    raise ArgumentError, "arg must be an array" unless args.is_a?(::Array)
    raise ArgumentError, "Wrong array size: found #{args.size}, expecting #{type.dim}" unless args.size == type.dim
    _encode_array(type: type, args: args, packed: packed)
  end
end
module AbiCoderRb
  def encode_primitive_type(type, arg, packed = false)
    arg = before_encoding_action.call(type.format, arg) if before_encoding_action
    case type
    when Uint
      encode_uint(arg, type.bits, packed)
    when Int
      encode_int(arg, type.bits, packed)
    when Bool
      encode_bool(arg, packed)
    when String
      encode_string(arg, packed)
    when FixedBytes
      encode_bytes(arg, length: type.length, packed: packed)
    when Bytes
      encode_bytes(arg, packed: packed)
    when Address
      encode_address(arg, packed)
    else
      raise EncodingError, "Unknown type: #{type}"
    end
  end
  def encode_uint(arg, bits, packed = false)
    raise ArgumentError, "arg is not integer: #{arg}" unless arg.is_a?(Integer)
    raise ValueOutOfBounds, arg unless arg >= 0 && arg < 2**bits
    if packed
      lpad_int(arg, bits / 8)
    else
      lpad_int(arg)
    end
  end
  def encode_uint256(arg)
    encode_uint(arg, 256)
  end
  def encode_int(arg, bits, packed = false)
    raise ArgumentError, "arg is not integer: #{arg}" unless arg.is_a?(Integer)
    if packed
      hex_to_bin(int_to_abi_signed(arg, bits))
    else
      hex_to_bin(int_to_abi_signed_256bit(arg))
    end
  end
  def encode_bool(arg, packed = false)
    raise ArgumentError, "arg is not bool: #{arg}" unless arg.is_a?(TrueClass) || arg.is_a?(FalseClass)
    if packed
      arg ? BYTE_ONE : BYTE_ZERO
    else
      lpad(arg ? BYTE_ONE : BYTE_ZERO) ## was  lpad_int( arg ? 1 : 0 )
    end
  end
  def encode_string(arg, packed = false)
    raise EncodingError, "Expecting string: #{arg}" unless arg.is_a?(::String)
    arg = arg.b if arg.encoding != "BINARY" ## was: name == 'UTF-8', wasm
    raise ValueOutOfBounds, "Integer invalid or out of range: #{arg.size}" if arg.size > UINT_MAX
    if packed
      arg
    else
      size = lpad_int(arg.size)
      value = rpad(arg, ceil32(arg.size))
      size + value
    end
  end
  def encode_bytes(arg, length: nil, packed: false)
    raise EncodingError, "Expecting string: #{arg}" unless arg.is_a?(::String)
    arg = arg.b if arg.encoding != Encoding::BINARY
    if length # fixed length type
      raise ValueOutOfBounds, "invalid bytes length #{arg.size}, should be #{length}" if arg.size > length
      raise ValueOutOfBounds, "invalid bytes length #{length}" if length < 0 || length > 32
      packed ? arg : rpad(arg)
    else # variable length type  (if length is nil)
      raise ValueOutOfBounds, "Integer invalid or out of range: #{arg.size}" if arg.size > UINT_MAX
      if packed
        arg
      else
        size =  lpad_int(arg.size)
        value = rpad(arg, ceil32(arg.size))
        size + value
      end
    end
  end
  def encode_address(arg, packed = false)
    if arg.is_a?(Integer)
      packed ? lpad_int(arg, 20) : lpad_int(arg)
    elsif arg.is_a?(::String)
      if arg.size == 20
        arg = arg.b if arg.encoding != Encoding::BINARY
        packed ? arg : lpad(arg)
      elsif arg.size == 40
        packed ? hex_to_bin(arg) : lpad_hex(arg)
      elsif arg.size == 42 && arg[0, 2] == "0x" ## todo/fix: allow 0X too - why? why not?
        arg = arg[2..-1] ## cut-off leading 0x
        packed ? hex_to_bin(arg) : lpad_hex(arg)
      else
        raise EncodingError, "Could not parse address: #{arg}"
      end
    end
  end
end
module AbiCoderRb
  def encode_tuple(tuple, args, packed = false)
    raise "#{tuple.class} with multi inner types is not supported in packed mode" if packed && tuple.types.size > 1
    encode_types(tuple.types, args, packed)
  end
  private
  def encode_types(types, args, packed = false)
    raise ArgumentError, "args must be an array" unless args.is_a?(::Array)
    unless args.size == types.size
      raise ArgumentError,
            "Wrong number of args: found #{args.size}, expecting #{types.size}"
    end
    head_size = types.map { |type| type.size || 32 }.sum
    head = "".b # 如果是动态类型，头部是指针；如果是静态类型，头部是数据
    tail = "".b # 使用二进制字符串
    types.each_with_index do |type, i|
      if !type.dynamic? || packed
        head += encode_type(type, args[i], packed)
      else
        head += encode_uint256(head_size + tail.size)
        tail += encode_type(type, args[i])
      end
    end
    head + tail
  end
end
module AbiCoderRb
  def encode(typestr_or_typestrs, value_or_values, packed = false)
    if typestr_or_typestrs.is_a?(::Array)
      raise EncodingError, "values should be an array" unless value_or_values.is_a?(::Array)
      typestrs = typestr_or_typestrs
      values = value_or_values
      typestrs.map.with_index do |typestr, i|
        value = values[i]
        encode(typestr, value, packed)
      end.join
    else
      typestr = typestr_or_typestrs
      value = value_or_values
      raise EncodingError, "Value can not be nil" if value.nil?
      parsed = Type.parse(typestr)
      encode_type(parsed, value, packed)
    end
  end
  private
  def encode_type(type, value, packed = false)
    if type.is_a?(Tuple)
      encode_tuple(type, value, packed)
    elsif type.is_a?(Array)
      encode_array(type, value, packed)
    elsif type.is_a?(FixedArray)
      encode_fixed_array(type, value, packed)
    else
      encode_primitive_type(type, value, packed)
    end
  end
end
module AbiCoderRb
  class Type
    class ParseError < StandardError; end
    class Parser
      TUPLE_TYPE_RX = /^\((.*)\)
                       ((\[[0-9]*\])*)
                     /x
      def self.parse(type)
        type = type.strip
        if type =~ TUPLE_TYPE_RX
          types = _parse_tuple_type(::Regexp.last_match(1))
          dims = _parse_dims(::Regexp.last_match(2))
          parsed_types = types.map { |t| parse(t) }
          return _parse_array_type(Tuple.new(parsed_types), dims)
        end
        base, sub, dims = _parse_base_type(type)
        sub ||= 256 if type.start_with?("uint") || type.start_with?("int") # default to 256 if no sub given
        _validate_base_type(base, sub)
        subtype =  case base
                   when "string"  then   String.new
                   when "bytes"   then   sub ? FixedBytes.new(sub) : Bytes.new
                   when "uint"    then   Uint.new(sub)
                   when "int"     then   Int.new(sub)
                   when "address" then   Address.new
                   when "bool"    then   Bool.new
                   else
                     raise ParseError, "Unrecognized type base: #{base}"
                   end
        _parse_array_type(subtype, dims)
      end
      BASE_TYPE_RX = /([a-z]*)
                      ([0-9]*)
                      ((\[[0-9]*\])*)
                     /x
      def self._parse_base_type(str)
        _, base, subscript, dimension = BASE_TYPE_RX.match(str).to_a
        sub = subscript == "" ? nil : subscript.to_i
        dims = _parse_dims(dimension)
        [base, sub, dims]
      end
      def self._parse_dims(str)
        dims = str.scan(/\[[0-9]*\]/)
        dims.map do |dim|
          size = dim[1...-1]
          size == "" ? -1 : size.to_i
        end
      end
      def self._parse_array_type(subtype, dims)
        dims.each do |dim|
          subtype = if dim == -1
                      Array.new(subtype)
                    else
                      FixedArray.new(subtype, dim)
                    end
        end
        subtype
      end
      def self._validate_base_type(base, sub)
        case base
        when "string"
          raise ParseError, "String cannot have suffix" if sub
        when "bytes"
          raise ParseError, "Maximum 32 bytes for fixed-length bytes" if sub && sub > 32
        when "uint", "int"
          raise ParseError, "Integer type must have numerical suffix"  unless sub
          raise ParseError, "Integer size out of bounds" unless sub >= 8 && sub <= 256
          raise ParseError, "Integer size must be multiple of 8" unless sub % 8 == 0
        when "address"
          raise ParseError, "Address cannot have suffix" if sub
        when "bool"
          raise ParseError, "Bool cannot have suffix" if sub
        else
          raise ParseError, "Unrecognized type base: #{base}"
        end
      end
      def self._parse_tuple_type(str)
        depth     = 0
        collected = []
        current   = ""
        str.each_char do |c|
          case c
          when ","
            if depth == 0
              collected << current
              current = ""
            else
              current += c
            end
          when "("
            depth += 1
            current += c
          when ")"
            depth -= 1
            current += c
          else
            current += c
          end
        end
        collected << current unless current.empty?
        collected
      end
    end # class Parser
  end #  class Type
end  # module ABI
module AbiCoderRb
  class Type
    def self.parse(type) ## convenience helper
      Parser.parse(type)
    end
    def size
    end
    def dynamic?
      size.nil?
    end
    def format
    end
  end
  class Address < Type
    def size
      32
    end
    def format
      "address"
    end
    def ==(other)
      other.is_a?(Address)
    end
  end # class Address
  class Bytes < Type
    def size
      nil
    end
    def format
      "bytes"
    end
    def ==(other)
      other.is_a?(Bytes)
    end
  end # class Bytes
  class FixedBytes < Type
    attr_reader :length
    def initialize(length)
      @length = length # in bytes (1,2,...32)
    end
    def size
      32
    end
    def format
      "bytes#{@length}"
    end
    def ==(other)
      other.is_a?(FixedBytes) && @length == other.length
    end
  end # class FixedBytes
  class Int < Type
    attr_reader :bits
    def initialize(bits = 256)
      @bits = bits # in bits (8,16,...256)
    end
    def size
      32
    end
    def format
      "int#{@bits}"
    end
    def ==(other)
      other.is_a?(Int) && @bits == other.bits
    end
  end # class Int
  class Uint < Type
    attr_reader :bits
    def initialize(bits = 256)
      @bits = bits # in bits (8,16,...256)
    end
    def size
      32
    end
    def format
      "uint#{@bits}"
    end
    def ==(other)
      other.is_a?(Uint) && @bits == other.bits
    end
  end # class  Uint
  class Bool < Type
    def size
      32
    end
    def format
      "bool"
    end
    def ==(other)
      other.is_a?(Bool)
    end
  end # class Bool
  class String < Type
    def size
      nil
    end
    def format
      "string"
    end
    def ==(other)
      other.is_a?(String)
    end
  end # class String
  class Array < Type
    attr_reader :subtype
    def initialize(subtype)
      @subtype = subtype
    end
    def size
      nil
    end
    def format
      "#{@subtype.format}[]"
    end
    def ==(other)
      other.is_a?(Array) && @subtype == other.subtype
    end
  end  # class Array
  class FixedArray < Type
    attr_reader :subtype, :dim
    def initialize(subtype, dim)
      @subtype = subtype
      @dim = dim
    end
    def size
      @subtype.dynamic? ? nil : @dim * subtype.size
    end
    def format
      "#{@subtype.format}[#{@dim}]"
    end
    def ==(other)
      other.is_a?(FixedArray) &&
        @dim == other.dim &&
        @subtype == other.subtype
    end
  end  # class FixedArray
  class Tuple < Type
    attr_reader :types
    def initialize(types)
      @types = types
    end
    def size
      s = 0
      has_dynamic = false
      @types.each do |type|
        ts = type.size
        if ts.nil?
          has_dynamic = true
        else
          s += ts
        end
      end
      return if has_dynamic
      s
    end
    def format
      "(#{@types.map { |t| t.format }.join(",")})" ## rebuild minimal string
    end
    def ==(other)
      other.is_a?(Tuple) && @types == other.types
    end
  end # class Tuple
end  # module ABI
module AbiCoderRb
  def hex_to_bin(hex)
    hex = hex[2..] if %w[0x 0X].include?(hex[0, 2]) ## cut-of leading 0x or 0X if present
    hex.scan(/../).map { |x| x.hex.chr }.join
  end
  alias hex hex_to_bin
  def bin_to_hex(bin)
    bin.each_byte.map { |byte| "%02x" % byte }.join
  end
  def hex?(str)
    str.start_with?("0x") && str.length.even? && str[2..].match?(/\A\b[0-9a-fA-F]+\b\z/)
  end
  def rpad(bin, l = 32) ## note: same as builtin String#ljust !!!
    return bin if bin.size >= l
    bin + BYTE_ZERO * (l - bin.size)
  end
  def lpad(bin, l = 32) ## note: same as builtin String#rjust !!!
    return bin  if bin.size >= l
    BYTE_ZERO * (l - bin.size) + bin
  end
  def lpad_int(n, l = 32)
    unless n.is_a?(Integer) && n >= 0 && n <= UINT_MAX
      raise ArgumentError,
            "Integer invalid or out of range: #{n}"
    end
    hex = n.to_s(16)
    hex = "0#{hex}" if hex.length.odd? # wasm, no .odd?
    bin = hex_to_bin(hex)
    lpad(bin, l)
  end
  def lpad_hex(hex)
    raise TypeError, "Value must be a string" unless hex.is_a?(::String)
    raise TypeError, "Non-hexadecimal digit found" unless hex =~ /\A[0-9a-fA-F]*\z/
    bin = hex_to_bin(hex)
    lpad(bin)
  end
  def ceil32(x)
    x % 32 == 0 ? x : (x + 32 - x % 32)
  end
  def int_to_abi_signed(value, bits)
    min = -2**(bits - 1)
    max = 2**(bits - 1) - 1
    raise "Value out of range" if value < min || value > max
    value = (1 << bits) + value if value < 0
    hex_str = value.to_s(16)
    hex_str.rjust(bits / 4, "0")
  end
  def int_to_abi_signed_256bit(value)
    min = -2**255
    max = 2**255 - 1
    raise "Value out of range" if value < min || value > max
    value = (1 << 256) + value if value < 0
    hex_str = value.to_s(16)
    hex_str.rjust(64, "0")
  end
  def abi_to_int_signed(hex_str, bits)
    hex_str = "0x#{hex_str}" if hex_str[0, 2] != "0x" || hex_str[0, 2] != "0X"
    expected_length = bits / 4
    extended_hex_str = if hex_str.length < expected_length
                         extend_char = hex_str[0] == "f" ? "f" : "0"
                         extend_char * (expected_length - hex_str.length) + hex_str
                       else
                         hex_str
                       end
    binary_str = extended_hex_str.to_i(16).to_s(2).rjust(bits, extended_hex_str[0])
    if binary_str[0] == "1" # 负数
      -((binary_str.tr("01", "10").to_i(2) + 1) & ((1 << bits) - 1))
    else # 正数
      binary_str.to_i(2)
    end
  end
end
module AbiCoderRb
  VERSION = "0.2.8"
end
module AbiCoderRb
  class DecodingError < StandardError; end
  class EncodingError < StandardError; end
  class ValueError < StandardError; end
  class ValueOutOfBounds < ValueError; end
  BYTE_EMPTY = "".b.freeze
  BYTE_ZERO  = "\x00".b.freeze
  BYTE_ONE   = "\x01".b.freeze ## note: used for encoding bool for now
  UINT_MAX = 2**256 - 1   ## same as 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  UINT_MIN = 0
  INT_MAX  = 2**255 - 1   ## same as  57896044618658097711785492504343953926634992332820282019728792003956564819967
  INT_MIN  = -2**255      ## same as -57896044618658097711785492504343953926634992332820282019728792003956564819968
  attr_accessor :before_encoding_action, :after_decoding_action
  def before_encoding(action)
    self.before_encoding_action = action
  end
  def after_decoding(action)
    self.after_decoding_action = action
  end
end
class EventDecoder
  include AbiCoderRb
  attr_reader :event_abi,
              :indexed_topic_inputs, :indexed_topic_fields,
              :data_inputs, :data_fields, :data_type_str
  def initialize(event_abi)
    @event_abi = event_abi
    @indexed_topic_inputs, @data_inputs = event_abi["inputs"].partition { |input| input["indexed"] }
    @indexed_topic_fields = fields_of(@indexed_topic_inputs)
    @data_fields = fields_of(@data_inputs)
    @data_type_str = fields_type_str(@data_fields)
    after_decoding lambda { |type, value|
      if type == "address"
        "0x#{value}"
      elsif type.start_with?("bytes")
        "0x#{bin_to_hex(value)}"
      else
        value
      end
    }
  end
  def data_fields_flatten(sep: ".")
    flat_fields(@data_fields, sep: sep)
  end
  def decode_topics(topics, with_names: false)
    topics = topics[1..] if topics.count == @indexed_topic_inputs.count + 1 && @event_abi["anonymous"] == false
    raise "topics count not match" if topics.count != @indexed_topic_inputs.count
    indexed_topic_types = @indexed_topic_inputs.map { |input| input["type"] }
    values = topics.each_with_index.map do |topic, i|
      indexed_topic_type = indexed_topic_types[i]
      decode(indexed_topic_type, hex_to_bin(topic))
    end
    if with_names
      combine(@indexed_topic_inputs.map { |input| input["name"].underscore }, values)
    else
      values
    end
  end
  def decode_data(data, flatten: true, sep: ".", with_names: false)
    return with_names ? {} : [] if @data_type_str == "()"
    data_values = decode(@data_type_str, hex_to_bin(data))
    case flatten
    when true
      if with_names
        combine(data_field_names(flatten: true, sep: sep), data_values.flatten)
      else
        data_values.flatten
      end
    when false
      if with_names
        combine(data_field_names, data_values)
      else
        data_values
      end
    end
  end
  private
  def fields_of(inputs)
    inputs.map do |input|
      if input["type"] == "tuple"
        [input["name"].underscore, fields_of(input["components"])]
      elsif input["type"] == "enum"
        [input["name"].underscore, "uint8"]
      else
        [input["name"].underscore, input["type"]]
      end
    end
  end
  def fields_type_str(fields)
    "(#{
      fields.map do |_name, type|
        if type.is_a?(::Array)
          fields_type_str(type)
        else
          type
        end
      end.join(",")
    })"
  end
  def flat_fields(fields, sep: ".")
    fields.map do |name, type|
      if type.is_a?(::Array)
        flat_fields(type, sep: sep).map do |n, t|
          ["#{name}#{sep}#{n}", t]
        end
      else
        [[name, type]]
      end
    end.flatten(1)
  end
  def fields_names(fields)
    fields.map do |name, type|
      if type.is_a?(::Array)
        { name => fields_names(type) }
      elsif type.is_a?(::String)
        name
      end
    end
  end
  def fields_names_flatten(fields, prefix: nil, sep: ".")
    fields.map do |name, type|
      if type.is_a?(::Array)
        fields_names_flatten(
          type,
          prefix: prefix.nil? ? name : "#{prefix}#{sep}#{name}",
          sep: sep
        )
      elsif type.is_a?(::String)
        prefix.nil? ? name : "#{prefix}#{sep}#{name}"
      end
    end.flatten
  end
  def data_field_names(flatten: false, sep: ".")
    if flatten
      fields_names_flatten(@data_fields, sep: sep)
    else
      fields_names(@data_fields)
    end
  end
  def combine(keys, values)
    result = {}
    keys.each_with_index do |key, index|
      if key.is_a?(Hash)
        key.each do |k, v|
          result[k] = combine(v, values[index])
        end
      else
        result[key] = values[index]
      end
    end
    result
  end
end
module FunctionEncoder
  extend AbiCoderRb
  class << self
    def encode_function(function_signature, params)
      raise "Invalid function signature" unless function_signature.match?(/^\w+\(.+\)$/)
      types_str = "(#{function_signature.match(/\((.*)\)/)[1]})"
      "0x#{function_id(function_signature)}#{bin_to_hex(encode(types_str, params))}"
    end
    private
    def function_id(function_signature)
      function_signature = function_signature.gsub(/\s+/, "")
      Digest::Keccak.hexdigest(function_signature, 256)[0, 8]
    end
  end
end
