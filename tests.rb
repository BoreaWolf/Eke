#!/usr/bin/env ruby

#
# Author: Riccardo Orizio (R)
# Date: 6 April 2016
# 
# Description: Tests
# 

require "base64"
require "digest/sha1"
require "openssl"

def bin_to_hex( s )
	s.each_byte.map{ |b| "%02x" % b.to_i }.join
end

def hex_to_bin( s )
	s.scan( /../ ).map{ |x| x.hex }.pack( 'c*' )
end 

def hex_to_int( s )
	s.scan( /../ ).map{ |x| x.hex }.pack( 'C*' )
end

def hex_to_string( s )
	s.scan( /../ ).map( &:hex ).map( &:chr ).join
end

# Parameters
password = "NetworkSecurity"
key_sha1 = Digest::SHA1.hexdigest( password )

# Data
data = 1645
data = data.to_s
puts "Data: #{data} #{data.class}"
#puts "Hello: #{bin_to_hex( "hello" )}"

# AES encryption
cipher = OpenSSL::Cipher::AES.new(128, :CBC)
cipher.encrypt
cipher.key = key_sha1
iv = cipher.random_iv
cipher.iv = iv
puts "Key: #{key_sha1}"
puts "IV: #{iv}"

encrypted = cipher.update( data ) + cipher.final

puts "Encrypted: #{encrypted} #{encrypted.class} #{encrypted.size}"

decipher = OpenSSL::Cipher::AES.new(128, :CBC)
decipher.decrypt
decipher.padding = 0
decipher.key = key_sha1
decipher.iv = iv

plain = decipher.update( encrypted ) + decipher.final
result = plain.unpack( "h*" )[0]

puts "Decrypted: '#{plain}' #{plain.class} #{plain.size}"
puts "Int: '#{plain.to_i}'"
puts "Result: #{result} #{result.class}"
#	puts "Other: #{result.inspect} #{result.inspect.class}"
#	[ result, result.inspect ].each{ |x|
#		puts "Bin: #{hex_to_bin( x )}"
#		puts "Int: #{hex_to_int( x )}"
#		puts "Str: #{hex_to_string( x )}"
#		puts "Sure: #{x.to_i}"
#	}

#	puts "IDK: #{hex_to_bin( result )}"
#	puts "Opposite: #{bin_to_hex( hex_to_bin( result ) )}"

