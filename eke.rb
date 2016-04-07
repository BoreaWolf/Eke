#!/usr/bin/env ruby

#
# Author: Riccardo Orizio (R)
# Date: 4 April 2016
# 
# Description: EKE implementation
# Network Security project
# 

# Imports
require "digest/sha1"
require "openssl"
require "prime"
require "socket"
require_relative "./constants.rb"

class EkeUser

	# Useful struct
	User = Struct.new( :ip, :port, :name )

	# Shared password
	@@password = "NetworkSecurity"

	def initialize( name )
		puts "Creating new EKE User '#{name}'"
		@name = name
	
		# Faster than doing it every time it's needed
		@key = Digest::SHA1.hexdigest( @@password )

		@known_clients = Array.new()

		# Threads
		@server_thread = Thread.new{ server_socket }
		@client_thread = Thread.new{ client_socket }

		@server_thread.join
		@client_thread.join
	end

	def server_socket()
		# Creating the server socket on a port
		# Trying to find the first available port
	
		@ip = "localhost"
		@server_port = -1

		# Checking which port is available
		SERVER_PORT_RANGE.each_with_index{ |port, i|
			begin
				# Checking if someone is listening on the current port
				s = TCPSocket.new( @ip, port )
				s.close
				@server_port = -1
			rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
				@server_port = port
				break
			end
		}
	
		# Checking if there is still one port available for the current client
		if @server_port == -1 then
			puts "ERROR: No more than #{MAX_CLIENTS} ports available."
			exit( -1 )	
		end
	
		# Log file
		@log_file = File.open( "#{LOG_DIR}#{@name}.#{@server_port}", "w" )

		# Creating the listening socket
		@listening_socket = TCPServer.new( @ip, @server_port )
		@log_file.puts "#{@ip}:#{@server_port} listening..."
		@log_file.flush
	 
		# Waiting for client requests
		loop{

			# Accepting incoming requests with a thread
			Thread.start( @listening_socket.accept ) do |client|
				# Reading some info about the client
				( port, ip ) = Socket.unpack_sockaddr_in( client.getpeername )
				# Reading the message
				client_first_msg = client.gets

				puts "*** First message ***"
				@log_file.puts "Received #{ip}:#{port}: #{client_first_msg}"
				@log_file.flush

				# Reading all data
				client_first_msg = parse_message( client_first_msg )
				# Name
				client_first_msg[ 0 ] = client_first_msg[ 0 ][1..-2]
				# Enc Ta
				client_first_msg[ 1 ] = hex_to_bin( client_first_msg[ 1 ][1..-2] )
				# G
				client_first_msg[ 2 ] = client_first_msg[ 2 ].to_i
				# P
				client_first_msg[ 3 ] = client_first_msg[ 3 ].to_i
				# IV
				client_first_msg[ 4 ] = hex_to_bin( client_first_msg[ 4 ][1..-2] )

				# Deciphering
				decipher = OpenSSL::Cipher::AES.new( 128, :CBC )
				decipher.decrypt
				decipher.padding = 0
				decipher.key = @key
				decipher.iv = client_first_msg[ 4 ]

				# Deciphering the data and transforming it into a number
				ta = decipher.update( client_first_msg[ 1 ] ) + decipher.final
				ta = ta.to_i
				puts "Ta: #{ta}"

				# Random number for challenging the client
				c1 = Random.new.rand( MAX_RANDOM_VALUE )
				puts "c1: #{c1}"
				# Random number in [ 1, p ), as for Sa
				sb = Random.new.rand( client_first_msg[ 3 ]-2 ) + 1
				# Other part of the ephemeral key
				tb = ( client_first_msg[ 2 ] ** sb ) % client_first_msg[ 3 ]
				# Final ephemeral key
				ephemeral_key = ( ta ** sb ) % client_first_msg[ 3 ]
				puts "Eph: #{ephemeral_key}"

				# Other ciphering
				cipher = OpenSSL::Cipher::AES.new( 128, :CBC )
				cipher.encrypt
				cipher.key = @key
				iv = cipher.random_iv
				cipher.iv = iv

				# Data to encrypt:
				#  - partial ephemeral key
				#  - challenge
				data = [ tb.to_s, c1.to_s ].to_s
				puts "Data: #{data}"

				# Encrypting
				enc_data = cipher.update( data ) + cipher.final

				# Message
				msg = [ # My identity
						@name,
						# Encrypted data
						bin_to_hex( enc_data ),
						# IV
						bin_to_hex( iv ) ].to_s

				puts "Sending #{msg}"
				@log_file.puts "Sending #{ip}:#{port}(#{client_first_msg[ 0 ]}): #{msg}"
				@log_file.flush

				# Answering to the client
				client.puts msg
				# Waiting for the answer with the challenge
				client_second_msg = client.gets
				puts "*** Second message ***"
				@log_file.puts "Received #{ip}:#{port}: #{client_second_msg}"
				@log_file.flush

				# Parsing th message
				client_second_msg = parse_message( client_second_msg )
				client_second_msg[ 0 ] = hex_to_bin( client_second_msg[ 0 ][1..-2] )

				# Deciphering with the ephemeral key
				eph_key_digest = Digest::SHA1.hexdigest( ephemeral_key.to_s )
				decipher_eph = OpenSSL::Cipher::AES.new( 128, :CBC )
				decipher_eph.decrypt
				decipher_eph.padding = 0
				decipher_eph.key = eph_key_digest

				# Decrypting data
				data = decipher_eph.update( client_second_msg[ 0 ] ) + decipher_eph.final
				data = parse_message( data.slice( 0..(data.index( ']' )+1 ) ) )
				# Challenge C1
				data[ 0 ] = data[ 0 ][1..-2].to_i
				# Challenge C2
				c2 = data[ 1 ][1..-2].to_i

				puts "Received challenges:"
				puts "c1: #{data[ 0 ]}"
				puts "c2: #{c2}"
				$stdin.flush

				# Checking the challenge
				if data[ 0 ] != c1 then
					[ $stdin, @log_file ].each{ |x|
						x.puts "EKE authentication failed: Challenge failed with #{ip}:#{port}(#{client_first_msg[ 0 ]}): #{c1} != #{data[ 0 ]}"
						x.flush
					}
				else
					# Answering the client with his challenge
					cipher_eph = OpenSSL::Cipher::AES.new( 128, :CBC )
					cipher_eph.encrypt
					cipher_eph.key = eph_key_digest

					data = [ c2.to_s ].to_s
					puts "Sending last challenge: #{data}"
					enc_data = cipher_eph.update( data ) + cipher_eph.final

					# Creating the message for the mutual authentication
					msg = [ bin_to_hex( enc_data ) ].to_s

					@log_file.puts "Sending #{ip}:#{port}(#{client_first_msg[ 0 ]}): #{msg}"
					@log_file.flush

					client.puts msg

					puts "EKE authentication succeeded with #{client_first_msg[ 0 ]}"
					$stdin.flush
					@log_file.puts "EKE authentication succeeded with #{ip}:#{port}(#{client_first_msg[ 0 ]})"
					@log_file.flush
				end

				# Closing the connection with the client
				client.close
			end
		}
	end
	
	def client_socket()
		loop do
			case ( user_choice = show_menu() )
			when 1 then
				eke_init()
			when 0 then
				close()
			end
			break if user_choice == 0
		end
	end

	def scan_for_clients()
		# Clearing all clients
		@known_clients.clear
		# Scanning all ports and checking if anyone answers the request
		# If so I save him
		SERVER_PORT_RANGE.each_with_index{ |port, i|
			begin
				# Checking if someone is listening on the current port
				if port != @server_port then
					s = TCPSocket.new( @ip, port )
					s.close
					# Saving the new client found
					@known_clients.push( User.new( @ip, port, i ) )
				end
			rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
			end
		}
		puts "#{@known_clients.size} client#{@known_clients.size != 1 ? 's' : ''} available."
	end

	def choose_client()
		scan_for_clients()
		if @known_clients.empty? == true then
			return -1
		else
			loop do
				puts "Choose a client by its number:"
				print_clients_list()
				return_value = to_number( $stdin.gets.chomp )
				if return_value >= 0 and return_value < @known_clients.size then
					return return_value
				end
			end
		end
	end

	def print_clients_list()
		if @known_clients.empty? != true then
			puts "Known clients: "
			@known_clients.each_with_index{ |client, i|
				puts "#{i}) #{client.ip}:#{client.port}" }
		else
			puts "No known clients yet."
		end
	end
		
	def eke_init()
		puts "Ready to start with EKE authentication"
		client_number = choose_client()
		if client_number != -1 then
			eke_authentication( client_number )
		else
			puts "No clients available yet."
		end
	end

	def eke_authentication( client_number )
		puts "Starting authentication with #{@known_clients[ client_number ]}"

		# Opening a socket with the other client
		socket = TCPSocket.new( @known_clients[ client_number ][ :ip ],
								@known_clients[ client_number ][ :port ] )

		puts "*** First message ***"
		
		# Diffie-Hellman parameters
		# Random prime number
		p = Prime.first( PRIME_LIST_SIZE ).sample
		# Random number in [ 1, p ):
		#  - p-2:
		#    * p-1 because i don't want p to be chosen
		#    * -1 because the random could give 0 as result and i don't want it,
		#      so i'll add 1 after, but i could get again p in this way
		sa = Random.new.rand( p-2 ) + 1
		# A generator of Zp* TODO
		g = 7
		# Part of the temporary key
		ta = ( g ** sa ) % p

		# AES Encryption on 128 bit key and Cipher Block Chaining block cipher
		# mode
		cipher = OpenSSL::Cipher::AES.new( 128, :CBC )
		cipher.encrypt
		# SHA-1 of the password, used to encrypt ta
		cipher.key = @key
		iv = cipher.random_iv
		cipher.iv = iv
		
		# Encrypting data to be sent on the network
		# NB! Data needs to be a String!
		data = ta.to_s
		enc_ta = cipher.update( data ) + cipher.final

		puts "Ta: #{ta}"

		# Creating the first message:
		# - My identity 
		# - Encrypted ephemeral key part
		# - A generator of Zp*
		# - A random prime number
		# - Initialization vector for AES
		msg = [ @name, bin_to_hex( enc_ta ), g, p, bin_to_hex( iv ) ].to_s

		puts "Sending: #{msg}"

		# Sending the message
		socket.puts msg

		# Waiting for his response
		server_first_msg = socket.gets
		puts "*** Second message ***"
		puts "Received: #{server_first_msg}"

		# Reading data
		server_first_msg = parse_message( server_first_msg )
		# Name
		server_first_msg[ 0 ] = server_first_msg[ 0 ][1..-2]
		# Enc data
		server_first_msg[ 1 ] = hex_to_bin( server_first_msg[ 1 ][1..-2] )
		# IV
		server_first_msg[ 2 ] = hex_to_bin( server_first_msg[ 2 ][1..-2] )

		# Decrypting
		decipher = OpenSSL::Cipher::AES.new( 128, :CBC )
		decipher.decrypt
		decipher.padding = 0
		decipher.key = @key
		decipher.iv = server_first_msg[ 2 ]

		# Deciphering the data and transforming it into a number
		data = decipher.update( server_first_msg[ 1 ] ) + decipher.final
		# Truncating what is meaningless from the decrypted data
		data = parse_message( data.slice( 0..( data.index( ']' )+1 ) ) )
		# Tb
		data[ 0 ] = data[ 0 ][1..-2].to_i
		# Challenge C1
		data[ 1 ] = data[ 1 ][1..-2].to_i

		puts "c1: #{data[ 1 ]}"

		# Constructing the ephemeral key
		ephemeral_key = ( data[ 0 ] ** sa ) % p
		puts "Eph: #{ephemeral_key}"
		# Challenge
		c2 = Random.new.rand( MAX_RANDOM_VALUE )
		puts "c2: #{c2}"

		# Encrypting data with the ephemeral key
		eph_key_digest = Digest::SHA1.hexdigest( ephemeral_key.to_s )
		cipher_eph = OpenSSL::Cipher::AES.new( 128, :CBC )
		cipher_eph.encrypt
		cipher_eph.key = eph_key_digest

		data = [ data[ 1 ].to_s, c2.to_s ].to_s
		puts "Sending Challenge: #{data}"
		enc_data = cipher_eph.update( data ) + cipher_eph.final

		# Sending the challenge encrypted
		socket.puts [ bin_to_hex( enc_data ) ].to_s
		# Waiting for the challenge response
		server_second_msg = socket.gets
		puts "Received: #{server_second_msg}"

		server_second_msg = parse_message( server_second_msg )
		server_second_msg[ 0 ] = hex_to_bin( server_second_msg[ 0 ][1..-2] )

		decipher_eph = OpenSSL::Cipher::AES.new( 128, :CBC )
		decipher_eph.decrypt
		decipher_eph.padding = 0
		decipher_eph.key = eph_key_digest

		# Decrypting last challenge
		data = decipher_eph.update( server_second_msg[ 0 ] ) + decipher_eph.final
		data = parse_message( data.slice( 0..(data.index( ']' )+1 ) ) )
		# Challenge C2
		data[ 0 ] = data[ 0 ][1..-2].to_i
		puts "Challenge: #{data}"

		# Checking the challenge
		if data[ 0 ] != c2 then
			puts "EKE authentication failed: Challenge failed with #{ip}:#{port}(#{server_first_msg[ 0 ]}): #{c1} != #{data[ 0 ]}"
			$stdin.flush
		else
			puts "EKE authentication succeeded with #{server_first_msg[ 0 ]}"
		end

		# Closing the connection
		socket.close
	end

	def close()
		puts "Closing."

		# Server part
		@log_file.close
		@listening_socket.close
		@server_thread.exit

		# Client part
		@client_thread.exit
	end

	def show_menu()
		puts "What do you want to do?"
		puts "1) EKE"
		puts "0) Close"
		loop do
			return_value = to_number( $stdin.gets.chomp )
			if return_value == 0 or return_value == 1 then
				return return_value
			end
		end
	end

	def to_number( string )
		num = string.to_i
		num if num.to_s == string
	end

	# Splitting the string into an array
	def parse_message( msg )
		msg = msg[1..-3].split( ", " )
	end

	# Coding and decoding ciphered data
	def bin_to_hex( s )
		s.each_byte.map{ |b| "%02x" % b.to_i }.join
	end

	def hex_to_bin( s )
		s.scan( /../ ).map{ |x| x.hex }.pack( 'c*' )
	end 
end

def random_name()
	(0..(rand(7)+3)).map{ ('a'..'z').to_a.sample }.join.capitalize
end

# Creating a new Eke user
name = ""
if ARGV[ 0 ].class == NilClass then
	name = random_name()
else
	name = ARGV[ 0 ]
end

EkeUser.new( name )

print "٩(๑❛ワ❛๑)و"

