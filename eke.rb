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
require "openssl" # TODO Check if needed
require "prime"
require "socket"
require_relative "./constants.rb"

class EkeUser

	# Useful struct
	User = Struct.new( :ip, :port, :name )

	# ...
	@@password = "NetworkSecurity"

	def initialize()
		puts "Creating new EKE User"
		puts "Insert your name:"
		@name = gets.chomp
	
		# Faster than doing it every time it's needed
		@key = Digest::SHA1.hexdigest @@password

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
	
		#	hostname = socket.gethostname()
		#	hostname = "127.0.0.1"
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

				@log_file.puts "Received request from #{ip}:#{port}"
				@log_file.puts "Received #{client_first_msg}"
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
				#client_first_msg[ 4 ] = hex_to_bin( client_first_msg[ 4 ][1..-2] )

				puts "Parsed:"
				client_first_msg.each{ |x|
					puts "#{x} #{x.size} #{x.class}"
				}

				#	puts "Parsed:"
				#	puts "Name: #{client_first_msg[0][1..-2]} #{client_first_msg[0].size}"
				#	puts "Enc: #{hex_to_bin( client_first_msg[1][1..-2] )} #{client_first_msg[1].size}"
				#	puts "G: #{client_first_msg[2]} #{client_first_msg[2].class}"
				#	puts "P: #{client_first_msg[3]} #{client_first_msg[3].class}"
				#	puts "IV: #{hex_to_bin( client_first_msg[4][1..-2] )} #{client_first_msg[4].size}"
				@log_file.flush

				# Deciphering
				decipher = OpenSSL::Cipher::AES.new( 128, :CBC )
				decipher.decrypt
				decipher.padding = 0
				decipher.key = @key
				#decipher.iv = client_first_msg[ 4 ]
				puts "Deciphering with: "
				puts "key: #{@key}"
				ta = decipher.update( client_first_msg[ 1 ] ) + decipher.final
				puts "Ta: #{ta}"
				ta = hex_to
				puts "Ta2: #{hex_to_bin( ta )} "
				$stdin.flush
				@log_file.puts "Ta: #{ta}"
				@log_file.flush

				# Random number for challenging the client
				c1 = ( 0..100 ).to_a.sample
				puts "c1: #{c1}"
				# Random number in [ 1, p )
				sb = ( 1..client_first_msg[3]-1 ).to_a.sample
				puts "sb: #{sb}"
				# Other part of the ephemeral key
				tb = ( client_first_msg[2] ** sb ) % client_first_msg[3]
				puts "tb: #{tb}"
				# Final ephemeral key
				ephemeral_key = ( ta ** sb ) % client_first_msg[3]
				puts "eph: #{ephemeral_key}"

				# Other ciphering

				# Encrypted data for the client
				enc_tb = [	# Second part of the key
							:key_part => cipher( tb.to_s ) + cipher.final,
							# Challenge
							:challenge => cipher( c1.to_s ) + cipher.final ]

				msg = [ # My identity
						:name => @name,
						# Encrypted ephemeral key part
						:enc_tb => enc_tb ]

				@log_file.puts msg
				@log_file.flush

				# Answering to the client
				#	client.puts msg

#	decipher = OpenSSL::Cipher::AES.new(128, :CBC)
#	decipher.decrypt
#	decipher.key = key
#	decipher.iv = iv
#	
#	plain = decipher.update(encrypted) + decipher.final
				#	client.puts "Sbra"
				#	client.puts "Bye"
				client.close
			end
		}

# Another way to loop, instead of the while
#		loop
#		{
#			Thread.start(server.accept) do |client|
#				client.puts(Time.now.ctime) # Send the time to the client
#				client.puts "Closing the connection. Bye!"
#				client.close                # Disconnect from the client
#			end
#		}
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

		#	s = Socket.new( :INET, :STREAM, 0 )
		#	# TODO: Fix this to be dynamic
		#	# Setting up the connection to the server
		#	hostname = socket.gethostname()
		#	client_port = server_port_range[ 0 ]
	
		#	puts "Client connecting to #{hostname}:#{client_port}"
		#	
		#	s.connect( Socket.sockaddr_in( client_port, hostname ) )
		#	s.close 
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
				return_value = to_number( gets.chomp )
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

# AES encryption
#	cipher = OpenSSL::Cipher::AES.new(128, :CBC)
#	cipher.encrypt
#	key = cipher.random_key
#	iv = cipher.random_iv
#	
#	encrypted = cipher.update(data) + cipher.final
#	...
#	decipher = OpenSSL::Cipher::AES.new(128, :CBC)
#	decipher.decrypt
#	decipher.key = key
#	decipher.iv = iv
#	
#	plain = decipher.update(encrypted) + decipher.final

		puts "Socket open"
		
		# Diffie-Hellman parameters
		# Random prime number
		p = Prime.first( PRIME_LIST_SIZE ).sample
		# Random number in [ 1, p )
		sa = ( 1..p-1 ).to_a.sample
		# A generator of Zp* TODO
		g = 7
		# Part of the temporary key
		ta = ( g ** sa ) % p

		# AES Encryption on 128 bit key and Cipher Block Chaining block cipher
		# mode
		cipher = OpenSSL::Cipher::AES.new( 128, :CBC )
		cipher.encrypt
		# SHA-1 of the password, used to encrypt ta
		key = @key
		# iv = cipher.random_iv
		
		# Encrypting data to be sent on the network
		# NB! Data needs to be a String!
		# NNB! Data needs to be represented as hex!
		data = ta.to_s
		data = bin_to_hex( data )
		enc_ta = cipher.update( data ) + cipher.final

		puts "Ta: #{ta} #{ta.class} => #{ta.to_s} #{ta.to_s.class}"
		puts "Enc: #{enc_ta} (#{enc_ta.class} #{enc_ta.size})"
		puts "Enc Hex: #{bin_to_hex( enc_ta )}"
		#	puts "IV: #{iv} => #{iv.to_s} (#{iv.class} #{iv.size})"
		#	puts "IV Hex: #{bin_to_hex( iv )}"

		# Creating the first message:
		# - My identity 
		# - Encrypted ephemeral key part
		# - A generator of Zp*
		# - A random prime number
		# - Initialization vector for AES
		#msg = [ @name, bin_to_hex( enc_ta ), g, p, bin_to_hex( iv ) ].to_s
		msg = [ @name, bin_to_hex( enc_ta ), g, p ].to_s

		puts "Sending: #{msg}"

		# Sending the message
		socket.puts msg

		# Waiting for his response
		#	server_first_msg = socket.gets
		#	puts "Received: #{server_first_msg}"
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
			return_value = to_number( gets.chomp )
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

#	def random_name()
#		(0..(rand(7)+3)).map{ ('a'..'z').to_a.sample }.join.capitalize
#	end

# Creating a new Eke user
#	name = ""
#	if ARGV[ 0 ].class == NilClass then
#		name = random_name()
#	else
#		name = ARGV[ 0 ].dup
#	end
#	
#	puts "#{ARGV}"
#	
#	puts "Before: '#{name}' #{name.class}"

EkeUser.new()

print "٩(๑❛ワ❛๑)و"

