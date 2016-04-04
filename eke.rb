#!/usr/bin/env ruby

#
# Author: Riccardo Orizio (R)
# Date: 4 April 2016
# 
# Description: EKE implementation
# Network Security project
# 

# Imports
require "socket"
require_relative "./constants.rb"

class EkeUser

	# Useful struct
	User = Struct.new( :ip, :port, :name )

	def initialize()
		puts "Creating new EKE User"
		@known_clients = Array.new()

		@server_thread = Thread.new{ server_socket }
		@server_thread.join
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
				puts "Noone listening on #{port}. Going for it."
				@server_port = port
				#	@name = CLIENT_NAMES[ i ]
				break
			end
		}
	
		# Checking if there is still one port available for the current client
		if @server_port == -1
			puts "ERROR: No more than #{MAX_CLIENTS} ports available."
			exit( -1 )	
		end
	
		# Creating the listening socket
		@listening_socket = TCPServer.new( @ip, @server_port )
		puts "#{@ip}:#{@server_port} listening..."

		# Starting the client socket
		@client_thread = Thread.new{ client_socket }
		@client_thread.join
	 
		# Waiting for client requests
		loop{
			client = @listening_socket.accept
	
			# Taking some information about the incoming request
			( port, ip ) = Socket.unpack_sockaddr_in( client.getpeername )
			puts "Received request from #{ip}:#{port}"

			eke_init() # Only if it's requested
	
			client.close
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
			when 1
				scan_for_clients()
			when 2
				eke_init()
			when 0
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
		# Scanning all ports and checking if anyone answers the request
		# If so I save him
		SERVER_PORT_RANGE.each_with_index{ |port, i|
			begin
				# Checking if someone is listening on the current port
				if port != @server_port
					s = TCPSocket.new( @ip, port )
					s.close
					# Saving the new client found
					@known_clients.push( User.new( @ip, port, i ) )
				end
			rescue Errno::ECONNREFUSED, Errno::EHOSTUNREACH
			end
		}
		puts "#{@known_clients} available."
	end

	def print_clients_list()
		if @known_clients.empty? != true
			puts "Known clients: "
			@known_clients.each{ |client| puts "#{client.name} (#{client.ip}:#{client.port})" }
		else
			puts "No known clients yet."
		end
	end
		
	def eke_init()
		puts "Ready to start with EKE authentication"
	end

	def close()
		puts "Closing."
	end

	def show_menu()
		puts "What do you want to do?"
	end
end

# Creating a new Eke user
EkeUser.new()

print "٩(๑❛ワ❛๑)و"

