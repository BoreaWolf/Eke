#!/usr/bin/env ruby

#
# Author: Riccardo Orizio (R)
# Date: 4 April 2016
# 
# Description: Constants
# 

STARTING_PORT = 6000
MAX_CLIENTS = 5
SERVER_PORT_RANGE = Array( STARTING_PORT..STARTING_PORT + MAX_CLIENTS - 1 )
CLIENT_NAMES = [
	"Alice",
	"Bob",
	"Carl",
	"Don",
	"Ellie" ]

LOG_DIR = "./log/"
PRIME_LIST_SIZE = 1000
MAX_RANDOM_VALUE = 1000000
