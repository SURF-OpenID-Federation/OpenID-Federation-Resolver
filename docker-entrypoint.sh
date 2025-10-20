#!/bin/sh
set -e

# Docker entrypoint script for federation resolver
# Configures network aliases to prevent hitting external IPs

echo "Federation Resolver Docker Entrypoint"

# Configure network aliases from environment variables
# Format: NETWORK_ALIAS_<name>=<internal_ip>
# Example: NETWORK_ALIAS_ta_demo=172.20.0.100

echo "Configuring network aliases..."

# Process all NETWORK_ALIAS_* environment variables
env | grep '^NETWORK_ALIAS_' | while IFS='=' read -r key value; do
    # Extract the alias name (remove NETWORK_ALIAS_ prefix)
    alias_name=$(echo "$key" | sed 's/NETWORK_ALIAS_//')

    # Convert underscores to dots for hostname format
    hostname=$(echo "$alias_name" | tr '_' '.')

    echo "Adding network alias: $hostname -> $value"
    echo "$value $hostname" >> /etc/hosts
done

# Also support TRUST_ANCHOR_ALIASES environment variable
# Format: comma-separated list of alias=ip pairs
# Example: TRUST_ANCHOR_ALIASES=ta.demo.orb.local=172.20.0.100,other.ta.local=172.20.0.101

if [ -n "$TRUST_ANCHOR_ALIASES" ]; then
    echo "Processing TRUST_ANCHOR_ALIASES: $TRUST_ANCHOR_ALIASES"

    # Split by comma and process each alias=ip pair
    echo "$TRUST_ANCHOR_ALIASES" | tr ',' '\n' | while IFS='=' read -r hostname ip; do
        if [ -n "$hostname" ] && [ -n "$ip" ]; then
            echo "Adding trust anchor alias: $hostname -> $ip"
            echo "$ip $hostname" >> /etc/hosts
        fi
    done
fi

# Display current /etc/hosts for debugging (optional)
if [ "$DEBUG_NETWORK" = "true" ]; then
    echo "Current /etc/hosts:"
    cat /etc/hosts
    echo ""
fi

echo "Network configuration complete, starting federation resolver..."

# Execute the main command
exec "$@"