#!/bin/bash

set -e

echo "Setting up SEPP repository..."

if [ ! -f .env ]; then
    echo "Creating .env file from .env.example..."
    cp .env.example .env

    echo ""
    echo "Please configure the following variables in .env:"
    echo "  - MONGODB_URI (MongoDB connection string)"
    echo "  - MONGODB_DB_NAME (Database name)"
    echo "  - SEPP_FQDN (Fully qualified domain name for this SEPP instance)"
    echo "  - PLMN_MCC and PLMN_MNC (PLMN identifier)"
    echo "  - Certificate paths (SEPP_CERT_PATH, SEPP_KEY_PATH)"
    echo ""

    read -p "Press Enter to continue with default values or Ctrl+C to exit and configure manually..."

    echo "Note: You need to configure MONGODB_URI in .env"
else
    echo ".env file already exists, skipping..."
fi

echo ""
echo "Fetching Rust dependencies..."
cargo fetch

echo ""
echo "Building project..."
cargo build

echo ""
echo "Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Configure .env with your MongoDB credentials"
echo "  2. Ensure certificates exist at the configured paths"
echo "  3. Run 'cargo run' to start the SEPP server"
