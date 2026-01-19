#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TEST_DIR="/tmp/sepp-setup-test-$(date +%s)"

echo "Creating test directory: $TEST_DIR"
mkdir -p "$TEST_DIR"

echo "Copying SEPP repository to test directory..."
rsync -av \
    --exclude 'target' \
    --exclude '.git' \
    --exclude '.env' \
    --exclude 'node_modules' \
    --exclude '*.log' \
    "$SCRIPT_DIR/" "$TEST_DIR/sepp/"

cd "$TEST_DIR/sepp"

echo ""
echo "=========================================="
echo "Running setup script in fresh clone..."
echo "=========================================="
echo ""

echo "" | ./setup.sh

echo ""
echo "=========================================="
echo "Verifying .env file was created..."
echo "=========================================="
echo ""

if [ -f .env ]; then
    echo "✓ .env file exists"
    echo "Contents:"
    cat .env
else
    echo "✗ .env file was not created!"
    exit 1
fi

echo ""
echo "=========================================="
echo "Running cargo build..."
echo "=========================================="
echo ""

cargo build

echo ""
echo "=========================================="
echo "Running cargo check..."
echo "=========================================="
echo ""

cargo check

echo ""
echo "=========================================="
echo "Test completed successfully!"
echo "=========================================="
echo ""
echo "Cleaning up test directory: $TEST_DIR"
rm -rf "$TEST_DIR"
echo "Cleanup complete!"
