#!/bin/zsh
# vulnscout wrapper -- handles venv activation automatically
# Usage: ./vs [same args as main.py]
#   ./vs hunt "topic:parser" --language c
#   ./vs repo ~/projects/target
#   ./vs webapp https://target.example.com

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
VENV_PYTHON="$VENV_DIR/bin/python"

# Create venv if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
    echo "Installing dependencies..."
    "$VENV_DIR/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"
    echo "Ready."
    echo ""
fi

# Install deps if click is missing (handles fresh clones)
if ! "$VENV_PYTHON" -c "import click" 2>/dev/null; then
    echo "Installing missing dependencies..."
    "$VENV_DIR/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"
fi

# Run vulnscout with all passed arguments
exec "$VENV_PYTHON" "$SCRIPT_DIR/main.py" "$@"
