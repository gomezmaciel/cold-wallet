#!/usr/bin/env python3
"""Cold Crypto Wallet - Main Entry Point"""
import sys
from app.ui.cli import cli

def main():
    try:
        cli()
    except KeyboardInterrupt:
        print("\n👋 Hasta luego!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
