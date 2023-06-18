"""
Main entry point for the CLI
"""
from ipv6ddns.cli import Cli

def main():
    """Entry method for the command line interface
    """
    cli = Cli()
    cli.execute()


if __name__ == "__main__":
    main()
