"""
Main entry point for the CLI
"""
from ipv6ddns.cli import Cli

def main(args=None):
    """Entry method for the command line interface
    """
    cli = Cli(cli_args=args)
    cli.execute()


if __name__ == "__main__":
    main()
