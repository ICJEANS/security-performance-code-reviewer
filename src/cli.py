import argparse
from reviewer import scan_path, to_markdown

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    args = ap.parse_args()
    print(to_markdown(scan_path(args.target)))

if __name__ == "__main__":
    main()
