import argparse
from unicodedata import name
from packet_analyzer.dpi_engine import DPIEngine
from packet_analyzer.rule_manager import RuleManager

def main():
    parser = argparse.ArgumentParser(description="Run DPI on a PCAP file")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", help="Output PCAP file")
    parser.add_argument("--block-app", action="append", help="Block app (e.g., YOUTUBE)")
    parser.add_argument("--block-ip", action="append", help="Block IP")
    parser.add_argument("--block-domain", action="append", help="Block domain substring")
    parser.add_argument("--multi", action="store_true", help="Use multi-threaded version")
    parser.add_argument("--lbs", type=int, default=2, help="Number of load balancers")
    parser.add_argument("--fps-per-lb", type=int, default=2, help="Fast paths per LB")
    args = parser.parse_args()

    rules = RuleManager()
    if args.block_app:
        from packet_analyzer.types import AppType
        for app in args.block_app:
            rules.add_block_app(AppType[app.upper()])
    if args.block_ip:
        for ip in args.block_ip:
            rules.add_block_ip(ip)
    if args.block_domain:
        for dom in args.block_domain:
            rules.add_block_domain(dom)

    engine = DPIEngine(args.input, args.output, rules, args.lbs, args.fps_per_lb)
    if args.multi:
        engine.run_multi()
    else:
        engine.run_simple()

if __name__ == "__main__":
    main()