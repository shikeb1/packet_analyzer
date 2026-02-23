from .types import AppType

class RuleManager:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_apps = set()
        self.blocked_domains = set()

    def add_block_ip(self, ip):
        self.blocked_ips.add(ip)

    def add_block_app(self, app: AppType):
        self.blocked_apps.add(app)

    def add_block_domain(self, domain):
        self.blocked_domains.add(domain.lower())

    def is_blocked(self, src_ip, app_type, sni):
        if src_ip in self.blocked_ips:
            return True
        if app_type in self.blocked_apps:
            return True
        if sni:
            sni_lower = sni.lower()
            for dom in self.blocked_domains:
                if dom in sni_lower:
                    return True
        return False