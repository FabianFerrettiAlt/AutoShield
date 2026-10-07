from ingestion import get_failed_login_ips


ips = get_failed_login_ips("auth.log")

print("Failed login IP addresses:")
for ip in ips:
    print(ip)