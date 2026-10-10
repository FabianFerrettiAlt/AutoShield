import re


def get_failed_login_ips(log_file):
    """
    Reads an authentication log and returns IP addresses
    from lines containing failed password attempts.
    """

    failed_ips = []

    with open(log_file, "r") as file:
        for line in file:
            if "Failed password" in line:
                match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", line)

                if match:
                    failed_ips.append(match.group(1))

    return failed_ips