import csv
from collections import defaultdict
from prettytable import PrettyTable
import ipaddress
import requests
import time


def ignored_ip(ip):
    # Garde la même fonction pour filtrer les IPs Cloudflare
    cloudflare_ranges = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22"
    ]

    ip_obj = ipaddress.ip_address(ip)
    return any(ip_obj in ipaddress.ip_network(cf_range) for cf_range in cloudflare_ranges)


def load_tracking_data(file_path):
    # Même fonction, pas de changement nécessaire
    ip_to_users = defaultdict(set)
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_to_users[row['ip']].add(row['user_id'])
    print(f"Number of IPs loaded: {len(ip_to_users)}")
    return ip_to_users


def load_user_data(file_path):
    # Simplifié pour ne garder que le mapping user_id -> name
    user_id_to_name = {}
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            user_id_to_name[row['id']] = row['name']
    print(f"Number of users loaded: {len(user_id_to_name)}")
    return user_id_to_name


def find_shared_ips(ip_to_users):
    # Nouvelle fonction qui cherche simplement les IPs utilisées par plusieurs users
    shared_ips = {}
    for ip, users in ip_to_users.items():
        if ignored_ip(ip):
            continue
        if len(users) > 1:  # Si plus d'un utilisateur pour cette IP
            shared_ips[ip] = users
    return shared_ips


def get_isp(ip):
    # Garde la même fonction
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=isp", timeout=5)
        data = response.json()
        return data.get('isp', 'Unknown')
    except requests.RequestException:
        return 'Request Failed'
    finally:
        time.sleep(1)  # Pour respecter la limite de l'API


def create_pretty_table(shared_ips, user_id_to_name):
    # Simplifié pour n'afficher que les IPs et les users
    table = PrettyTable()
    table.field_names = ["IP", "ISP", "Users"]

    for ip, user_ids in shared_ips.items():
        users = []
        for user_id in user_ids:
            username = user_id_to_name.get(user_id, f"Unknown User ({user_id})")
            users.append(username)

        isp = get_isp(ip)
        table.add_row([ip, isp, "\n".join(users)])

    return table


def export_shared_ips_to_csv(shared_ips, user_id_to_name, output_file):
    # Simplifié pour n'exporter que les IPs et les users
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "ISP", "Users"])

        for ip, user_ids in shared_ips.items():
            users = []
            for user_id in user_ids:
                username = user_id_to_name.get(user_id, f"Unknown User ({user_id})")
                users.append(username)

            isp = get_isp(ip)
            writer.writerow([
                ip,
                isp,
                "\n".join(users)
            ])

    print(f"Results have been exported to {output_file}")


def main():
    tracking_file = 'tracking.csv'
    users_file = 'users.csv'
    output_file = 'shared_ips_results.csv'

    ip_to_users = load_tracking_data(tracking_file)
    user_id_to_name = load_user_data(users_file)

    shared_ips = find_shared_ips(ip_to_users)

    print("Retrieving ISP information for each shared IP...")
    table = create_pretty_table(shared_ips, user_id_to_name)
    print(table)

    print("Exporting results to CSV...")
    export_shared_ips_to_csv(shared_ips, user_id_to_name, output_file)


if __name__ == "__main__":
    main()
