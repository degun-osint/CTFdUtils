import csv
from collections import defaultdict
from prettytable import PrettyTable
import ipaddress
import requests
import time


def ignored_ip(ip):
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
    ip_to_users = defaultdict(set)
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip_to_users[row['ip']].add(row['user_id'])
    print(f"Number of IPs loaded: {len(ip_to_users)}")
    return ip_to_users


def load_user_data(file_path):
    user_id_to_name = {}
    user_id_to_team = {}
    with open(file_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            user_id_to_name[row['id']] = row['name']
            user_id_to_team[row['id']] = row['team_id']
    print(f"Number of users loaded: {len(user_id_to_name)}")
    return user_id_to_name, user_id_to_team


def load_team_data(file_path):
    team_id_to_name = {}
    with open(file_path, 'r', encoding='utf-8') as f:
        # Read the first line to determine the CSV dialect
        dialect = csv.Sniffer().sniff(f.readline())
        f.seek(0)  # Go back to the beginning of the file

        reader = csv.DictReader(f, dialect=dialect)

        # Check headers
        headers = reader.fieldnames

        if 'id' not in headers or 'name' not in headers:
            print("Warning: Columns 'id' or 'name' are missing.")

        for row in reader:
            try:
                team_id = row['id']
                team_name = row.get('name', row.get('oauth_id', row.get('email', f"Unknown Team {team_id}")))
                team_id_to_name[team_id] = team_name
            except KeyError as e:
                print(f"Error while reading the line: {row}")
                print(f"Error: {e}")
                continue

    print(f"Number of teams loaded: {len(team_id_to_name)}")
    return team_id_to_name


def find_shared_ips_different_teams(ip_to_users, user_id_to_team):
    shared_ips = {}
    for ip, users in ip_to_users.items():
        if ignored_ip(ip):
            continue  # Skip ignored IPs
        teams = set(user_id_to_team.get(user_id, "Unknown") for user_id in users)
        if len(teams) > 1:  # If there's more than one team for this IP
            shared_ips[ip] = users
    return shared_ips


def get_isp(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=isp", timeout=5)
        data = response.json()
        return data.get('isp', 'Unknown')
    except requests.RequestException:
        return 'Request Failed'
    finally:
        time.sleep(1)  # To respect the API's rate limit


def create_pretty_table(shared_ips, user_id_to_name, user_id_to_team, team_id_to_name):
    table = PrettyTable()
    table.field_names = ["IP", "ISP", "Pseudos", "Team Names"]

    for ip, user_ids in shared_ips.items():
        pseudos = []
        team_names = set()
        for user_id in user_ids:
            pseudo = user_id_to_name.get(user_id, "Unknown")
            team_id = user_id_to_team.get(user_id, "Unknown")
            team_name = team_id_to_name.get(team_id, f"Unknown Team ({team_id})")
            pseudos.append(pseudo)
            team_names.add(team_name)

        isp = get_isp(ip)
        table.add_row([ip, isp, "\n".join(pseudos), "\n".join(team_names)])

    return table


def export_shared_ips_to_csv(shared_ips, user_id_to_name, user_id_to_team, team_id_to_name, output_file):
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "ISP", "Pseudos", "Team Names"])

        for ip, user_ids in shared_ips.items():
            pseudos = []
            team_names = set()
            for user_id in user_ids:
                pseudo = user_id_to_name.get(user_id, "Unknown")
                team_id = user_id_to_team.get(user_id, "Unknown")
                team_name = team_id_to_name.get(team_id, f"Unknown Team ({team_id})")
                pseudos.append(pseudo)
                team_names.add(team_name)

            isp = get_isp(ip)
            writer.writerow([
                ip,
                isp,
                "\n".join(pseudos),
                "\n".join(team_names)
            ])

    print(f"Results have been exported to {output_file}")


def main():
    tracking_file = 'tracking.csv'
    users_file = 'users.csv'
    teams_file = 'teams.csv'
    output_file = 'shared_ips_results.csv'

    ip_to_users = load_tracking_data(tracking_file)
    user_id_to_name, user_id_to_team = load_user_data(users_file)
    team_id_to_name = load_team_data(teams_file)

    if not team_id_to_name:
        print("No team data has been loaded. Please check the teams.csv file.")
        return

    shared_ips = find_shared_ips_different_teams(ip_to_users, user_id_to_team)

    print("Retrieving ISP information for each shared IP...")
    table = create_pretty_table(shared_ips, user_id_to_name, user_id_to_team, team_id_to_name)
    print(table)

    print("Exporting results to CSV...")
    export_shared_ips_to_csv(shared_ips, user_id_to_name, user_id_to_team, team_id_to_name, output_file)


if __name__ == "__main__":
    main()
