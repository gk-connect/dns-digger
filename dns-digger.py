import boto3
import socket
import argparse
import json
import subprocess
from datetime import datetime
from tabulate import tabulate


def nslookup_dns(dns_name):
    try:
        result = subprocess.run(['nslookup', dns_name], capture_output=True, text=True)
        output = result.stdout
        print("NSLOOKUP Output:")
        print(output)

        cname = None
        for line in output.splitlines():
            if 'canonical name' in line:
                cname = line.split('=')[1].strip().strip('.')
                break

        ips = []
        for line in output.splitlines():
            if 'Address' in line and '#' not in line:
                ips.append(line.split(':')[1].strip())

        return cname, ips
    except Exception as e:
        print(f"Error performing nslookup: {e}")
        return None, []


def get_load_balancer(client, dns_name):
    try:
        elb_response = client.describe_load_balancers()
        for elb in elb_response['LoadBalancers']:
            if dns_name.lower() in elb['DNSName'].lower():
                return elb
    except Exception as e:
        print(f"Error finding load balancer: {e}")
    return None


def get_target_group_details(client, target_group_arn):
    """
    Retrieves the target group name and its associated targets.
    """
    try:
        response = client.describe_target_groups(TargetGroupArns=[target_group_arn])
        target_group_name = response['TargetGroups'][0]['TargetGroupName']

        # Fetching targets for the target group
        targets_response = client.describe_target_health(TargetGroupArn=target_group_arn)
        targets = [target['Target']['Id'] for target in targets_response['TargetHealthDescriptions']]
        return target_group_name, targets
    except Exception as e:
        print(f"Error fetching target group details: {e}")
        return None, []


def get_load_balancer_rules(client, lb_arn):
    try:
        listener_response = client.describe_listeners(LoadBalancerArn=lb_arn)
        rules_data = []
        for listener in listener_response['Listeners']:
            port = listener['Port']
            rules = client.describe_rules(ListenerArn=listener['ListenerArn'])
            for rule in rules['Rules']:
                path_pattern = ""
                host_header = ""
                for condition in rule['Conditions']:
                    if condition['Field'] == 'path-pattern':
                        path_pattern = ",\n".join(condition['Values'])
                    if condition['Field'] == 'host-header':
                        host_header = ",\n".join(condition['Values'])

                for action in rule['Actions']:
                    target_group_arn = action.get('TargetGroupArn', 'N/A')
                    target_name, targets = get_target_group_details(client,
                                                                    target_group_arn) if target_group_arn != 'N/A' else (
                    'N/A', [])

                    table_value = "N/A"
                    if host_header:
                        table_value = host_header
                    elif path_pattern:
                        table_value = path_pattern




                    rules_data.append([
                        port,
                        rule.get('Priority', 'N/A'),
                        action.get('Type', 'N/A'),
                        target_name,
                        ", ".join(targets),
                        table_value
                    ])
        return rules_data
    except Exception as e:
        print(f"Error fetching rules: {e}")
    return None


def convert_datetime(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")


def main():
    parser = argparse.ArgumentParser(description="AWS Load Balancer or IP Resolver")
    parser.add_argument('--dns', required=True, help='DNS name to resolve')
    parser.add_argument('--profile', required=True, help='AWS profile to use')
    args = parser.parse_args()

    boto3.setup_default_session(profile_name=args.profile)
    elb_client = boto3.client('elbv2')
    tg_client = boto3.client('elbv2')

    cname, ips = nslookup_dns(args.dns)

    if cname:
        print(f"Canonical Name: {cname}")
    if ips:
        print(f"Resolved IP Addresses: {', '.join(ips)}")

    lookup_name = cname if cname else args.dns

    load_balancer = get_load_balancer(elb_client, lookup_name)
    if load_balancer:
        print(f"Found Load Balancer: {load_balancer['LoadBalancerName']}")

        rules_data = get_load_balancer_rules(elb_client, load_balancer['LoadBalancerArn'])
        if rules_data:
            print("Load Balancer Rules:")
            table_headers = ["Port", "Priority", "Actions.type", "TargetName", "Targets", "Path/Host"]
            print(tabulate(rules_data, headers=table_headers, tablefmt="pipe", stralign="left", numalign="left"))
        else:
            print("No rules found for the load balancer.")
    else:
        print(
            f"The DNS name {args.dns} resolves to IP addresses: {', '.join(ips)}, but no associated load balancer found.")


if __name__ == "__main__":
    main()
