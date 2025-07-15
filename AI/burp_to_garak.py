#Burp Suite, save the request and response. Disable the Base64 option when you save.
# this script will create the JSON file used with garak.
# Usage:
# python burp_to_garak.py --file ~/folder/request

import xml.etree.ElementTree as ET
import json
from argparse import ArgumentParser


def parse_from_burpitem(file_name: str):
    tree = ET.parse(file_name)
    root = tree.getroot()
    request = "".join([x.text for x in root[0] if x.tag == "request"])
    response = "".join([x.text for x in root[0] if x.tag == "response"])
    return request, response


def parse_to_garak(request, response):
    http_method = request.split()[0]
    if http_method == "GET":
        http_headers = {
            header.split(":")[0]: header.split(":")[1][1:]
            for header in request.split("\n")[1:-2]
        }
        http_uri = "https://" + http_headers["Host"] + request.split()[1]
        name = http_headers["Host"].split(".")[-2]
        return {
            "name": name,
            "uri": http_uri,
            "method": http_method,
            "headers": {k: v for k, v in http_headers.items() if k != "Host"},
            "response_json": (
                True if response.find("Content-Type: application/json") else False
            ),
            "response_json_field": None,
        }

    if http_method != "GET" and request.find("Content-Type: application/json"):
        http_headers = {
            header.split(":")[0]: header.split(":")[1][1:]
            for header in request.split("\n\n")[0].split("\n")[1:-2]
        }
        http_uri = "https://" + http_headers["Host"] + request.split()[1]
        name = http_headers["Host"].split(".")[-2]
        return {
            "name": name,
            "uri": http_uri,
            "method": http_method,
            "headers": {k: v for k, v in http_headers.items() if k != "Host"},
            "req_template_json_object": json.loads(request.split("\n\n")[1]),
            "response_json": (
                True if response.find("Content-Type: application/json") else False
            ),
            "response_json_field": None,
        }


def save_config(generated_json):
    with open(generated_json["name"] + ".json", "w") as f:
        json.dump({"rest": {"RestGenerator": generated_json}}, f, indent=4)


def get_arguments():
    parser = ArgumentParser(
        prog="Burp request to Garak JSON",
        description="This is a tool that helps generate a garak config file for the REST generator. See wiki for tutorial",
        epilog="Disclaimer: This is still in the works",
    )
    parser.add_argument("--file", help="Path to burp request")
    return parser.parse_args()


if __name__ == "__main__":
    args = get_arguments()
    request, response = parse_from_burpitem(args.file)
    x = parse_to_garak(request, response)
    save_config(x)
