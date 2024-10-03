import os
import csv
import requests
import toml
import base64
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# GitHub API Token
github_token = os.getenv("github_token")

# GitHub repository URL
github_api_url = "https://api.github.com/repos/elastic/detection-rules/contents/rules"

# Get the current date in the specified format
current_date = datetime.now().strftime("%d_%m_%Y")

# Output CSV file with the current date in the name
output_csv = f"elastic_detection_rules_export_{current_date}.csv"

# Specify the fields to extract from the TOML files
fields_to_extract = [
    "metadata.creation_date", "metadata.integration", "metadata.maturity", "metadata.min_stack_comments", "metadata.min_stack_version",
    "metadata.updated_date", "rule.author", "rule.description", "rule.false_positives", "rule.from", "rule.index", "rule.language",
    "rule.license", "rule.name", "rule.note", "rule.references", "rule.risk_score", "rule.rule_id", "rule.severity", "rule.tags",
    "rule.timestamp_override", "rule.type", "rule.query"
]

# Function to fetch TOML file content from GitHub API
def fetch_toml_content(url):
    headers = {"Authorization": f"token {github_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        content = response.json()
        if "content" in content:
            toml_content = base64.b64decode(content["content"]).decode("utf-8")
            return toml_content
    else:
        print(f"Failed to fetch TOML content from {url}. Status code: {response.status_code}")
    return None

# Function to recursively fetch and parse TOML files in a directory and its subdirectories
def scrape_toml_files(url):
    headers = {"Authorization": f"token {github_token}"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        toml_data = []

        for item in data:
            if "name" in item:
                if item["type"] == "file" and item["name"].endswith(".toml"):
                    toml_url = item["url"]

                    # Extract GitHub Folder Location (folder name only)
                    github_folder_location = os.path.dirname(item["path"]).split("/rules/", 1)[-1]

                    toml_content = fetch_toml_content(toml_url)

                    if toml_content is not None:
                        print(f"Fetching and parsing {item['name']}...")
                        try:
                            toml_dict = toml.loads(toml_content)
                            flattened_dict = {}

                            for field in fields_to_extract:
                                keys = field.split('.')
                                temp = toml_dict
                                for key in keys:
                                    if isinstance(temp, dict) and key in temp:
                                        temp = temp[key]
                                    else:
                                        temp = None
                                        break
                                flattened_dict[field] = temp

                            # Add GitHub Folder Location and GitHub File Name
                            flattened_dict["GitHub Folder Location"] = github_folder_location
                            flattened_dict["GitHub File Name"] = item["name"]

                            toml_data.append(flattened_dict)
                        except Exception as e:
                            print(f"Error parsing {item['name']}: {e}")
                            # Log the error and continue processing other files
                    else:
                        print(f"Skipping {item['name']} due to an error while fetching content.")
                elif item["type"] == "dir":
                    subfolder_url = item["url"]
                    subfolder_data = scrape_toml_files(subfolder_url)
                    toml_data.extend(subfolder_data)

        return toml_data
    else:
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return []

# Main function
def main():
    toml_data = scrape_toml_files(github_api_url)

    if toml_data:
        # Reorder the fieldnames to have the desired columns first
        fieldnames = [
            "GitHub Folder Location", "GitHub File Name", "rule.name", "rule.rule_id"
        ] + fields_to_extract

        # Write to CSV with the current date in the name
        with open(output_csv, mode="w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(toml_data)
            print(f"CSV file '{output_csv}' created successfully.")
    else:
        print("No TOML files were found.")

if __name__ == "__main__":
    main()
